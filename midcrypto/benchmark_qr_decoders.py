from __future__ import annotations

import argparse
import csv
import json
import platform
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

import cv2
import numpy as np
import cryptography
from cryptography.hazmat.primitives import serialization

from crypto_utils import normalize_cert_data, sign_data, pack_qr_payload
from qr_utils import create_qr_image, image_to_bytes, decode_qr_image


def decode_baseline(image_bytes: bytes) -> str | None:
    """Decode once with the standard OpenCV detector, including PNG decoding."""
    encoded = np.frombuffer(image_bytes, dtype=np.uint8)
    image = cv2.imdecode(encoded, cv2.IMREAD_COLOR)
    if image is None:
        return None
    text, _, _ = cv2.QRCodeDetector().detectAndDecode(image)
    return text or None


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare OpenCV baseline and the project QR decoder on one saved image set.")
    parser.add_argument("--output-dir", type=Path, default=Path("sample_qrs/decoder_eval"),
                        help="New output directory for the 100 PNGs, per-image CSV, and environment summary.")
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--timing-repeats", type=int, default=3,
                        help="Timed decodes per method and image; success/failure is taken from the first timed pass.")
    args = parser.parse_args()
    if args.samples < 1 or args.timing_repeats < 1:
        parser.error("--samples and --timing-repeats must be positive")
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        parser.error(f"output directory is not empty: {args.output_dir}; choose a new --output-dir")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    key_path = Path("sample_keys/private_key.pem")
    if not key_path.is_file():
        parser.error(f"missing sample private key: {key_path}")
    private_pem = key_path.read_text(encoding="utf-8")
    # One certificate fixture is deliberately reused; each image gets a new randomized PSS signature.
    certificate = {
        "name": "Decoder Benchmark",
        "cert_id": "QR-DECODER-TEST",
        "issue_date": "2026-11-14",
    }
    normalized = normalize_cert_data(certificate)
    images: list[bytes] = []
    versions: list[int] = []
    dimensions: tuple[int, int] | None = None

    for index in range(args.samples):
        signature = sign_data(private_pem, normalized)
        payload = pack_qr_payload(certificate, signature)
        image, version = create_qr_image(payload, error_level="M")
        image_bytes = image_to_bytes(image)
        image.save(args.output_dir / f"qr_{index + 1:03d}.png")
        images.append(image_bytes)
        versions.append(version)
        dimensions = image.size

    # Warm up both paths on an image outside all reported timings and counts.
    decode_baseline(images[0])
    decode_qr_image(images[0])

    rows: list[dict[str, object]] = []
    baseline_successes = 0
    pipeline_successes = 0
    baseline_all_ms: list[float] = []
    pipeline_all_ms: list[float] = []

    for index, image_bytes in enumerate(images, start=1):
        baseline_times: list[float] = []
        pipeline_times: list[float] = []
        baseline_ok = False
        pipeline_ok = False
        # Alternate first method per repetition to reduce systematic order bias.
        for repetition in range(args.timing_repeats):
            methods = (("baseline", decode_baseline), ("pipeline", decode_qr_image))
            if (index + repetition) % 2:
                methods = methods[::-1]
            for method, decoder in methods:
                started = time.perf_counter()
                decoded = decoder(image_bytes)
                elapsed_ms = (time.perf_counter() - started) * 1000
                ok = decoded is not None
                if method == "baseline":
                    baseline_times.append(elapsed_ms)
                    if repetition == 0:
                        baseline_ok = ok
                else:
                    pipeline_times.append(elapsed_ms)
                    if repetition == 0:
                        pipeline_ok = ok

        baseline_successes += int(baseline_ok)
        pipeline_successes += int(pipeline_ok)
        baseline_mean = statistics.mean(baseline_times)
        pipeline_mean = statistics.mean(pipeline_times)
        baseline_all_ms.extend(baseline_times)
        pipeline_all_ms.extend(pipeline_times)
        rows.append({
            "image": f"qr_{index:03d}.png",
            "qr_version": versions[index - 1],
            "width_px": dimensions[0],
            "height_px": dimensions[1],
            "baseline_success": int(baseline_ok),
            "baseline_mean_ms": f"{baseline_mean:.6f}",
            "pipeline_success": int(pipeline_ok),
            "pipeline_mean_ms": f"{pipeline_mean:.6f}",
        })

    csv_path = args.output_dir / "decoder_results.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    summary = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "operating_system": platform.platform(),
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "opencv": cv2.__version__,
        "sample_count": args.samples,
        "certificate_fixture_count": 1,
        "fixture": certificate,
        "signatures": "one fresh RSA-PSS signature per image; PSS salt is randomized",
        "physical_or_synthetic": "software-generated PNGs; no resize, blur, rotation, noise, or camera capture",
        "qr_version": sorted(set(versions)),
        "dimensions_px": list(dimensions or ()),
        "error_correction": "M",
        "timing_repeats_per_image_and_method": args.timing_repeats,
        "warmup": "one unmeasured call to each method on the first image",
        "baseline": "PNG decode with cv2.imdecode plus cv2.QRCodeDetector().detectAndDecode",
        "pipeline": "midcrypto.qr_utils.decode_qr_image (PNG decode, detector cascade, preprocessing fallbacks)",
        "success_counted_from": "first timed pass per image; decode outcome is deterministic for a fixed image and software build",
        "baseline_successes": baseline_successes,
        "baseline_failures": args.samples - baseline_successes,
        "baseline_mean_ms": round(statistics.mean(baseline_all_ms), 3),
        "pipeline_successes": pipeline_successes,
        "pipeline_failures": args.samples - pipeline_successes,
        "pipeline_mean_ms": round(statistics.mean(pipeline_all_ms), 3),
        "timing_note": "Mean over all timed calls; no outlier removal. Decode time only, excluding QR generation and signature verification.",
    }
    json_path = args.output_dir / "decoder_summary.json"
    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"CSV: {csv_path}")
    print(f"Images: {args.samples} PNG files in {args.output_dir}")


if __name__ == "__main__":
    main()
