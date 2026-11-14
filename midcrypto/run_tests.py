import os
import sys
import platform
import json
import time
import matplotlib.pyplot as plt
import cryptography
import cv2

from crypto_utils import (
    generate_rsa_keys,
    normalize_cert_data,
    sign_data,
    verify_signature,
    pack_qr_payload,
    unpack_qr_payload,
    demo_textbook_rsa_forgery
)
from qr_utils import create_qr_image, image_to_bytes, decode_qr_image


def main():
    os.makedirs("sample_keys", exist_ok=True)
    os.makedirs("sample_qrs", exist_ok=True)

    print("================================================================================")
    print("        TEST SUITE & BENCHMARK: QR-BASED RSA-PSS CERTIFICATE VERIFICATION      ")
    print("================================================================================")
    print(f"Platform:     {platform.platform()}")
    print(f"Python:       {platform.python_version()} ({platform.architecture()[0]})")
    print(f"Cryptography: {cryptography.__version__}")
    print(f"OpenCV:       {cv2.__version__}")
    print("--------------------------------------------------------------------------------\n")

    test_results = []

    # --------------------------------------------------------------------------
    # 1. GENERATE SAMPLE RSA-2048 KEY PAIR
    # --------------------------------------------------------------------------
    print("=== 1. GENERATE SAMPLE KEY PAIR (RSA-2048) ===")
    priv_pem, pub_pem = generate_rsa_keys(2048)
    _, wrong_pub_pem = generate_rsa_keys(2048)

    with open("sample_keys/private_key.pem", "w", encoding="utf-8") as f:
        f.write(priv_pem)
    with open("sample_keys/public_key.pem", "w", encoding="utf-8") as f:
        f.write(pub_pem)
    with open("sample_keys/wrong_public_key.pem", "w", encoding="utf-8") as f:
        f.write(wrong_pub_pem)
    print("[+] Saved sample keys to sample_keys/\n")

    # Sample certificate data
    cert_valid = {
        "name": "Nguyen Van A",
        "cert_id": "CERT-2026-001",
        "issue_date": "2026-11-09"
    }
    norm_valid = normalize_cert_data(cert_valid)
    sig_valid = sign_data(priv_pem, norm_valid)

    # 1. Valid QR
    payload_valid = pack_qr_payload(cert_valid, sig_valid)
    img_valid, ver_valid = create_qr_image(payload_valid)
    img_valid.save("sample_qrs/qr_valid.png")

    # 2. QR with tampered recipient name after signing
    cert_tampered = {
        "name": "Nguyen Van B (Fake)",
        "cert_id": "CERT-2026-001",
        "issue_date": "2026-11-09"
    }
    payload_tampered_data = pack_qr_payload(cert_tampered, sig_valid)
    img_tampered_data, _ = create_qr_image(payload_tampered_data)
    img_tampered_data.save("sample_qrs/qr_tampered_data.png")

    # 3. QR with tampered signature string
    bad_sig = "A" * 10 + sig_valid[10:]
    payload_tampered_sig = pack_qr_payload(cert_valid, bad_sig)
    img_tampered_sig, _ = create_qr_image(payload_tampered_sig)
    img_tampered_sig.save("sample_qrs/qr_tampered_sig.png")

    # --------------------------------------------------------------------------
    # 2. RUN 5 SECURITY TEST CASES
    # --------------------------------------------------------------------------
    print("=== 2. RUN 5 SECURITY TEST CASES ===")

    # Case 1: Valid QR and authentic signature
    with open("sample_qrs/qr_valid.png", "rb") as f:
        decoded_1 = decode_qr_image(f.read())
    if not decoded_1:
        res_1 = False
        tc1_status = "FAIL (Decode Error)"
    else:
        obj_1 = unpack_qr_payload(decoded_1)
        res_1 = verify_signature(pub_pem, normalize_cert_data(obj_1["data"]), obj_1["sig"])
        tc1_status = "PASS" if res_1 is True else "FAIL"
    print(f"[TC-01] Valid QR and authentic signature      -> {tc1_status} (Result: {'Valid Signature' if res_1 else 'Invalid Signature'})")
    test_results.append(("TC-01: Valid QR & Signature", res_1 is True))

    # Case 2: Tampered holder name after signing
    with open("sample_qrs/qr_tampered_data.png", "rb") as f:
        decoded_2 = decode_qr_image(f.read())
    if not decoded_2:
        res_2 = True
        tc2_status = "FAIL (Decode Error)"
    else:
        obj_2 = unpack_qr_payload(decoded_2)
        res_2 = verify_signature(pub_pem, normalize_cert_data(obj_2["data"]), obj_2["sig"])
        tc2_status = "PASS" if res_2 is False else "FAIL (Tamper undetected)"
    print(f"[TC-02] Tampered holder name after signing    -> {tc2_status} (Result: {'Invalid Signature' if not res_2 else 'Valid Signature'})")
    test_results.append(("TC-02: Tampered Data Detection", res_2 is False))

    # Case 3: Altered Base64 signature bytes
    with open("sample_qrs/qr_tampered_sig.png", "rb") as f:
        decoded_3 = decode_qr_image(f.read())
    if not decoded_3:
        res_3 = True
        tc3_status = "FAIL (Decode Error)"
    else:
        obj_3 = unpack_qr_payload(decoded_3)
        res_3 = verify_signature(pub_pem, normalize_cert_data(obj_3["data"]), obj_3["sig"])
        tc3_status = "PASS" if res_3 is False else "FAIL (Tamper undetected)"
    print(f"[TC-03] Altered Base64 signature bytes        -> {tc3_status} (Result: {'Invalid Signature' if not res_3 else 'Valid Signature'})")
    test_results.append(("TC-03: Tampered Signature Detection", res_3 is False))

    # Case 4: Mismatched unauthorized public key
    if decoded_1:
        res_4 = verify_signature(wrong_pub_pem, normalize_cert_data(obj_1["data"]), obj_1["sig"])
        tc4_status = "PASS" if res_4 is False else "FAIL (Unauthorized key accepted)"
    else:
        res_4 = True
        tc4_status = "FAIL (Case 1 decode failed)"
    print(f"[TC-04] Mismatched unauthorized public key    -> {tc4_status} (Result: {'Invalid Signature' if not res_4 else 'Valid Signature'})")
    test_results.append(("TC-04: Mismatched Public Key Rejection", res_4 is False))

    # Case 5: Corrupted image stream / non-QR media
    decoded_5 = decode_qr_image(b"not_an_image_bytes")
    tc5_status = "PASS" if decoded_5 is None else "FAIL"
    print(f"[TC-05] Corrupted image stream / non-QR media -> {tc5_status} (Result: {'Error: Cannot decode QR code' if not decoded_5 else 'Unexpected decode'})\n")
    test_results.append(("TC-05: Corrupted Media Error Handling", decoded_5 is None))

    # --------------------------------------------------------------------------
    # 3. STRESS TEST (100 ITERATIONS)
    # --------------------------------------------------------------------------
    print("=== 3. STRESS TEST (100 ITERATIONS OF RSA-2048 QR GENERATION & DECODE) ===")
    stress_success = 0
    t_stress_0 = time.perf_counter()
    for i in range(100):
        sig_i = sign_data(priv_pem, norm_valid)
        payload_i = pack_qr_payload(cert_valid, sig_i)
        img_i, _ = create_qr_image(payload_i)
        raw_png = image_to_bytes(img_i)
        decoded_i = decode_qr_image(raw_png)
        if decoded_i:
            obj_i = unpack_qr_payload(decoded_i)
            if verify_signature(pub_pem, normalize_cert_data(obj_i["data"]), obj_i["sig"]):
                stress_success += 1

    stress_dt = (time.perf_counter() - t_stress_0)
    stress_pass = (stress_success == 100)
    print(f"[STRESS] Decode & verification success rate: {stress_success}/100 ({stress_success}%) in {stress_dt:.2f}s")
    print(f"[STRESS] Status: {'PASS' if stress_pass else 'FAIL'}\n")
    test_results.append(("STRESS-100: 100-Run Decode & Verify", stress_pass))

    # --------------------------------------------------------------------------
    # 4. PROVING TEXTBOOK RSA WEAKNESS vs RSA-PSS
    # --------------------------------------------------------------------------
    print("=== 4. PROVING TEXTBOOK RSA WEAKNESS vs RSA-PSS ===")
    forgery = demo_textbook_rsa_forgery(priv_pem)
    tf_pass = (forgery["is_forged_valid"] is True)
    print(f"Textbook RSA multiplicative forgery (m1={forgery['m1']}, m2={forgery['m2']} -> m3={forgery['m3_forged']}):")
    print(f"Forged valid = {forgery['is_forged_valid']} -> {'PASS (Weakness successfully reproduced)' if tf_pass else 'FAIL'}\n")
    test_results.append(("DEMO: Textbook RSA Multiplicative Forgery", tf_pass))

    # --------------------------------------------------------------------------
    # 5. PERFORMANCE BENCHMARK (30 RUNS AVERAGE)
    # --------------------------------------------------------------------------
    print("=== 5. PERFORMANCE BENCHMARK (AVERAGED OVER 30 RUNS) ===")
    key_sizes = [1024, 2048, 3072]
    sign_times = []
    verify_times = []
    raw_sizes = []
    comp_sizes = []
    benchmark_data = {}

    for bits in key_sizes:
        pk, pubk = generate_rsa_keys(bits)

        t0 = time.perf_counter()
        for _ in range(30):
            s = sign_data(pk, norm_valid)
        s_ms = ((time.perf_counter() - t0) / 30) * 1000

        t1 = time.perf_counter()
        for _ in range(30):
            verify_signature(pubk, norm_valid, s)
        v_ms = ((time.perf_counter() - t1) / 30) * 1000

        p_raw = pack_qr_payload(cert_valid, s, use_compression=False)
        p_comp = pack_qr_payload(cert_valid, s, use_compression=True)
        _, v_raw = create_qr_image(p_raw)
        _, v_comp = create_qr_image(p_comp)

        sign_times.append(s_ms)
        verify_times.append(v_ms)
        raw_sizes.append(len(p_raw))
        comp_sizes.append(len(p_comp))

        benchmark_data[bits] = {
            "sign_ms": s_ms,
            "verify_ms": v_ms,
            "raw_len": len(p_raw),
            "comp_len": len(p_comp),
            "qr_ver_raw": v_raw,
            "qr_ver_comp": v_comp
        }

        reduction = (1 - len(p_comp) / len(p_raw)) * 100
        print(f"RSA-{bits}: Sign={s_ms:6.3f} ms | Verify={v_ms:5.3f} ms | "
              f"Raw={len(p_raw)}B (QR v{v_raw}) | Zlib={len(p_comp)}B (QR v{v_comp}) | Reduction: {reduction:.2f}%")

    # Plot chart
    labels = [f"RSA-{b}" for b in key_sizes]
    x = range(len(labels))

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))

    ax1.bar([i - 0.18 for i in x], sign_times, width=0.35, label="Sign (ms)", color="#1f77b4")
    ax1.bar([i + 0.18 for i in x], verify_times, width=0.35, label="Verify (ms)", color="#2ca02c")
    ax1.set_xticks(list(x))
    ax1.set_xticklabels(labels)
    ax1.set_ylabel("Time (ms)")
    ax1.set_title("Signing vs Verification Time")
    ax1.legend()
    ax1.grid(axis="y", linestyle="--", alpha=0.5)

    ax2.bar([i - 0.18 for i in x], raw_sizes, width=0.35, label="Standard JSON (Bytes)", color="#3498db")
    ax2.bar([i + 0.18 for i in x], comp_sizes, width=0.35, label="Zlib Compact (Bytes)", color="#e67e22")
    ax2.set_xticks(list(x))
    ax2.set_xticklabels(labels)
    ax2.set_ylabel("Payload Size (Bytes)")
    ax2.set_title("QR Payload Size Comparison")
    ax2.legend()
    ax2.grid(axis="y", linestyle="--", alpha=0.5)

    plt.tight_layout()
    chart_path = "sample_qrs/benchmark_chart.png"
    plt.savefig(chart_path, dpi=150)
    print(f"\n[+] Saved comparison chart to: {chart_path}\n")

    # --------------------------------------------------------------------------
    # 6. TEST SUITE SUMMARY
    # --------------------------------------------------------------------------
    print("================================================================================")
    print("                        TEST SUITE EXECUTION SUMMARY                            ")
    print("================================================================================")
    all_passed = True
    for name, passed in test_results:
        status_str = "[PASS]" if passed else "[FAIL]"
        if not passed:
            all_passed = False
        print(f" {status_str}  {name}")
    print("--------------------------------------------------------------------------------")
    if all_passed:
        print("OVERALL STATUS: ALL TESTS PASSED SUCCESSFULLY (Exit Code: 0)")
        print("================================================================================")
        sys.exit(0)
    else:
        print("OVERALL STATUS: SOME TESTS FAILED (Exit Code: 1)")
        print("================================================================================")
        sys.exit(1)


if __name__ == "__main__":
    main()
