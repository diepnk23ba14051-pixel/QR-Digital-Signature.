import os
import json
import time
import matplotlib.pyplot as plt

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

    print("=== 1. TAO CAP KHOA MAU (RSA-2048) ===")
    priv_pem, pub_pem = generate_rsa_keys(2048)
    _, wrong_pub_pem = generate_rsa_keys(2048)

    with open("sample_keys/private_key.pem", "w", encoding="utf-8") as f:
        f.write(priv_pem)
    with open("sample_keys/public_key.pem", "w", encoding="utf-8") as f:
        f.write(pub_pem)
    with open("sample_keys/wrong_public_key.pem", "w", encoding="utf-8") as f:
        f.write(wrong_pub_pem)
    print("Da luu khoa mau tai thu muc sample_keys/\n")

    # Du lieu chung nhan mau
    cert_valid = {
        "name": "Nguyen Van A",
        "cert_id": "CERT-2026-001",
        "issue_date": "2026-11-09"
    }
    norm_valid = normalize_cert_data(cert_valid)
    sig_valid = sign_data(priv_pem, norm_valid)

    # 1. QR hop le
    payload_valid = pack_qr_payload(cert_valid, sig_valid)
    img_valid, ver_valid = create_qr_image(payload_valid)
    img_valid.save("sample_qrs/qr_valid.png")

    # 2. QR bi sua ten sau khi ky
    cert_tampered = {
        "name": "Nguyen Van B (Fake)",
        "cert_id": "CERT-2026-001",
        "issue_date": "2026-11-09"
    }
    payload_tampered_data = pack_qr_payload(cert_tampered, sig_valid)
    img_tampered_data, _ = create_qr_image(payload_tampered_data)
    img_tampered_data.save("sample_qrs/qr_tampered_data.png")

    # 3. QR bi thay doi chu ky
    bad_sig = "A" * 10 + sig_valid[10:]
    payload_tampered_sig = pack_qr_payload(cert_valid, bad_sig)
    img_tampered_sig, _ = create_qr_image(payload_tampered_sig)
    img_tampered_sig.save("sample_qrs/qr_tampered_sig.png")

    print("=== 2. CHAY 5 KICH BAN KIEM THU (TEST CASES) ===")

    # Case 1: QR va chu ky hop le
    with open("sample_qrs/qr_valid.png", "rb") as f:
        decoded_1 = decode_qr_image(f.read())
    obj_1 = unpack_qr_payload(decoded_1)
    res_1 = verify_signature(pub_pem, normalize_cert_data(obj_1["data"]), obj_1["sig"])
    print(f"[Case 1] QR va chu ky hop le              -> {'Valid Signature' if res_1 else 'Invalid Signature'}")

    # Case 2: Sua ten/ma chung nhan sau khi ky
    with open("sample_qrs/qr_tampered_data.png", "rb") as f:
        decoded_2 = decode_qr_image(f.read())
    obj_2 = unpack_qr_payload(decoded_2)
    res_2 = verify_signature(pub_pem, normalize_cert_data(obj_2["data"]), obj_2["sig"])
    print(f"[Case 2] Sua ten chung nhan sau khi ky    -> {'Valid Signature' if res_2 else 'Invalid Signature'}")

    # Case 3: Thay doi chu ky
    with open("sample_qrs/qr_tampered_sig.png", "rb") as f:
        decoded_3 = decode_qr_image(f.read())
    obj_3 = unpack_qr_payload(decoded_3)
    res_3 = verify_signature(pub_pem, normalize_cert_data(obj_3["data"]), obj_3["sig"])
    print(f"[Case 3] Thay doi chu ky                  -> {'Valid Signature' if res_3 else 'Invalid Signature'}")

    # Case 4: Dung public key khong khop
    res_4 = verify_signature(wrong_pub_pem, normalize_cert_data(obj_1["data"]), obj_1["sig"])
    print(f"[Case 4] Dung Public Key khong khop       -> {'Valid Signature' if res_4 else 'Invalid Signature'}")

    # Case 5: Anh QR hong / sai dinh dang
    decoded_5 = decode_qr_image(b"not_an_image_bytes")
    print(f"[Case 5] Anh QR hong / sai dinh dang      -> {'Doc thanh cong' if decoded_5 else 'Bao loi: Khong doc duoc ma QR'}\n")

    print("=== 3. CHUNG MINH DIEM YEU TEXTBOOK RSA vs RSA-PSS ===")
    forgery = demo_textbook_rsa_forgery(priv_pem)
    print(f"Textbook RSA multiplicative forgery (m1={forgery['m1']}, m2={forgery['m2']} -> m3={forgery['m3_forged']}): "
          f"Forged valid = {forgery['is_forged_valid']}\n")

    print("=== 4. BENCHMARK & VE BIEU DO BAO CAO ===")
    key_sizes = [1024, 2048, 3072]
    sign_times = []
    verify_times = []
    raw_sizes = []
    comp_sizes = []

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

        print(f"RSA-{bits}: Sign={s_ms:.3f}ms | Verify={v_ms:.3f}ms | "
              f"Raw={len(p_raw)}B (QR v{v_raw}) | Zlib={len(p_comp)}B (QR v{v_comp})")

    # Ve bieu do luu thanh file anh cho bao cao
    labels = [f"RSA-{b}" for b in key_sizes]
    x = range(len(labels))

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))

    ax1.bar([i - 0.18 for i in x], sign_times, width=0.35, label="Sign (ms)")
    ax1.bar([i + 0.18 for i in x], verify_times, width=0.35, label="Verify (ms)")
    ax1.set_xticks(list(x))
    ax1.set_xticklabels(labels)
    ax1.set_ylabel("Time (ms)")
    ax1.set_title("Signing vs Verification Time")
    ax1.legend()

    ax2.bar([i - 0.18 for i in x], raw_sizes, width=0.35, label="Standard JSON (Bytes)")
    ax2.bar([i + 0.18 for i in x], comp_sizes, width=0.35, label="Zlib Compressed (Bytes)")
    ax2.set_xticks(list(x))
    ax2.set_xticklabels(labels)
    ax2.set_ylabel("Payload Size (Bytes)")
    ax2.set_title("QR Payload Size Comparison")
    ax2.legend()

    plt.tight_layout()
    plt.savefig("sample_qrs/benchmark_chart.png", dpi=150)
    print("\nDa luu bieu do so sanh tai: sample_qrs/benchmark_chart.png")


if __name__ == "__main__":
    main()
