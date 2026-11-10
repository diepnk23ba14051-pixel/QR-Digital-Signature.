import os
import time
from datetime import date

from crypto_utils import (
    generate_rsa_keys,
    normalize_cert_data,
    sign_data,
    verify_signature,
    pack_qr_payload,
    unpack_qr_payload,
    demo_textbook_rsa_forgery
)
from qr_utils import create_qr_image, decode_qr_file
import run_tests


PRIV_KEY_PATH = "sample_keys/private_key.pem"
PUB_KEY_PATH = "sample_keys/public_key.pem"


def ensure_default_keys():
    os.makedirs("sample_keys", exist_ok=True)
    os.makedirs("sample_qrs", exist_ok=True)
    if not os.path.exists(PRIV_KEY_PATH) or not os.path.exists(PUB_KEY_PATH):
        priv, pub = generate_rsa_keys(2048)
        with open(PRIV_KEY_PATH, "w", encoding="utf-8") as f:
            f.write(priv)
        with open(PUB_KEY_PATH, "w", encoding="utf-8") as f:
            f.write(pub)


def load_key(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def menu_generate_keys():
    print("\n--- 1. TAO CAP KHOA RSA ---")
    bits_str = input("Nhap do dai khoa (1024 / 2048 / 3072) [mac dinh 2048]: ").strip()
    bits = int(bits_str) if bits_str in ["1024", "2048", "3072"] else 2048

    t0 = time.perf_counter()
    priv, pub = generate_rsa_keys(bits)
    dt = (time.perf_counter() - t0) * 1000

    with open(PRIV_KEY_PATH, "w", encoding="utf-8") as f:
        f.write(priv)
    with open(PUB_KEY_PATH, "w", encoding="utf-8") as f:
        f.write(pub)

    print(f"[+] Da tao cap khoa RSA-{bits} thanh cong trong {dt:.2f} ms")
    print(f"[+] Private key luu tai: {PRIV_KEY_PATH}")
    print(f"[+] Public key luu tai : {PUB_KEY_PATH}")


def menu_issue_certificate():
    print("\n--- 2. NHAP CHUNG NHAN, KY SO RSA-PSS VA TAO MA QR ---")
    name = input("Nhap ho va ten [mac dinh: Nguyen Van A]: ").strip() or "Nguyen Van A"
    cert_id = input("Nhap ma chung nhan [mac dinh: CERT-2026-001]: ").strip() or "CERT-2026-001"
    issue_date = input(f"Nhap ngay cap [mac dinh: {date.today()}]: ").strip() or str(date.today())
    comp_ans = input("Su dung che do nen du lieu (y/n) [mac dinh: n]: ").strip().lower()
    use_comp = (comp_ans == "y")

    out_file = input("Ten file anh QR xuat ra [mac dinh: sample_qrs/qr_custom.png]: ").strip()
    if not out_file:
        out_file = "sample_qrs/qr_custom.png"

    cert_data = {
        "name": name,
        "cert_id": cert_id,
        "issue_date": issue_date
    }

    priv_pem = load_key(PRIV_KEY_PATH)

    # Buoc 1: Chuan hoa du lieu JSON
    norm_str = normalize_cert_data(cert_data)
    print(f"\n[*] Chuoi JSON chuan hoa: {norm_str}")

    # Buoc 2: Ky bang RSA-PSS + SHA-256
    t0 = time.perf_counter()
    sig_b64 = sign_data(priv_pem, norm_str)
    sign_ms = (time.perf_counter() - t0) * 1000
    print(f"[*] Da ky RSA-PSS ({sign_ms:.2f} ms). Do dai chu ky Base64: {len(sig_b64)} ky tu")

    # Buoc 3: Dong goi va tao QR Code
    payload = pack_qr_payload(cert_data, sig_b64, use_compression=use_comp)
    qr_img, qr_ver = create_qr_image(payload)
    qr_img.save(out_file)

    print(f"[+] Da luu anh QR tai: {out_file} (Payload: {len(payload)} bytes | QR Version: {qr_ver})")


def menu_verify_qr():
    print("\n--- 3. QUET ANH QR VA XAC MINH CHU KY ---")
    print("Goi y cac file co san trong sample_qrs/:")
    print("  - sample_qrs/qr_valid.png          (QR hop le)")
    print("  - sample_qrs/qr_tampered_data.png  (QR bi sua ten)")
    print("  - sample_qrs/qr_tampered_sig.png   (QR bi sua chu ky)")

    qr_path = input("Nhap duong dan file anh QR [mac dinh: sample_qrs/qr_valid.png]: ").strip()
    if not qr_path:
        qr_path = "sample_qrs/qr_valid.png"

    pub_path = input(f"Nhap duong dan Public Key [mac dinh: {PUB_KEY_PATH}]: ").strip()
    if not pub_path:
        pub_path = PUB_KEY_PATH

    if not os.path.exists(qr_path):
        print(f"[-] Loi: Khong tim thay file anh '{qr_path}'")
        return
    if not os.path.exists(pub_path):
        print(f"[-] Loi: Khong tim thay file khoa '{pub_path}'")
        return

    decoded_text = decode_qr_file(qr_path)
    if not decoded_text:
        print("[-] Loi: Khong doc duoc ma QR tu anh nay (anh hong hoac sai dinh dang).")
        return

    try:
        payload_obj = unpack_qr_payload(decoded_text)
        cert_dict = payload_obj["data"]
        sig_b64 = payload_obj["sig"]
        kid = payload_obj.get("kid", "N/A")

        print("\n[*] Thong tin doc duoc tu ma QR:")
        print(f"    - Ho va ten     : {cert_dict.get('name')}")
        print(f"    - Ma chung nhan : {cert_dict.get('cert_id')}")
        print(f"    - Ngay cap      : {cert_dict.get('issue_date')}")
        print(f"    - Key ID        : {kid}")

        pub_pem = load_key(pub_path)
        norm_data = normalize_cert_data(cert_dict)

        t0 = time.perf_counter()
        is_valid = verify_signature(pub_pem, norm_data, sig_b64)
        ver_ms = (time.perf_counter() - t0) * 1000

        if is_valid:
            print(f"\n==> KET QUA: VALID SIGNATURE (Chu ky hop le - Xac minh trong {ver_ms:.3f} ms)")
        else:
            print(f"\n==> KET QUA: INVALID SIGNATURE (Chu ky KHONG hop le - Du lieu bi sua hoac sai khoa!)")
    except Exception as e:
        print(f"[-] Loi dinh dang du lieu trong QR: {e}")


def menu_tamper_demo():
    print("\n--- 4. THU NGHIEM SUA DU LIEU SAU KHI KY (TAMPERING DEMO) ---")
    qr_path = input("Nhap file QR hop le de thu sua [mac dinh: sample_qrs/qr_valid.png]: ").strip()
    if not qr_path:
        qr_path = "sample_qrs/qr_valid.png"

    decoded_text = decode_qr_file(qr_path)
    if not decoded_text:
        print("[-] Khong doc duoc file QR.")
        return

    payload_obj = unpack_qr_payload(decoded_text)
    cert_dict = payload_obj["data"]
    sig_b64 = payload_obj["sig"]

    print(f"[*] Du lieu goc trong QR: {cert_dict}")
    fake_name = input("Nhap ten gia mao muon sua thanh [mac dinh: Le Van Fake]: ").strip() or "Le Van Fake"
    cert_dict["name"] = fake_name

    norm_tampered = normalize_cert_data(cert_dict)
    pub_pem = load_key(PUB_KEY_PATH)

    is_valid = verify_signature(pub_pem, norm_tampered, sig_b64)
    print(f"[*] Du lieu sau khi bi sua: {norm_tampered}")
    print(f"==> KET QUA XAC MINH VOI CHU KY CU: {'VALID SIGNATURE' if is_valid else 'INVALID SIGNATURE (Phat hien gia mao!)'}")


def main():
    ensure_default_keys()

    while True:
        print("\n==============================================================")
        print("   HE THONG XAC MINH CHUNG NHAN BANG MA QR (RSA-PSS + SHA256)")
        print("==============================================================")
        print("1. Tao cap khoa RSA moi (1024 / 2048 / 3072 bit)")
        print("2. Nhap thong tin chung nhan, ky so va xuat anh QR")
        print("3. Quet anh QR va xac minh chu ky")
        print("4. Thu nghiem sua du lieu sau khi ky (Demo phat hien gia mao)")
        print("5. Chay tu dong 5 Test Cases + Demo diem yeu Textbook RSA + Benchmark")
        print("0. Thoat chuong trinh")
        print("--------------------------------------------------------------")

        choice = input("Chon chuc nang (0-5): ").strip()

        if choice == "1":
            menu_generate_keys()
        elif choice == "2":
            menu_issue_certificate()
        elif choice == "3":
            menu_verify_qr()
        elif choice == "4":
            menu_tamper_demo()
        elif choice == "5":
            print()
            run_tests.main()
        elif choice == "0":
            print("Da thoat chuong trinh.")
            break
        else:
            print("Lua chon khong hop le, vui long nhap tu 0 den 5.")


if __name__ == "__main__":
    main()
