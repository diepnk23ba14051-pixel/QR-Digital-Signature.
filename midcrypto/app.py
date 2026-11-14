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
    print("\n--- 1. GENERATE RSA KEY PAIR ---")
    bits_str = input("Enter key size in bits (1024 / 2048 / 3072) [default: 2048]: ").strip()
    bits = int(bits_str) if bits_str in ["1024", "2048", "3072"] else 2048

    t0 = time.perf_counter()
    priv, pub = generate_rsa_keys(bits)
    dt = (time.perf_counter() - t0) * 1000

    with open(PRIV_KEY_PATH, "w", encoding="utf-8") as f:
        f.write(priv)
    with open(PUB_KEY_PATH, "w", encoding="utf-8") as f:
        f.write(pub)

    print(f"[+] Successfully generated RSA-{bits} key pair in {dt:.2f} ms")
    print(f"[+] Private key saved to: {PRIV_KEY_PATH}")
    print(f"[+] Public key saved to : {PUB_KEY_PATH}")


def menu_issue_certificate():
    print("\n--- 2. ISSUE CERTIFICATE, SIGN WITH RSA-PSS, AND GENERATE QR CODE ---")
    name = input("Enter certificate holder name [default: Alice Smith]: ").strip() or "Alice Smith"
    cert_id = input("Enter certificate ID [default: CERT-2026-001]: ").strip() or "CERT-2026-001"
    issue_date = input(f"Enter issue date [default: {date.today()}]: ").strip() or str(date.today())
    comp_ans = input("Use compact payload compression? (y/n) [default: n]: ").strip().lower()
    use_comp = (comp_ans == "y")

    out_file = input("Output QR image path [default: sample_qrs/qr_custom.png]: ").strip()
    if not out_file:
        out_file = "sample_qrs/qr_custom.png"

    cert_data = {
        "name": name,
        "cert_id": cert_id,
        "issue_date": issue_date
    }

    priv_pem = load_key(PRIV_KEY_PATH)

    # Step 1: Normalize certificate data into deterministic JSON
    norm_str = normalize_cert_data(cert_data)
    print(f"\n[*] Deterministic JSON string: {norm_str}")

    # Step 2: Sign with RSA-PSS (SHA-256)
    t0 = time.perf_counter()
    sig_b64 = sign_data(priv_pem, norm_str)
    sign_ms = (time.perf_counter() - t0) * 1000
    print(f"[*] Signed with RSA-PSS ({sign_ms:.2f} ms). Base64 signature length: {len(sig_b64)} chars")

    # Step 3: Pack payload and generate QR code
    payload = pack_qr_payload(cert_data, sig_b64, use_compression=use_comp)
    qr_img, qr_ver = create_qr_image(payload)
    qr_img.save(out_file)

    print(f"[+] Saved QR code image to: {out_file} (Payload: {len(payload)} bytes | QR Version: {qr_ver})")


def menu_verify_qr():
    print("\n--- 3. SCAN QR CODE AND VERIFY DIGITAL SIGNATURE ---")
    print("Available sample files in sample_qrs/:")
    print("  - sample_qrs/qr_valid.png          (Authentic valid QR)")
    print("  - sample_qrs/qr_tampered_data.png  (QR with tampered holder name)")
    print("  - sample_qrs/qr_tampered_sig.png   (QR with corrupted signature)")

    qr_path = input("Enter QR image path [default: sample_qrs/qr_valid.png]: ").strip()
    if not qr_path:
        qr_path = "sample_qrs/qr_valid.png"

    pub_path = input(f"Enter Public Key path [default: {PUB_KEY_PATH}]: ").strip()
    if not pub_path:
        pub_path = PUB_KEY_PATH

    if not os.path.exists(qr_path):
        print(f"[-] Error: Image file '{qr_path}' not found.")
        return
    if not os.path.exists(pub_path):
        print(f"[-] Error: Public key file '{pub_path}' not found.")
        return

    decoded_text = decode_qr_file(qr_path)
    if not decoded_text:
        print("[-] Error: Unable to decode QR code from image (corrupted image or unsupported format).")
        return

    try:
        payload_obj = unpack_qr_payload(decoded_text)
        cert_dict = payload_obj["data"]
        sig_b64 = payload_obj["sig"]
        kid = payload_obj.get("kid", "N/A")

        print("\n[*] Decoded QR Certificate Payload:")
        print(f"    - Holder Name    : {cert_dict.get('name')}")
        print(f"    - Certificate ID : {cert_dict.get('cert_id')}")
        print(f"    - Issue Date     : {cert_dict.get('issue_date')}")
        print(f"    - Key ID         : {kid}")

        pub_pem = load_key(pub_path)
        norm_data = normalize_cert_data(cert_dict)

        t0 = time.perf_counter()
        is_valid = verify_signature(pub_pem, norm_data, sig_b64)
        ver_ms = (time.perf_counter() - t0) * 1000

        if is_valid:
            print(f"\n==> RESULT: VALID SIGNATURE (Verification passed in {ver_ms:.3f} ms)")
        else:
            print(f"\n==> RESULT: INVALID SIGNATURE (Verification failed: data tampered or wrong public key!)")
    except Exception as e:
        print(f"[-] Error parsing QR payload: {e}")


def menu_tamper_demo():
    print("\n--- 4. TAMPER CERTIFICATE DATA (FORGERY DETECTION DEMO) ---")
    qr_path = input("Enter authentic QR image path to tamper [default: sample_qrs/qr_valid.png]: ").strip()
    if not qr_path:
        qr_path = "sample_qrs/qr_valid.png"

    decoded_text = decode_qr_file(qr_path)
    if not decoded_text:
        print("[-] Error: Unable to read QR image file.")
        return

    payload_obj = unpack_qr_payload(decoded_text)
    cert_dict = payload_obj["data"]
    sig_b64 = payload_obj["sig"]

    print(f"[*] Original data from QR: {cert_dict}")
    fake_name = input("Enter fraudulent name to replace [default: Mallory (Attacker)]: ").strip() or "Mallory (Attacker)"
    cert_dict["name"] = fake_name

    norm_tampered = normalize_cert_data(cert_dict)
    pub_pem = load_key(PUB_KEY_PATH)

    is_valid = verify_signature(pub_pem, norm_tampered, sig_b64)
    print(f"[*] Tampered data string: {norm_tampered}")
    print(f"==> VERIFICATION WITH ORIGINAL SIGNATURE: {'VALID SIGNATURE' if is_valid else 'INVALID SIGNATURE (Tampering detected!)'}")


def main():
    ensure_default_keys()

    while True:
        print("\n==============================================================")
        print("   QR DIGITAL CERTIFICATE VERIFICATION SYSTEM (RSA-PSS)")
        print("==============================================================")
        print("1. Generate new RSA key pair (1024 / 2048 / 3072 bit)")
        print("2. Issue certificate, sign with RSA-PSS, and generate QR code")
        print("3. Scan QR code image and verify digital signature")
        print("4. Tamper certificate data (Demonstrate forgery detection)")
        print("5. Run automated test suite (5 Test Cases + Textbook RSA + Benchmark)")
        print("0. Exit")
        print("--------------------------------------------------------------")

        choice = input("Select an option (0-5): ").strip()

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
            print("Exiting application. Goodbye!")
            break
        else:
            print("Invalid choice, please select between 0 and 5.")


if __name__ == "__main__":
    main()
