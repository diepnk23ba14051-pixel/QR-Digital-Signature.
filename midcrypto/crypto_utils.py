import json
import base64
import zlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


# Tao cap khoa RSA (mac dinh 2048 bit)
def generate_rsa_keys(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return priv_pem.decode("utf-8"), pub_pem.decode("utf-8")


# Chuan hoa du lieu chung nhan thanh chuoi JSON co thu tu co dinh
def normalize_cert_data(cert_dict):
    return json.dumps(cert_dict, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


# Ky du lieu bang RSA-PSS va SHA-256
def sign_data(private_key_pem, data_str):
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None
    )

    signature = private_key.sign(
        data_str.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return base64.b64encode(signature).decode("utf-8")


# Xac minh chu ky bang public key
def verify_signature(public_key_pem, data_str, signature_b64):
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8")
        )
        sig_bytes = base64.b64decode(signature_b64)

        public_key.verify(
            sig_bytes,
            data_str.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


# Dong goi du lieu de dua vao QR code
# Ho tro che do rut gon (nen phan JSON + ghep chu ky nhi phan roi moi Base64 1 lan)
def pack_qr_payload(cert_dict, signature_b64, key_id="EDU-2026", use_compression=False):
    if use_compression:
        meta = json.dumps({"d": cert_dict, "k": key_id}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        comp_meta = zlib.compress(meta, level=9)
        sig_raw = base64.b64decode(signature_b64)
        # 2 byte dau luu do dai phan meta da nen, theo sau la meta va chu ky nhi phan
        combined = len(comp_meta).to_bytes(2, "big") + comp_meta + sig_raw
        return "C:" + base64.b64encode(combined).decode("utf-8")

    payload = {
        "data": cert_dict,
        "sig": signature_b64,
        "kid": key_id
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


# Giai ma du lieu doc duoc tu QR code
def unpack_qr_payload(qr_text):
    if qr_text.startswith("C:"):
        raw = base64.b64decode(qr_text[2:])
        meta_len = int.from_bytes(raw[:2], "big")
        comp_meta = raw[2:2 + meta_len]
        sig_raw = raw[2 + meta_len:]
        meta_obj = json.loads(zlib.decompress(comp_meta).decode("utf-8"))
        return {
            "data": meta_obj["d"],
            "sig": base64.b64encode(sig_raw).decode("utf-8"),
            "kid": meta_obj["k"]
        }
    return json.loads(qr_text)


# Minh hoa diem yeu cua Textbook RSA (khong dung hash va padding PSS)
# Ke tan cong co the nhan 2 chu ky hop le de tao chu ky gia cho m3 = m1 * m2 mod n
def demo_textbook_rsa_forgery(private_key_pem):
    priv_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    priv_nums = priv_key.private_numbers()
    pub_nums = priv_key.public_key().public_numbers()

    n = pub_nums.n
    e = pub_nums.e
    d = priv_nums.d

    # Gia su 2 thong diep dang so nguyen
    m1 = 105
    m2 = 200

    # Ky truc tiep khong qua RSA-PSS: s = m^d mod n
    s1 = pow(m1, d, n)
    s2 = pow(m2, d, n)

    # Ke tan cong khong biet d nhung tinh duoc chu ky cho m3 = m1 * m2
    m3_forged = (m1 * m2) % n
    s3_forged = (s1 * s2) % n

    # Kiem tra xem chu ky gia co vuot qua buoc verify (s^e mod n == m) hay khong
    verified_m = pow(s3_forged, e, n)
    is_forged_valid = (verified_m == m3_forged)

    return {
        "m1": m1,
        "m2": m2,
        "m3_forged": m3_forged,
        "is_forged_valid": is_forged_valid
    }
