import json
import base64
import zlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


# Generate RSA key pair (default: 2048-bit)
# NOTE: For this educational prototype, PEM keys are saved with NoEncryption()
# to simplify CLI execution. In a production system, private keys must be protected
# with strong password-based encryption (e.g., BestAvailableEncryption) or stored
# in a Hardware Security Module (HSM) / Key Vault to prevent key leakage.
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


# Normalize certificate data into deterministic JSON with sorted keys
def normalize_cert_data(cert_dict):
    return json.dumps(cert_dict, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


# Sign normalized message using RSA-PSS and SHA-256
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


# Verify RSA-PSS signature against trusted public key
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


# Package certificate data and digital signature into a QR payload
# Supports compact binary mode (zlib-compressed metadata + raw binary signature)
def pack_qr_payload(cert_dict, signature_b64, key_id="EDU-2026", use_compression=False):
    if use_compression:
        meta = json.dumps({"d": cert_dict, "k": key_id}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        comp_meta = zlib.compress(meta, level=9)
        sig_raw = base64.b64decode(signature_b64)
        # First 2 bytes store length of compressed metadata, followed by metadata and raw signature
        combined = len(comp_meta).to_bytes(2, "big") + comp_meta + sig_raw
        return "C:" + base64.b64encode(combined).decode("utf-8")

    payload = {
        "data": cert_dict,
        "sig": signature_b64,
        "kid": key_id
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


# Unpack and parse payload extracted from QR code
def unpack_qr_payload(qr_text):
    if not qr_text or not isinstance(qr_text, str):
        raise ValueError("QR data does not exist or is not a valid string.")

    qr_text = qr_text.strip()
    if qr_text.startswith("C:"):
        try:
            raw = base64.b64decode(qr_text[2:])
            meta_len = int.from_bytes(raw[:2], "big")
            comp_meta = raw[2:2 + meta_len]
            sig_raw = raw[2 + meta_len:]
            meta_obj = json.loads(zlib.decompress(comp_meta).decode("utf-8"))
            return {
                "data": meta_obj["d"],
                "sig": base64.b64encode(sig_raw).decode("utf-8"),
                "kid": meta_obj.get("k", "N/A")
            }
        except Exception as e:
            raise ValueError(f"Error decoding compact payload: {e}")

    try:
        payload = json.loads(qr_text)
        if not isinstance(payload, dict) or "data" not in payload or "sig" not in payload:
            raise ValueError("JSON payload missing 'data' or 'sig' field.")
        return payload
    except json.JSONDecodeError as e:
        raise ValueError(f"Cannot parse payload as valid JSON: {e}")


# Demonstrate the multiplicative forgery weakness of unpadded Textbook RSA
# An attacker can multiply two valid signatures to forge a signature for m3 = m1 * m2 mod n
def demo_textbook_rsa_forgery(private_key_pem):
    priv_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    priv_nums = priv_key.private_numbers()
    pub_nums = priv_key.public_key().public_numbers()

    n = pub_nums.n
    e = pub_nums.e
    d = priv_nums.d

    # Two sample integer messages
    m1 = 105
    m2 = 200

    # Direct signing without hash or PSS padding: s = m^d mod n
    s1 = pow(m1, d, n)
    s2 = pow(m2, d, n)

    # Attacker does not know private key d, but computes signature for m3 = m1 * m2 mod n
    m3_forged = (m1 * m2) % n
    s3_forged = (s1 * s2) % n

    # Check if the forged signature passes verification: s^e mod n == m3
    verified_m = pow(s3_forged, e, n)
    is_forged_valid = (verified_m == m3_forged)

    return {
        "m1": m1,
        "m2": m2,
        "m3_forged": m3_forged,
        "is_forged_valid": is_forged_valid
    }
