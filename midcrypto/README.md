# QR Code-Based Digital Certificate Verification System Using RSA-PSS Digital Signatures

**Project Title:** Design and Implementation of a QR Code-Based Digital Certificate Verification System Using RSA Digital Signatures  
**Course:** Cryptography (2026–2027)  
**Institution:** University of Science and Technology of Hanoi (USTH)

---

## 1. Directory Structure

- `crypto_utils.py`: Cryptographic utility functions for RSA key generation (1024 / 2048 / 3072 bits), deterministic JSON normalization, RSA-PSS (SHA-256) signing and verification, compact payload packaging, and the Textbook RSA multiplicative forgery demonstration.
- `qr_utils.py`: QR code generation routines using `qrcode` and robust multi-stage QR image decoding pipeline using OpenCV (`cv2.QRCodeDetectorAruco` fallback with quiet-zone padding and Otsu thresholding).
- `app.py`: Interactive CLI application with user menus for key generation, certificate issuance, QR scanning/verification, and tampering demonstrations.
- `run_tests.py`: Automated test runner executing the 5 core test cases (TC-01 through TC-05), the Textbook RSA forgery proof, 100-run stress testing, and RSA performance benchmarks across key sizes.
- `benchmark_qr_decoders.py`: Script comparing OpenCV's baseline detector against the multi-stage pipeline across 100 generated QR images.
- `sample_keys/`: Directory containing pre-generated sample RSA key pairs (`private_key.pem`, `public_key.pem`, `wrong_public_key.pem`).
- `sample_qrs/`: Directory containing generated sample QR images (`qr_valid.png`, `qr_tampered_data.png`, `qr_tampered_sig.png`), benchmark charts, and decoder evaluation logs.

---

## 2. Prerequisites & Installation

Requires **Python 3.9+** (tested on Python 3.13 and Python 3.14 on Windows 11).

Install all necessary dependencies via:

```bash
pip install -r requirements.txt
```

Core dependencies:
- `cryptography>=41.0.0`
- `opencv-python>=4.7.0`
- `qrcode[pil]>=7.4.0`
- `Pillow>=10.0.0`
- `matplotlib>=3.7.0`

---

## 3. Interactive CLI Usage

To launch the interactive command-line interface:

```bash
python app.py
```

Available menu options:
1. **Generate RSA Key Pair**: Creates 1024, 2048, or 3072-bit keys and exports PEM files.
2. **Issue Certificate & Generate QR**: Inputs certificate holder details, signs via RSA-PSS, and exports the resulting QR image.
3. **Scan QR Code & Verify Signature**: Reads a QR image, parses payload, and checks cryptographic integrity against a trusted public key.
4. **Tamper Certificate Data Demo**: Simulates an in-transit attack modifying the holder's name to prove signature rejection.
5. **Run Automated Test Suite**: Executes all 5 test scenarios, Textbook RSA demo, and performance benchmarks.
0. **Exit**.

---

## 4. Automated Testing and Benchmarks

To execute the complete automated test suite non-interactively:

```bash
python run_tests.py
```

To run the 100-sample QR decoder pipeline benchmark:

```bash
python benchmark_qr_decoders.py
```
