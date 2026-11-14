# QR-Based Digital Certificate Verification System Using RSA-PSS Signatures

> **Mid-term Project — Cryptography (2026–2027)**  
> **University of Science and Technology of Hanoi (USTH)**  
> **Topic:** Design and Implementation of a QR Code-Based Digital Certificate Verification System Using RSA Digital Signatures

---

## 1. Project Overview & Scope
This project is an **offline, stateless digital certificate verification prototype** built in Python with an interactive Command-Line Interface (CLI).

- **Included in Scope:**
  - RSA asymmetric key generation (1024, 2048, 3072 bits).
  - Deterministic canonical JSON serialization (`sort_keys=True`, compact separators).
  - RSA-PSS probabilistic digital signing and verification with SHA-256 (`RFC 8017`).
  - Mathematical demonstration of Textbook RSA multiplicative forgery weakness.
  - Multi-stage OpenCV QR code decoding pipeline (`QRCodeDetectorAruco` + preprocessing fallbacks).
  - 5 automated security & tamper-detection test cases.
  - Quantitative performance benchmarking across RSA key sizes.
- **Explicitly Out of Scope:**
  - Web applications, GUI, or centralized databases.
  - Online certificate revocation protocols (CRL / OCSP).
  - Production Hardware Security Modules (HSM) / Key Vaults.

---

## 2. Directory Structure
```text
QR-Digital-Signature/
├── Project_Report_RSA_QR.pdf     # Compiled academic PDF report
├── Project_Report_RSA_QR.tex     # Complete LaTeX source code (Overleaf / TeXLive ready)
├── README.md                     # Root project overview
└── midcrypto/
    ├── app.py                    # Interactive CLI Terminal Menu (6 options)
    ├── crypto_utils.py           # RSA-PSS, SHA-256, Canonical JSON, Textbook RSA demo
    ├── qr_utils.py               # Robust multi-stage OpenCV QR generator & decoder
    ├── run_tests.py              # Automated 5 test cases + Textbook RSA demo + Benchmark
    ├── requirements.txt          # Dependencies: cryptography, qrcode, opencv-python, pillow, matplotlib
    ├── REPORT.md                 # Full detailed project report in Markdown
    ├── sample_keys/              # Sample PEM keys (private_key.pem, public_key.pem, wrong_public_key.pem)
    └── sample_qrs/               # Valid/tampered QR codes and benchmark_chart.png
```

---

## 3. Installation & Quick Start

### Prerequisites
Python 3.9+ (tested on Python 3.11 & 3.14).

### Step 1: Install Dependencies
```bash
cd midcrypto
pip install -r requirements.txt
```

### Step 2: Run Automated Test Cases & Benchmark
```bash
python run_tests.py
```
This executes:
1. Sample RSA-2048 key generation.
2. 5 security test cases (tamper detection & error handling).
3. Textbook RSA multiplicative forgery attack reproduction.
4. Benchmark (Signing vs. Verification latency across 1024, 2048, 3072 bits) and saves `sample_qrs/benchmark_chart.png`.

### Step 3: Run Interactive CLI Application
```bash
python app.py
```

---

## 4. Academic Report & LaTeX Source
- Full Markdown report: [`midcrypto/REPORT.md`](midcrypto/REPORT.md)
- Complete LaTeX source code: [`Project_Report_RSA_QR.tex`](Project_Report_RSA_QR.tex)
