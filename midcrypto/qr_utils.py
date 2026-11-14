import io
import os
import qrcode
import cv2
import numpy as np


# Generate QR code image from payload string
def create_qr_image(data_str, error_level="M"):
    level_map = {
        "L": qrcode.constants.ERROR_CORRECT_L,
        "M": qrcode.constants.ERROR_CORRECT_M,
        "Q": qrcode.constants.ERROR_CORRECT_Q,
        "H": qrcode.constants.ERROR_CORRECT_H
    }
    ec_level = level_map.get(error_level, qrcode.constants.ERROR_CORRECT_M)

    qr = qrcode.QRCode(
        version=None,
        error_correction=ec_level,
        box_size=8,
        border=4
    )
    qr.add_data(data_str)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    return img, qr.version


# Convert PIL image object to PNG byte array
def image_to_bytes(pil_img):
    buf = io.BytesIO()
    pil_img.save(buf, format="PNG")
    return buf.getvalue()


# Decode QR code content from raw image bytes using a cascading multi-stage pipeline
def decode_qr_image(file_bytes):
    if not file_bytes:
        return None

    file_arr = np.frombuffer(file_bytes, np.uint8)
    img = cv2.imdecode(file_arr, cv2.IMREAD_COLOR)

    if img is None:
        return None

    # Initialize detector list: prioritize QRCodeDetectorAruco (OpenCV 4.7+) with fallback to classic QRCodeDetector
    detectors = []
    if hasattr(cv2, "QRCodeDetectorAruco"):
        try:
            detectors.append(cv2.QRCodeDetectorAruco())
        except Exception:
            pass
    detectors.append(cv2.QRCodeDetector())

    # Strategy 1: Direct decoding on original color image (BGR)
    for d in detectors:
        data, _, _ = d.detectAndDecode(img)
        if data:
            return data

    # Strategy 2: Grayscale conversion
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if len(img.shape) == 3 else img
    for d in detectors:
        data, _, _ = d.detectAndDecode(gray)
        if data:
            return data

    # Strategy 3: Add white Quiet Zone padding to help OpenCV locate finder patterns
    for pad in [20, 40]:
        padded = cv2.copyMakeBorder(gray, pad, pad, pad, pad, cv2.BORDER_CONSTANT, value=255)
        for d in detectors:
            data, _, _ = d.detectAndDecode(padded)
            if data:
                return data

    # Strategy 4: Otsu binarization (Thresholding) combined with margin padding
    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)
    padded_otsu = cv2.copyMakeBorder(otsu, 30, 30, 30, 30, cv2.BORDER_CONSTANT, value=255)
    for d in detectors:
        data, _, _ = d.detectAndDecode(padded_otsu)
        if data:
            return data

    # Strategy 5: Multi-scale resizing with INTER_NEAREST interpolation (avoids module blurring)
    h, w = gray.shape[:2]
    for target_w in [600, 800, 500, 400]:
        scale = target_w / w
        resized = cv2.resize(gray, (target_w, int(h * scale)), interpolation=cv2.INTER_NEAREST)
        for d in detectors:
            data, _, _ = d.detectAndDecode(resized)
            if data:
                return data

    return None


# Read and decode QR code content directly from an image file path
def decode_qr_file(file_path):
    if not os.path.exists(file_path):
        return None
    with open(file_path, "rb") as f:
        return decode_qr_image(f.read())
