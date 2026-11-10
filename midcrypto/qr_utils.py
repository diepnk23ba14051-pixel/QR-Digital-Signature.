import io
import os
import qrcode
import cv2
import numpy as np


# Tao anh QR code tu chuoi du lieu
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


# Chuyen anh PIL sang bytes
def image_to_bytes(pil_img):
    buf = io.BytesIO()
    pil_img.save(buf, format="PNG")
    return buf.getvalue()


# Doc noi dung QR code tu du lieu bytes cua anh
def decode_qr_image(file_bytes):
    file_arr = np.frombuffer(file_bytes, np.uint8)
    img = cv2.imdecode(file_arr, cv2.IMREAD_COLOR)

    if img is None:
        return None

    detector = cv2.QRCodeDetector()
    data, bbox, _ = detector.detectAndDecode(img)

    if not data:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        data, bbox, _ = detector.detectAndDecode(gray)

    if not data:
        h, w = img.shape[:2]
        if w > 600:
            scale = 500.0 / w
            resized = cv2.resize(img, (int(w * scale), int(h * scale)))
            data, bbox, _ = detector.detectAndDecode(resized)

    return data if data else None


# Doc noi dung QR code truc tiep tu duong dan file anh
def decode_qr_file(file_path):
    if not os.path.exists(file_path):
        return None
    with open(file_path, "rb") as f:
        return decode_qr_image(f.read())
