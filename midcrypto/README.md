# Hệ thống xác minh chứng nhận bằng mã QR sử dụng chữ ký số RSA-PSS

**Tên đề tài tiếng Anh:** Design and Implementation of a QR Code-Based Digital Certificate Verification System Using RSA Digital Signatures

## 1. Cấu trúc thư mục
- `crypto_utils.py`: Các hàm tạo khóa RSA, chuẩn hóa dữ liệu JSON, ký số bằng RSA-PSS (SHA-256), xác minh chữ ký và minh họa điểm yếu của Textbook RSA.
- `qr_utils.py`: Các hàm tạo mã QR từ dữ liệu đã ký và đọc/giải mã ảnh QR bằng OpenCV.
- `app.py`: Chương trình chính chạy menu tương tác trên Terminal (CLI).
- `run_tests.py`: Script tự động tạo bộ khóa mẫu, ảnh QR mẫu, chạy 5 kịch bản kiểm thử và xuất biểu đồ đánh giá hiệu năng.
- `sample_keys/`: Chứa khóa riêng và khóa công khai mẫu (`private_key.pem`, `public_key.pem`).
- `sample_qrs/`: Chứa ảnh QR hợp lệ, QR bị giả mạo và biểu đồ benchmark.

## 2. Cài đặt thư viện
Yêu cầu Python 3.9 trở lên. Cài đặt các thư viện cần thiết bằng lệnh:

```bash
pip install -r requirements.txt
```

## 3. Chạy chương trình Menu chính (Terminal)
```bash
python app.py
```

## 4. Chạy nhanh toàn bộ kịch bản kiểm thử và xuất biểu đồ
```bash
python run_tests.py
```
