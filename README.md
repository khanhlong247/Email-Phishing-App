# Phishing Detector

Ứng dụng web mô phỏng phát hiện phishing bằng trí tuệ nhân tạo (AI) được phát triển cho bài tập lớn (BTL) môn Bảo Mật Ứng dụng.

## Hướng dẫn cài đặt

### 1. Cài đặt Python/Flask

- Yêu cầu: Cài đặt Python 3.x.
- Kiểm tra phiên bản Python:
  ```bash
  python3 --version
  ```
- Cài đặt các thư viện cần thiết:
  ```bash
  pip install -r requirements.txt
  ```
- Khởi động API Flask:
  ```bash
  cd ai_model
  python predict.py
  ```
  - API sẽ chạy trên `http://localhost:5000`.

### 2. Cài đặt Node.js

- Yêu cầu: Cài đặt Node.js và npm.
- Kiểm tra phiên bản:
  ```bash
  node --version
  npm --version
  ```
- Cài đặt các dependencies:
  ```bash
  cd web
  npm install
  ```
- Khởi động server Node.js:
  ```bash
  node app.js
  ```
  - Server sẽ chạy trên `http://localhost:3000`.

### 3. Truy cập ứng dụng

- Mở trình duyệt và truy cập: `http://localhost:3000`.

## Công nghệ sử dụng

- **Flask**: Xây dựng API để tích hợp và chạy model AI.
- **Node.js/Express**: Làm backend cho ứng dụng web, phục vụ API và file tĩnh.
- **JavaScript**: Tạo giao diện động phía client (không sử dụng HTML tĩnh hoặc EJS).
- **Bootstrap**: Cung cấp giao diện responsive và thân thiện với người dùng.
- **CSS**: Tùy chỉnh giao diện với file `style.css`.
