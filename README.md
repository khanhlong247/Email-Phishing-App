# 📧 EmailChecker Desktop Client

## 🧩 Giới thiệu
**EmailChecker Desktop App** là ứng dụng giao diện người dùng (UI) viết bằng **PyQt5**, cho phép người dùng theo dõi và giám sát các email đến được xử lý bởi **SMTP Proxy Server** thông qua kết nối **WebSocket**.  
Ứng dụng hiển thị **nội dung email**, **quá trình lọc và phân loại** (spam / hợp lệ), và trạng thái kết nối với server theo thời gian thực.

---

## ⚙️ Yêu cầu hệ thống
| Thành phần | Phiên bản khuyến nghị |
|-------------|------------------------|
| Hệ điều hành | Windows 10/11 64-bit |
| Python | Không bắt buộc (đã build `.exe`) |
| RAM tối thiểu | 2 GB |
| Internet | Bắt buộc (để kết nối tới server qua WebSocket) |

---

## 🗂️ Cấu trúc thư mục

EmailChecker/

├── dist/

│ └── EmailChecker.exe # File thực thi chính

├── classification/ # (Tuỳ chọn) chứa logic phân tích nội dung

├── database/ # (Tuỳ chọn) chứa kết nối hoặc log cục bộ

├── models/ # (Tuỳ chọn) chứa model .pkl, .joblib

├── smtp/ # Chứa module hỗ trợ xử lý email

├── app.py # Điểm khởi đầu chính (trước khi build)

├── ui.py # Giao diện PyQt5 + kết nối WebSocket

├── config.py # Cấu hình IP/port kết nối

├── logo.png, logo.ico # Logo ứng dụng

├── .env # Thông tin cấu hình động (nếu có)

└── README.md # Tài liệu hướng dẫn

---

## 🚀 Cài đặt & chạy chương trình

1. Giải nén file `EmailChecker_Client.zip`.
2. Mở thư mục `dist/`.
3. Chạy file: EmailChecker.exe

### Liên hệ "khanhlong024@gmail.com" để lấy các folder models, disk, build và file .env

## 📄 Giấy phép & Bản quyền

### © 2025 EmailChecker Project
Bản quyền thuộc về **Tác giả & Nhóm phát triển EmailChecker**.  
Mọi quyền được bảo lưu.

Phần mềm này được phát hành theo **Giấy phép MIT**, cho phép:
- Sử dụng, sao chép, sửa đổi và phân phối lại phần mềm;
- Với điều kiện giữ nguyên thông tin bản quyền gốc và giấy phép đi kèm.

---

## 👨‍💻 Tác giả & Liên hệ

**Nhóm phát triển:**  
- 👨‍💻 **Khánh Long** – Trưởng nhóm kỹ thuật, phụ trách hệ thống SMTP & WebSocket.  
- 📧 **Email:** [khanhlong024@gmail.com](mailto:khanhlong024@gmail.com)  
- 🌐 **GitHub:** [github.com/khanhlong247](https://github.com/khanhlong247)

---

> 💬 *EmailChecker Desktop Client là phần mềm mã nguồn mở, được phát triển với mục tiêu hỗ trợ giám sát và phân loại email theo thời gian thực. Nếu bạn sử dụng hoặc phát triển lại dự án, vui lòng ghi nhận nhóm tác giả trong tài liệu hoặc phần "About" của ứng dụng.*