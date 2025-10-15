# 📨 EmailChecker Server

## 🧩 Giới thiệu
**EmailChecker Server** là thành phần trung tâm trong hệ thống giám sát email thời gian thực.  
Server hoạt động như một **SMTP Proxy**, tiếp nhận email từ client, **phân tích – phân loại spam/phishing**, và **gửi kết quả đến Desktop Client** thông qua **WebSocket**.  
Hệ thống cũng ghi lại toàn bộ kết quả xử lý vào **MySQL** để truy xuất và đánh giá sau này.

---

## ⚙️ Yêu cầu hệ thống
| Thành phần | Phiên bản khuyến nghị |
|-------------|------------------------|
| Hệ điều hành | Ubuntu 20.04 / Amazon Linux 2 / Windows Server |
| Python | 3.9+ |
| MySQL | 8.0+ |
| RAM tối thiểu | 4 GB |
| Cổng mở | 2525 (SMTP), 8765 (WebSocket) |

---

## 🗂️ Cấu trúc thư mục

EmailChecker_Server/

├── classification/         # Chứa model và pipeline phân loại email  
├── database/               # Module kết nối và ghi dữ liệu MySQL  
├── smtp/                   # SMTP proxy, xử lý mail đến  
├── models/                 # Các model .pkl, .joblib huấn luyện sẵn  
├── app.py                  # Điểm khởi động server  
├── config.py               # Cấu hình IP, port, DB  
├── requirements.txt        # Danh sách thư viện cần thiết  
├── .env                    # Biến môi trường (tùy chọn)  
└── README.md               # Tài liệu hướng dẫn  

---

### 2️⃣ Cấu hình thông tin

Tạo tệp `.env` trong thư mục gốc của dự án với nội dung sau:

```bash
PROTECTED_EMAIL=your_protected_email@example.com
MAIN_MAIL_SERVER=smtp.gmail.com:587
RELAY_PASSWORD=your_smtp_password

MYSQL_HOST=localhost
MYSQL_USER=root
MYSQL_PASSWORD=your_password
MYSQL_DB=emailchecker
```

> 🔒 **Lưu ý bảo mật:**  
> - Không commit tệp `.env` lên GitHub.  
> - Có thể thay đổi `MAIN_MAIL_SERVER` và `PORT` để phù hợp với mail server nội bộ.  
> - Các thông tin đăng nhập MySQL nên có quyền giới hạn (SELECT, INSERT).  

---

#### Liên hệ "khanhlong024@gmail.com" để lấy các folder models, disk, build và file .env

### 3️⃣ Khởi chạy server

Chạy các lệnh sau trong terminal (tại thư mục gốc dự án):

```bash
# Cài đặt thư viện cần thiết
pip install -r requirements.txt

# Khởi động server
python3 app.py
```

Khi chạy thành công, terminal sẽ hiển thị:

```
🚀 EmailChecker Server started successfully!
📡 SMTP Proxy listening on port 2525
🌐 WebSocket Server listening on port 8765
💾 Connected to MySQL: emailchecker
```

> 🔁 Để chạy nền liên tục trên Linux:
> ```bash
> nohup python3 app.py > server.log 2>&1 &
> ```

---

### 🔌 Tích hợp với EmailChecker Desktop Client

**Kết nối thời gian thực:**  
- Desktop Client sử dụng WebSocket để nhận dữ liệu phân loại từ server.  
- Mặc định, client sẽ kết nối đến địa chỉ:
  ```
  ws://<server_ip>:8765
  ```
- Khi một email mới được xử lý, client sẽ hiển thị **nội dung email, kết quả phân loại và log xử lý** ngay lập tức.  

**Luồng dữ liệu tổng quát:**
```
SMTP Mail → [EmailChecker Server] → (Phân loại & Ghi MySQL)
                                     ↓
                             [WebSocket Broadcast]
                                     ↓
                          [EmailChecker Desktop Client]
```

---

### 🧠 Hoạt động xử lý email

Quy trình xử lý tại server gồm 5 bước chính:

1. 📥 **Nhận email** từ ứng dụng gửi mail (qua port `2525`).  
2. 🔍 **Phân tích nội dung**: trích xuất URL, tiêu đề, domain, và đặc trưng từ nội dung.  
3. 🤖 **Phân loại** bằng mô hình học máy (`.pkl` / `.joblib`) được huấn luyện trước.  
4. 💾 **Ghi kết quả** vào MySQL (thông tin người gửi, trạng thái spam, độ tin cậy, timestamp).  
5. 📡 **Phát tín hiệu WebSocket** để client cập nhật giao diện theo thời gian thực.

> Nếu email được xác định là **spam/phishing**, hệ thống sẽ **ngăn chuyển tiếp** đến mail server thật để đảm bảo an toàn.

---

### 🛠️ Các module chính

| 🧩 Module | 📝 Chức năng chính |
|-----------|--------------------|
| **`smtp/smtp_server.py`** | SMTP Proxy chính, tiếp nhận và xử lý email đến |
| **`smtp/email_processor.py`** | Tiền xử lý email, trích xuất nội dung và đặc trưng đầu vào model |
| **`classification/`** | Chứa mô hình và thuật toán học máy để nhận dạng spam/phishing |
| **`database/mysql_logger.py`** | Ghi log và kết quả phân loại vào cơ sở dữ liệu MySQL |
| **`config.py`** | Quản lý thông tin cấu hình hệ thống, port, mail relay và DB |
| **`app.py`** | Tập hợp toàn bộ luồng khởi chạy (SMTP + WebSocket + DB) |

---

### 📄 Giấy phép & Bản quyền

#### © 2025 EmailChecker Project  
Bản quyền thuộc về **Tác giả & Nhóm phát triển EmailChecker**.  
Mọi quyền được bảo lưu.  

Phần mềm này phát hành theo **Giấy phép MIT**, cho phép:
- ✅ Sử dụng, sao chép, sửa đổi và phân phối lại phần mềm;  
- ⚖️ Với điều kiện giữ nguyên thông tin bản quyền gốc và giấy phép đi kèm.  

#### 🪪 Trích nội dung giấy phép (MIT License)
```
MIT License

Copyright (c) 2025 EmailChecker

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

> 🔗 Xem toàn văn tại [opensource.org/licenses/MIT](https://opensource.org/licenses/MIT)

---

### 👨‍💻 Tác giả & Liên hệ

**Nhóm phát triển:**  
- 👨‍💻 **Khánh Long** – Trưởng nhóm kỹ thuật, phụ trách SMTP Proxy, WebSocket và AI Model  
- 📧 **Email:** [khanhlong024@gmail.com](mailto:khanhlong024@gmail.com)  
- 🌐 **GitHub:** [github.com/khanhlong247](https://github.com/khanhlong247)

---

> 💬 *EmailChecker Server là thành phần trung tâm của hệ thống giám sát email thời gian thực.  
> Dự án được phát triển nhằm nâng cao bảo mật và phát hiện sớm các cuộc tấn công phishing.  
> Nếu bạn sử dụng hoặc mở rộng mã nguồn, vui lòng ghi nhận nhóm tác giả trong phần “About” hoặc tài liệu dự án.*


