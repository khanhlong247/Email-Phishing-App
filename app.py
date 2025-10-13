# -*- coding: utf-8 -*-
"""
SMTP Phishing Detector Proxy Server
Author: khanhlong (dựa trên Final Polished Version và Custom SMTP Server)
"""

import asyncio
import os
import re
import joblib
import pickle
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from tldextract import extract
import xgboost as xgb
from datetime import datetime
import sys
from email.parser import BytesParser
from email.policy import default
import smtplib
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import Error
import mysql.connector
from mysql.connector import Error

# Load environment variables from .env file
load_dotenv()

# ==========================
# 🔧 CONFIG
# ==========================
MODEL_DIR = "models"

EMAIL_MODEL_PATH = os.path.join(MODEL_DIR, "svm_email_classifier.pkl")
URL_MODEL_PATH = os.path.join(MODEL_DIR, "xgb_phishing_url_model.json")
FEATURE_ORDER_PATH = os.path.join(MODEL_DIR, "xgb_feature_order.pkl")

SPAM_LABEL = 1
PHISH_LABEL = 1

# Database configuration
DB_HOST = os.environ.get("DB_HOST")
DB_PORT = int(os.environ.get("DB_PORT"))
DB_NAME = os.environ.get("DB_NAME")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")

# ==========================
# 🧠 LOAD MODELS
# ==========================
print("=== 🧠 SMTP Phishing Detector Proxy Server ===")

EMAIL_MODEL = None
URL_MODEL = None
FEATURE_ORDER = []

if os.path.exists(EMAIL_MODEL_PATH):
    EMAIL_MODEL = joblib.load(EMAIL_MODEL_PATH)
    print(f"✅ Email model loaded: {EMAIL_MODEL_PATH}")
else:
    print("⚠️ Email model not found.")

if os.path.exists(URL_MODEL_PATH):
    URL_MODEL = xgb.XGBClassifier()
    URL_MODEL.load_model(URL_MODEL_PATH)
    print(f"✅ URL model loaded: {URL_MODEL_PATH}")
else:
    print("⚠️ URL model not found.")

if os.path.exists(FEATURE_ORDER_PATH):
    with open(FEATURE_ORDER_PATH, "rb") as f:
        FEATURE_ORDER = pickle.load(f)
    print(f"✅ Feature order loaded ({len(FEATURE_ORDER)} features)")
else:
    print("⚠️ Feature order not found.")

# ==========================
# 🔍 FEATURE EXTRACTOR
# ==========================
def extract_url_features(url: str) -> pd.DataFrame:
    feats = {}
    try:
        parsed = urlparse(url)
        ext = extract(url)
        host = parsed.netloc or ext.registered_domain or ""
        path = parsed.path or ""
        query = parsed.query or ""

        # Đặc trưng cơ bản đã có
        feats["url_length"] = len(url)
        feats["hostname_length"] = len(host)
        feats["path_length"] = len(path)  # Thêm tạm vì không có trong danh sách gốc
        feats["nb_dots"] = url.count(".")
        feats["nb_hyphens"] = url.count("-")
        feats["nb_at"] = url.count("@")
        feats["nb_qm"] = url.count("?")
        feats["nb_and"] = url.count("&")
        feats["nb_or"] = url.count("|")
        feats["nb_eq"] = url.count("=")
        feats["nb_underscore"] = url.count("_")
        feats["nb_tilde"] = url.count("~")
        feats["nb_percent"] = url.count("%")
        feats["nb_slash"] = url.count("/")
        feats["nb_star"] = url.count("*")
        feats["nb_colon"] = url.count(":")
        feats["nb_comma"] = url.count(",")
        feats["nb_semicolumn"] = url.count(";")
        feats["nb_dollar"] = url.count("$")
        feats["nb_space"] = url.count(" ")
        feats["nb_www"] = 1 if "www" in host.lower() else 0
        feats["nb_com"] = 1 if ".com" in url.lower() else 0
        feats["nb_dslash"] = url.count("//")
        feats["http_in_path"] = 1 if "http" in path.lower() else 0
        feats["https_token"] = 1 if parsed.scheme == "https" else 0
        feats["ratio_digits_url"] = sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0
        feats["ratio_digits_host"] = sum(c.isdigit() for c in host) / len(host) if len(host) > 0 else 0
        feats["punycode"] = 1 if any(ord(c) > 127 for c in url) else 0  # Kiểm tra ký tự không ASCII
        feats["port"] = 1 if ":" in host.split("@")[-1] and host.split(":")[-1].isdigit() else 0
        feats["tld_in_path"] = 1 if ext.suffix in path.lower() else 0
        feats["tld_in_subdomain"] = 1 if ext.suffix in host.lower() and ext.subdomain else 0
        feats["abnormal_subdomain"] = 1 if ext.subdomain and len(ext.subdomain.split(".")) > 2 else 0
        feats["nb_subdomains"] = host.count(".") if host else 0
        feats["prefix_suffix"] = 1 if "-" in host else 0  # Heuristic đơn giản
        feats["random_domain"] = 0  # Cần thêm kiểm tra (tạm thời 0)
        feats["shortening_service"] = 0  # Cần danh sách dịch vụ (tạm thời 0)
        feats["path_extension"] = 1 if "." in path.split("/")[-1] else 0
        feats["nb_redirection"] = 0  # Cần phân tích HTTP (tạm thời 0)
        feats["nb_external_redirection"] = 0  # Cần phân tích HTTP (tạm thời 0)
        feats["length_words_raw"] = len(url.split())  # Số từ thô
        feats["char_repeat"] = 1 if any(url.count(c) > 3 for c in url) else 0  # Heuristic lặp ký tự
        feats["shortest_words_raw"] = min(len(w) for w in url.split()) if url.split() else 0
        feats["shortest_word_host"] = min(len(w) for w in host.split(".")) if host.split(".") else 0
        feats["shortest_word_path"] = min(len(w) for w in path.split("/")) if path.split("/") else 0
        feats["longest_words_raw"] = max(len(w) for w in url.split()) if url.split() else 0
        feats["longest_word_host"] = max(len(w) for w in host.split(".")) if host.split(".") else 0
        feats["longest_word_path"] = max(len(w) for w in path.split("/")) if path.split("/") else 0
        feats["avg_words_raw"] = sum(len(w) for w in url.split()) / len(url.split()) if url.split() else 0
        feats["avg_word_host"] = sum(len(w) for w in host.split(".")) / len(host.split(".")) if host.split(".") else 0
        feats["avg_word_path"] = sum(len(w) for w in path.split("/")) / len(path.split("/")) if path.split("/") else 0
        feats["phish_hints"] = 1 if any(w in url.lower() for w in ["verify", "login", "account"]) else 0
        feats["domain_in_brand"] = 0  # Cần danh sách thương hiệu (tạm thời 0)
        feats["brand_in_subdomain"] = 0  # Cần danh sách thương hiệu (tạm thời 0)
        feats["brand_in_path"] = 0  # Cần danh sách thương hiệu (tạm thời 0)
        feats["suspecious_tld"] = 1 if ext.suffix not in ["com", "org", "net"] else 0  # Heuristic đơn giản
        feats["statistical_report"] = 0  # Cần dữ liệu thống kê (tạm thời 0)
        feats["nb_hyperlinks"] = 0  # Cần nội dung trang (tạm thời 0)
        feats["ratio_intHyperlinks"] = 0  # Cần nội dung trang (tạm thời 0)
        feats["ratio_extHyperlinks"] = 0  # Cần nội dung trang (tạm thời 0)
        feats["ratio_nullHyperlinks"] = 0  # Cần nội dung trang (tạm thời 0)
        feats["nb_extCSS"] = 0  # Cần nội dung trang (tạm thời 0)
        feats["ratio_intRedirection"] = 0  # Cần phân tích HTTP (tạm thời 0)
        feats["ratio_extRedirection"] = 0  # Cần phân tích HTTP (tạm thời 0)
        feats["ratio_intErrors"] = 0  # Cần phân tích HTTP (tạm thời 0)
        feats["ratio_extErrors"] = 0  # Cần phân tích HTTP (tạm thời 0)
        feats["login_form"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["external_favicon"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["links_in_tags"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["submit_email"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["ratio_intMedia"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["ratio_extMedia"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["sfh"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["iframe"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["popup_window"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["safe_anchor"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["onmouseover"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["right_clic"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["empty_title"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["domain_in_title"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["domain_with_copyright"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["whois_registered_domain"] = 0  # Cần WHOIS (tạm thời 0)
        feats["domain_registration_length"] = 0  # Cần WHOIS (tạm thời 0)
        feats["domain_age"] = -1  # Heuristic đơn giản
        feats["web_traffic"] = 0  # Cần dữ liệu lưu lượng (tạm thời 0)
        feats["dns_record"] = 1 if re.match(r".+\.[a-z]{2,}$", host) else 0  # Heuristic đơn giản
        feats["google_index"] = 1  # Giả định (tạm thời 1)
        feats["page_rank"] = 0  # Cần API PageRank (tạm thời 0)

        # Điền các đặc trưng còn thiếu bằng 0
        for f in FEATURE_ORDER:
            if f not in feats:
                feats[f] = 0.0

        df = pd.DataFrame([[feats[f] for f in FEATURE_ORDER]], columns=FEATURE_ORDER)
        return df
    except Exception as e:
        print(f"[ERROR] Failed to extract features for URL '{url}': {e}")
        return pd.DataFrame([[0] * len(FEATURE_ORDER)], columns=FEATURE_ORDER)

# ==========================
# 📧 EMAIL PREDICTION
# ==========================
def predict_email(text: str):
    try:
        X_input = [text]
        raw_pred = EMAIL_MODEL.predict(X_input)[0]
        if hasattr(EMAIL_MODEL, "decision_function"):
            margin = float(EMAIL_MODEL.decision_function(X_input)[0])
        elif hasattr(EMAIL_MODEL, "predict_proba"):
            margin = float(np.max(EMAIL_MODEL.predict_proba(X_input)[0]))
        else:
            margin = None

        label = "NON-SPAM" if margin < 1.0 else "SPAM"
        return label, margin
    except Exception as e:
        return f"[ERROR] {e}", None

# ==========================
# 🌐 URL PREDICTION
# ==========================
def predict_url(url: str):
    try:
        feats = extract_url_features(url)
        score = float(URL_MODEL.predict_proba(feats)[0][PHISH_LABEL])
        label = "PHISHING" if score < 0.1 else "LEGIT"
        return label, score
    except Exception as e:
        return f"[ERROR] {e}", 0.0

# ==========================
# 🔍 EXTRACT URLS FROM TEXT
# ==========================
def extract_urls(text: str) -> list:
    url_pattern = r'(https?://[^\s]+)'
    urls = re.findall(url_pattern, text)
    return urls

# ==========================
# 📨 PROCESS SMTP EMAIL
# ==========================
def process_email(raw_email: bytes) -> dict:
    try:
        email_message = BytesParser(policy=default).parsebytes(raw_email)
        
        body = ""
        if email_message.is_multipart():
            for part in email_message.walk():
                if part.get_content_type() == 'text/plain':
                    body = part.get_payload(decode=True).decode(errors='ignore')
                    break
        else:
            body = email_message.get_payload(decode=True).decode(errors='ignore')
        
        email_label, margin = predict_email(body)
        
        result = {
            "email_label": email_label,
            "margin": margin,
            "body": body,
            "is_safe": True,
            "reason": "Safe email"
        }
        
        if email_label == "SPAM":
            result["is_safe"] = False
            result["reason"] = "Detected as SPAM by email model"
            return result
        
        urls = extract_urls(body)
        result["urls"] = urls
        
        if urls:
            url_checks = []
            has_phishing = False
            for url in urls:
                url_label, score = predict_url(url)
                url_checks.append((url, url_label, score))
                if url_label == "PHISHING":
                    has_phishing = True
            result["url_checks"] = url_checks
            if has_phishing:
                result["is_safe"] = False
                result["reason"] = "Phishing URL detected in email"
        
        return result
    except Exception as e:
        return {"error": str(e)}

# ==========================
# 🧾 LOG RESULTS TO MYSQL
# ==========================

def log_result_to_mysql(result, from_addr):
    """
    Lưu kết quả phân loại email và phân tích phishing URL vào MySQL.
    - Mỗi URL trong email sẽ được lưu thành một bản ghi riêng trong bảng url_phishing_analysis.
    - Ghi cột 'url' thay cho 'email'.
    - Đảm bảo chỉ chèn những cột thực sự tồn tại trong bảng.
    """
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        cursor = conn.cursor()

        # 1️⃣ Lưu kết quả phân loại email tổng thể (vẫn giữ bảng email_classification nếu cần)
        cursor.execute(
            "INSERT INTO email_classification (content, spam_result) VALUES (%s, %s)",
            (result.get("body", ""), result.get("email_label", "UNKNOWN"))
        )

        # 2️⃣ Lấy danh sách cột hiện có trong bảng để đảm bảo đồng bộ
        cursor.execute("SHOW COLUMNS FROM url_phishing_analysis")
        db_columns = [row[0] for row in cursor.fetchall()]

        # 3️⃣ Mapping tên feature (nếu feature extractor dùng tên khác)
        name_map = {
            "length_url": "url_length",
            "length_hostname": "hostname_length",
            "length_path": "path_length",
            # thêm mapping khác nếu có
        }

        # 4️⃣ Ghi từng URL vào bảng
        if "url_checks" in result and result["url_checks"]:
            for url, label, score in result["url_checks"]:
                features = extract_url_features(url).iloc[0].to_dict()

                # Bổ sung thêm thông tin
                features["url"] = url
                features["phishing_result"] = label
                features["phishing_score"] = score

                # Danh sách cột & giá trị sẽ insert
                columns_to_insert = ["url"]
                values = [features["url"]]

                # Duyệt qua FEATURE_ORDER để lấy đúng thứ tự cột
                for feat_name in FEATURE_ORDER:
                    db_col = name_map.get(feat_name, feat_name)
                    if db_col not in db_columns:
                        continue  # bỏ qua cột không tồn tại

                    val = features.get(feat_name, 0.0)
                    # đảm bảo là số hợp lệ
                    if isinstance(val, (int, float)):
                        try:
                            if np.isnan(val) or np.isinf(val):
                                val = 0.0
                        except Exception:
                            val = 0.0
                        val = float(val)
                    else:
                        try:
                            val = float(val)
                        except Exception:
                            val = 0.0

                    columns_to_insert.append(db_col)
                    values.append(val)

                # Thêm kết quả phân loại nếu có
                if "phishing_result" in db_columns:
                    columns_to_insert.append("phishing_result")
                    values.append(label)

                if "phishing_score" in db_columns:
                    columns_to_insert.append("phishing_score")
                    values.append(score)

                # Thêm timestamp nếu bảng có
                if "timestamp" in db_columns:
                    columns_to_insert.append("timestamp")
                    values.append(datetime.now())

                # Xây dựng câu lệnh INSERT động
                placeholders = ", ".join(["%s"] * len(values))
                query = f"INSERT INTO url_phishing_analysis ({', '.join(columns_to_insert)}) VALUES ({placeholders})"
                cursor.execute(query, tuple(values))

        else:
            print("[INFO] Không có URL nào để lưu vào bảng url_phishing_analysis.")

        conn.commit()
        print(f"[OK] Đã lưu {len(result.get('url_checks', []))} URL vào MySQL (nguồn email: {from_addr})")

    except Error as e:
        print(f"[ERROR] Ghi vào MySQL thất bại: {e}")

    finally:
        try:
            if conn and conn.is_connected():
                cursor.close()
                conn.close()
        except Exception:
            pass

class CustomSMTPServer:
    async def handle_EHLO(self, server, session, envelope, hostname):
        print(f"EHLO from: {hostname}")
        session.host_name = hostname
        return '250 OK'

    async def handle_HELO(self, server, session, envelope, hostname):
        print(f"HELO from: {hostname}")
        session.host_name = hostname
        return '250 OK'

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        print(f"MAIL FROM: {address}")
        envelope.mail_from = address
        return '250 OK'

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        print(f"RCPT TO: {address}")
        envelope.rcpt_tos.append(address)
        return '250 OK'

    async def handle_DATA(self, server, session, envelope):
        try:
            print("Received DATA command")
            email_data = envelope.content
            parser = BytesParser(policy=default)
            message = parser.parsebytes(email_data)

            from_addr = envelope.mail_from
            to_addr = envelope.rcpt_tos
            subject = message.get('subject', 'No Subject')
            body = message.get_payload(decode=True).decode('utf-8', errors='ignore') if message.get_payload() else "No Body"

            print(f"Received email from: {from_addr}")
            print(f"To: {to_addr}")
            print(f"Subject: {subject}")
            print(f"Body: {body[:200]}...")

            result = process_email(email_data)
            print("\n🔹 ===== EMAIL DETECTION RESULT =====")
            print(f"Email Label: {result.get('email_label')}")
            print(f"Margin: {result.get('margin')}")
            print(f"Is Safe: {result.get('is_safe')}")
            print(f"Reason: {result.get('reason')}")
            if "urls" in result:
                print("\nURLs Found:")
                for url, label, score in result.get("url_checks", []):
                    print(f"{url} → {label} (score={score:.4f})")

            # Log results to MySQL
            log_result_to_mysql(result, from_addr)

            if not result.get("is_safe", False):
                print("Email blocked due to detection.")
                return '550 Email blocked due to phishing/spam detection'

            protected_email = os.environ.get("PROTECTED_EMAIL")
            main_mail_server = os.environ.get("MAIN_MAIL_SERVER")
            app_password = os.environ.get("RELAY_PASSWORD")

            if not all([protected_email, main_mail_server, app_password]):
                print("Error: Missing environment variables")
                return '550 Environment variables missing'

            host, port = main_mail_server.split(':')
            with smtplib.SMTP(host, int(port)) as smtp:
                smtp.starttls()
                smtp.login(protected_email, app_password)
                smtp.sendmail(from_addr, to_addr, email_data)
                print(f"Email forwarded to {main_mail_server}")
                return '250 OK'

        except Exception as e:
            print(f"Error forwarding email: {str(e)}")
            return '550 Forwarding failed'

async def main():
    controller = Controller(
        CustomSMTPServer(),
        hostname='192.168.1.109',
        port=2525
    )
    controller.start()
    print("SMTP Proxy Server running on 192.168.1.109...")
    try:
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        controller.stop()
        print("SMTP Proxy Server stopped.")

if __name__ == "__main__":
    asyncio.run(main())