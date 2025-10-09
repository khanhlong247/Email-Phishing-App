import os
from dotenv import load_dotenv

load_dotenv()

# SMTP Gateway Settings
SMTP_HOST = os.getenv('SMTP_HOST', 'localhost')  # Thay '0.0.0.0' bằng 'localhost'
SMTP_PORT = int(os.getenv('SMTP_PORT', 2525))  # Thay 25 bằng 2525

# Protected Entities
PROTECTED_EMAIL = os.getenv('PROTECTED_EMAIL')
PROTECTED_DOMAINS = [d.strip() for d in os.getenv('PROTECTED_DOMAINS', '').split(',') if d.strip()]  # Loại bỏ khoảng trắng và rỗng

# Main Mail Server for Forwarding
MAIN_MAIL_SERVER = os.getenv('MAIN_MAIL_SERVER')
RELAY_USER = os.getenv('RELAY_USER')
RELAY_PASSWORD = os.getenv('RELAY_PASSWORD')

# ML Model Path
MODEL_PATH = os.getenv('MODEL_PATH', 'models/svm_phishing_detector.pkl')  # Cập nhật theo yêu cầu của bạn

# Logging
LOG_DIR = os.getenv('LOG_DIR', 'data/logs')
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

# Blacklists for Network Filter
RBL_SERVERS = [s.strip() for s in os.getenv('RBL_SERVERS', 'zen.spamhaus.org,bl.spamcop.net').split(',') if s.strip()]  # Hỗ trợ danh sách từ .env

# Spam Threshold for ML Classifier
SPAM_THRESHOLD = float(os.getenv('SPAM_THRESHOLD', 0.5))

# API Settings
API_TOKEN = os.getenv('API_TOKEN', 'dfc418c23f67ec66fab2f287dbdc0b9a')  # Thêm token theo yêu cầu
API_URL = os.getenv('API_URL', 'http://localhost:8000/predict')  # URL mặc định cho API