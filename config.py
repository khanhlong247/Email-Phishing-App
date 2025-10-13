import os
from dotenv import load_dotenv

load_dotenv()

MODEL_DIR = "models"

EMAIL_MODEL_PATH = os.path.join(MODEL_DIR, "svm_email_classifier.pkl")
URL_MODEL_PATH = os.path.join(MODEL_DIR, "xgb_phishing_url_model.json")
FEATURE_ORDER_PATH = os.path.join(MODEL_DIR, "xgb_feature_order.pkl")

SPAM_LABEL = 1
PHISH_LABEL = 1

# Database config
DB_HOST = os.environ.get("DB_HOST")
DB_PORT = int(os.environ.get("DB_PORT"))
DB_NAME = os.environ.get("DB_NAME")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")

PROTECTED_EMAIL = os.environ.get("PROTECTED_EMAIL")
MAIN_MAIL_SERVER = os.environ.get("MAIN_MAIL_SERVER")
RELAY_PASSWORD = os.environ.get("RELAY_PASSWORD")
