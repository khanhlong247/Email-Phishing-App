import re
from email.parser import BytesParser
from email.policy import default
from classification.email_model import EmailClassifier
from classification.url_model import URLClassifier
from config import EMAIL_MODEL_PATH, URL_MODEL_PATH

def extract_urls(text: str) -> list:
    return re.findall(r'(https?://[^\s]+)', text)

class EmailProcessor:
    def __init__(self):
        self.email_model = EmailClassifier(EMAIL_MODEL_PATH)
        self.url_model = URLClassifier(URL_MODEL_PATH)

    def process(self, raw_email: bytes) -> dict:
        email_message = BytesParser(policy=default).parsebytes(raw_email)

        body = ""
        if email_message.is_multipart():
            for part in email_message.walk():
                if part.get_content_type() == 'text/plain':
                    body = part.get_payload(decode=True).decode(errors='ignore')
                    break
        else:
            body = email_message.get_payload(decode=True).decode(errors='ignore')

        email_label, margin = self.email_model.predict(body)
        result = {
            "email_label": email_label,
            "margin": margin,
            "body": body,
            "is_safe": True,
            "reason": "Safe email"
        }

        if email_label == "SPAM":
            result["is_safe"] = False
            result["reason"] = "Detected as SPAM"
            return result

        urls = extract_urls(body)
        result["urls"] = urls
        if urls:
            url_checks, has_phishing = [], False
            for url in urls:
                url_label, score = self.url_model.predict(url)
                url_checks.append((url, url_label, score))
                if url_label == "PHISHING":
                    has_phishing = True
            result["url_checks"] = url_checks
            if has_phishing:
                result["is_safe"] = False
                result["reason"] = "Phishing URL detected"

        return result
