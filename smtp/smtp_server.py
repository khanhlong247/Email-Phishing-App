import smtplib
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP
from email.parser import BytesParser
from email.policy import default
from database.mysql_logger import MySQLLogger
from smtp.email_processor import EmailProcessor
from config import PROTECTED_EMAIL, MAIN_MAIL_SERVER, RELAY_PASSWORD
import os

class CustomSMTPServer:
    def __init__(self):
        self.processor = EmailProcessor()
        self.logger = MySQLLogger()

    async def handle_DATA(self, server, session, envelope):
        try:
            email_data = envelope.content
            from_addr = envelope.mail_from
            to_addr = envelope.rcpt_tos

            result = self.processor.process(email_data)
            print(f"\n=== EMAIL RESULT ===\nLabel: {result['email_label']}, Safe: {result['is_safe']}")
            if "url_checks" in result:
                for u, l, s in result["url_checks"]:
                    print(f"{u} → {l} ({s:.4f})")

            self.logger.log(result, from_addr)

            if not result.get("is_safe", False):
                return '550 Email blocked due to phishing/spam detection'

            host, port = MAIN_MAIL_SERVER.split(':')
            with smtplib.SMTP(host, int(port)) as smtp:
                smtp.starttls()
                smtp.login(PROTECTED_EMAIL, RELAY_PASSWORD)
                smtp.sendmail(from_addr, to_addr, email_data)
                print(f"Email forwarded to {MAIN_MAIL_SERVER}")
            return '250 OK'

        except Exception as e:
            print(f"[ERROR] {e}")
            return '550 Forwarding failed'

def start_smtp_server():
    controller = Controller(CustomSMTPServer(), hostname='192.168.1.109', port=2525)
    controller.start()
    print("SMTP Proxy Server running on 192.168.1.109...")
    return controller
