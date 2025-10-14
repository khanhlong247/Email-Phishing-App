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

            # Ghi log vào MySQL
            self.logger.log(result, from_addr)

            if not result.get("is_safe", False):
                print("[INFO] Email identified as SPAM — suppressed forwarding.")
                return '250 OK (SPAM detected and suppressed)'

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
    controller = Controller(CustomSMTPServer(), hostname='192.168.1.216', port=2525)
    controller.start()
    print("SMTP Proxy Server running on 192.168.1.216:2525...")
    return controller