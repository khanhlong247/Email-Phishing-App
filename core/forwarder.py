import smtplib
from config.settings import MAIN_MAIL_SERVER, RELAY_USER, RELAY_PASSWORD
import logging

logging.basicConfig(level=logging.INFO, filename='data/logs/forwarder.log')

def forward_email(data: bytes, mailfrom: str, rcpttos: list):
    try:
        host, port = MAIN_MAIL_SERVER.split(':')
        port = int(port)
        with smtplib.SMTP(host, port) as server:
            server.starttls()
            server.login(RELAY_USER, RELAY_PASSWORD)
            server.sendmail(mailfrom, rcpttos, data)
            logging.info(f"Successfully forwarded email to {rcpttos}")
    except Exception as e:
        logging.error(f"Failed to forward email: {e}")
        raise