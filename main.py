import os
import asyncio
import logging
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP
from email import message_from_bytes
import smtplib
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),  # Output to console
        logging.FileHandler('smtp_gateway.log')  # Output to file
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
PROTECTED_EMAIL = os.getenv("PROTECTED_EMAIL")  # e.g., user@example.com
MAIN_MAIL_SERVER = os.getenv("MAIN_MAIL_SERVER")  # e.g., smtp.gmail.com:587
RELAY_USER = os.getenv("MAIN_MAIL_SERVER_USER")
RELAY_PASSWORD = os.getenv("MAIN_MAIL_SERVER_PASSWORD")

# Placeholder for spam filtering
def is_spam(email_data):
    # Simple keyword-based spam check
    logger.info("Checking email for spam...")
    spam_keywords = ["viagra", "free money", "win prize"]
    is_spam_detected = any(keyword in email_data.lower() for keyword in spam_keywords)
    if is_spam_detected:
        logger.warning("Spam detected in email content")
    else:
        logger.info("No spam detected")
    return is_spam_detected

# Forward email to main mail server
async def forward_email(data, mailfrom, rcpttos):
    try:
        logger.info(f"Preparing to forward email from {mailfrom} to {rcpttos}")
        # Simulate 3-second delay
        logger.info("Holding email for 3 seconds...")
        await asyncio.sleep(3)
        
        host, port = MAIN_MAIL_SERVER.split(':')
        with smtplib.SMTP(host, int(port)) as server:
            server.starttls()
            server.login(RELAY_USER, RELAY_PASSWORD)
            server.sendmail(mailfrom, rcpttos, data)
            logger.info(f"Successfully forwarded email to {rcpttos}")
            print("Complete")  # Print "Complete" when done
    except Exception as e:
        logger.error(f"Failed to forward email: {e}")
        raise

# Custom SMTP handler
class SpamFilterHandler:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        logger.info(f"Received RCPT TO: {address}")
        # Check if recipient matches PROTECTED_EMAIL
        if address.lower() != PROTECTED_EMAIL.lower():
            logger.warning(f"Recipient {address} not protected by this gateway")
            return "550 Recipient not protected by this gateway"
        envelope.rcpt_tos.append(address)
        logger.info("Recipient accepted")
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        logger.info(f"Received email from {envelope.mail_from} to {envelope.rcpt_tos}")
        email_data = envelope.content.decode('utf-8', errors='replace')
        
        # Check for spam
        if is_spam(email_data):
            logger.warning(f"Spam detected for {envelope.rcpt_tos}, rejecting email")
            return "550 Spam detected"
        
        # Forward email
        await forward_email(envelope.content, envelope.mail_from, envelope.rcpt_tos)
        return "250 Message accepted for delivery"

# Run SMTP server
if __name__ == "__main__":
    if not PROTECTED_EMAIL or not MAIN_MAIL_SERVER:
        logger.error("PROTECTED_EMAIL and MAIN_MAIL_SERVER must be set in .env")
        raise ValueError("PROTECTED_EMAIL and MAIN_MAIL_SERVER must be set in .env")
    
    logger.info(f"Starting SMTP Gateway on port 25, protecting {PROTECTED_EMAIL}")
    controller = Controller(
        SpamFilterHandler(),
        hostname="0.0.0.0",
        port=25
    )
    controller.start()
    logger.info("SMTP Gateway is running")
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down SMTP Gateway")
        controller.stop()
        print("SMTP Gateway stopped")