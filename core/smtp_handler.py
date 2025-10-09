import asyncio
import aiohttp
from aiosmtpd.smtp import Envelope, Session, SMTP
from email import message_from_bytes
from filters.network import check_network_filters
from filters.content import check_content_filters
from core.forwarder import forward_email
from config.settings import PROTECTED_EMAIL, PROTECTED_DOMAINS, SPAM_THRESHOLD, MODEL_PATH, API_TOKEN
import logging
import os

logging.basicConfig(level=logging.INFO, filename='data/logs/smtp.log')

class SpamFilterHandler:
    async def handle_RCPT(self, server: SMTP, session: Session, envelope: Envelope, address: str, rcpt_options: list):
        # Check if recipient is protected
        domain = address.split('@')[-1].lower()
        if address.lower() != PROTECTED_EMAIL.lower() and domain not in [d.lower() for d in PROTECTED_DOMAINS]:
            logging.warning(f"Rejected unprotected recipient: {address}")
            return "550 Recipient not protected by this gateway"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server: SMTP, session: Session, envelope: Envelope):
        try:
            email_data = envelope.content
            msg = message_from_bytes(email_data)
            body = msg.get_payload(decode=True).decode(errors='replace') if msg.get_payload() else ""

            # Layer 1: Network Filters
            if not check_network_filters(session.peer[0]):
                logging.warning(f"Spam detected by network filters from {session.peer[0]}")
                return "550 Spam detected by network filters"

            # Layer 2: Content Filters
            if check_content_filters(body):
                logging.warning(f"Spam detected by content filters")
                return "550 Spam detected by content filters"

            # Layer 3: Call ML API with token
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": f"Bearer {API_TOKEN}"}
                async with session.post(
                    "http://localhost:8000/predict",
                    json={"text": body, "model_path": MODEL_PATH},
                    headers=headers
                ) as response:
                    if response.status != 200:
                        raise Exception(f"API error: {response.status}")
                    result = await response.json()
                    spam_prob = result.get("probability", 0.0)
                    logging.info(f"API returned spam probability: {spam_prob} with model {MODEL_PATH}")

            # Decision based on threshold
            if spam_prob > SPAM_THRESHOLD:
                logging.warning(f"Spam detected by ML API (prob: {spam_prob})")
                return "550 Spam detected by ML classifier"

            # If clean, forward
            forward_email(envelope.content, envelope.mail_from, envelope.rcpt_tos)
            logging.info(f"Email forwarded to {envelope.rcpt_tos}")
            return "250 Message accepted for delivery"
        except Exception as e:
            logging.error(f"Error processing email: {e}")
            return "451 Temporary failure, please try again later"