# smtp_server.py (cho WebSocket)
import smtplib
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP
from email.parser import BytesParser
from email.policy import default
from database.mysql_logger import MySQLLogger
from smtp.email_processor import EmailProcessor
from config import PROTECTED_EMAIL, MAIN_MAIL_SERVER, RELAY_PASSWORD
import os
import asyncio
import websockets
import json

custom_server = None  # Biến global để chia sẻ instance


# ✅ Đảm bảo server luôn tồn tại
def ensure_server():
    global custom_server
    if custom_server is None:
        custom_server = CustomSMTPServer()
    return custom_server


class CustomSMTPServer:
    def __init__(self):
        global custom_server
        self.processor = EmailProcessor()
        self.logger = MySQLLogger()
        self.websocket_clients = set()
        custom_server = self  # Gán instance global

    async def handle_DATA(self, server, session, envelope):
        try:
            email_data = envelope.content
            from_addr = envelope.mail_from
            to_addr = envelope.rcpt_tos

            # Parse email để lấy header & body rõ ràng
            parser = BytesParser(policy=default)
            msg = parser.parsebytes(email_data)
            subject = msg.get("Subject", "")
            sender = msg.get("From", "")
            recipients = msg.get_all("To", [])
            body = ""

            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body += part.get_payload(decode=True).decode(errors="ignore")
            else:
                body = msg.get_payload(decode=True).decode(errors="ignore")

            # Gửi nội dung đầy đủ đến WebSocket clients
            full_message = (
                f"From: {sender}\n"
                f"To: {', '.join(recipients)}\n"
                f"Subject: {subject}\n"
                f"Body:\n{body}\n"
            )

            print(full_message)  # In ra console rõ ràng, không emoji

            # Xử lý bằng model
            result = self.processor.process(email_data)
            log_message = f"\n=== EMAIL RESULT ===\nLabel: {result['email_label']}, Safe: {result['is_safe']}"
            print(log_message)
            if "url_checks" in result:
                for u, l, s in result["url_checks"]:
                    url_log = f"{u} → {l} ({s:.4f})"
                    print(f"{url_log}\n\n")
                    log_message += f"\n{url_log}"

            # Ghi log vào DB
            self.logger.log(result, from_addr)

            # Gửi log và nội dung email tới WebSocket clients
            if custom_server.websocket_clients:
                await asyncio.gather(
                    *[
                        client.send(full_message + "\n" + log_message)
                        for client in custom_server.websocket_clients
                    ]
                )

            # Nếu email là spam → chặn chuyển tiếp
            if not result.get("is_safe", False):
                info = "[INFO] Email identified as SPAM — suppressed forwarding."
                print(info)
                if custom_server.websocket_clients:
                    await asyncio.gather(
                        *[client.send(info) for client in custom_server.websocket_clients]
                    )
                return '250 OK (SPAM detected and suppressed)'

            # Nếu hợp lệ → forward đến mail server thật
            host, port = MAIN_MAIL_SERVER.split(':')
            with smtplib.SMTP(host, int(port)) as smtp:
                smtp.starttls()
                smtp.login(PROTECTED_EMAIL, RELAY_PASSWORD)
                smtp.sendmail(from_addr, to_addr, email_data)
                forward_message = f"Email forwarded to {MAIN_MAIL_SERVER}"
                print(forward_message)
                if custom_server.websocket_clients:
                    await asyncio.gather(
                        *[client.send(forward_message) for client in custom_server.websocket_clients]
                    )

            return '250 OK'

        except Exception as e:
            error_message = f"[ERROR] {e}"
            print(error_message)
            if custom_server.websocket_clients:
                await asyncio.gather(
                    *[client.send(error_message) for client in custom_server.websocket_clients]
                )
            return '550 Forwarding failed'


# ===============================
# WebSocket handler (giữ nguyên)
# ===============================
async def websocket_handler(websocket, path):
    server = ensure_server()
    server.websocket_clients.add(websocket)
    try:
        await websocket.wait_closed()
    finally:
        server.websocket_clients.remove(websocket)


async def start_websocket_server():
    ensure_server()
    server = await websockets.serve(websocket_handler, '0.0.0.0', 8765)
    await server.wait_closed()


def start_smtp_server():
    ensure_server()
    controller = Controller(custom_server, hostname='0.0.0.0', port=2525)
    controller.start()
    print("SMTP Proxy Server running on 0.0.0.0:2525...")
    return controller


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(start_websocket_server())
    controller = start_smtp_server()
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        controller.stop()
        loop.close()
