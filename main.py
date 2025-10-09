import asyncio
from aiosmtpd.controller import Controller
from core.smtp_handler import SpamFilterHandler
from config.settings import SMTP_HOST, SMTP_PORT
import socket

async def main():
    controller = Controller(
        SpamFilterHandler(),
        hostname=SMTP_HOST,
        port=SMTP_PORT
    )
    controller.start()
    print(f"SMTP Gateway running on {SMTP_HOST}:{SMTP_PORT}")
    try:
        await asyncio.Event().wait()  # Chờ sự kiện vô hạn
    except KeyboardInterrupt:
        controller.stop()
        print("SMTP Gateway stopped")

if __name__ == "__main__":
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((SMTP_HOST, SMTP_PORT))
        sock.close()
        asyncio.run(main())
    except OSError as e:
        print(f"Error: {e}. Check if port {SMTP_PORT} is in use or requires admin rights. Try a different port (e.g., 2525).")
    except Exception as e:
        print(f"Unexpected error: {e}")