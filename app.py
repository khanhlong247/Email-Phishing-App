import asyncio
from smtp.smtp_server import start_smtp_server

async def main():
    controller = start_smtp_server()
    try:
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        controller.stop()
        print("SMTP Proxy Server stopped.")

if __name__ == "__main__":
    asyncio.run(main())
