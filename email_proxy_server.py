import asyncio
import os
import smtplib
from email.parser import BytesParser
from email.policy import default
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class CustomSMTPServer:
    async def handle_EHLO(self, server, session, envelope, hostname):
        print(f"EHLO from: {hostname}")
        session.host_name = hostname
        return '250 OK'

    async def handle_HELO(self, server, session, envelope, hostname):
        print(f"HELO from: {hostname}")
        session.host_name = hostname
        return '250 OK'

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        print(f"MAIL FROM: {address}")
        envelope.mail_from = address
        return '250 OK'

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        print(f"RCPT TO: {address}")
        envelope.rcpt_tos.append(address)
        return '250 OK'

    async def handle_DATA(self, server, session, envelope):
        try:
            print("Received DATA command")
            # Parse the email data
            email_data = envelope.content
            parser = BytesParser(policy=default)
            message = parser.parsebytes(email_data)

            # Extract email details
            from_addr = envelope.mail_from
            to_addr = envelope.rcpt_tos
            subject = message.get('subject', 'No Subject')
            body = message.get_payload(decode=True).decode('utf-8', errors='ignore') if message.get_payload() else "No Body"

            # Log email details
            print(f"Received email from: {from_addr}")
            print(f"To: {to_addr}")
            print(f"Subject: {subject}")
            print(f"Body: {body[:200]}...")

            # Get environment variables
            protected_email = os.environ.get("PROTECTED_EMAIL")
            main_mail_server = os.environ.get("MAIN_MAIL_SERVER")
            app_password = os.environ.get("RELAY_PASSWORD")

            # Debug: Print environment variables
            print(f"PROTECTED_EMAIL: {protected_email}")
            print(f"MAIN_MAIL_SERVER: {main_mail_server}")
            print(f"RELAY_PASSWORD: {app_password}")

            if not all([protected_email, main_mail_server, app_password]):
                print("Error: Missing environment variables")
                return '550 Environment variables missing'

            # Hold email for 3 seconds
            print("Holding email for 3 seconds...")
            await asyncio.sleep(3)

            # Connect to the main mail server
            host, port = main_mail_server.split(':')
            with smtplib.SMTP(host, int(port)) as smtp:
                smtp.starttls()  # Enable TLS
                smtp.login(protected_email, app_password)
                smtp.sendmail(from_addr, to_addr, email_data)
                print(f"Email forwarded to {main_mail_server}")
                return '250 OK'

        except Exception as e:
            print(f"Error forwarding email: {str(e)}")
            return '550 Forwarding failed'

async def main():
    # Start the SMTP server on localhost:2525
    controller = Controller(
        CustomSMTPServer(),
        hostname='localhost',
        port=2525
    )
    controller.start()
    print("SMTP Proxy Server running on localhost...")
    try:
        while True:
            await asyncio.sleep(3600)  # Keep the server running
    except KeyboardInterrupt:
        controller.stop()
        print("SMTP Proxy Server stopped.")

if __name__ == "__main__":
    asyncio.run(main())