# ui.py (cho EC2, server-only với Controller không async)
import asyncio
from email.parser import BytesParser
from email.policy import default
from aiosmtpd.controller import Controller
import types

class ServerThread:
    def __init__(self):
        self.controller = None
        self.hostname = None
        self.port = None
        self.custom_server = None

    async def run(self, loop):
        from smtp.smtp_server import CustomSMTPServer
        self.custom_server = CustomSMTPServer()

        original_handle_DATA = self.custom_server.handle_DATA.__func__
        async def patched_handle_DATA(self_custom, server, session, envelope):
            bound_original = types.MethodType(original_handle_DATA, self_custom)
            result = await bound_original(server, session, envelope)
            email_message = BytesParser(policy=default).parsebytes(envelope.content)
            email_data = {
                "From": envelope.mail_from if envelope.mail_from else "Unknown",
                "To": envelope.rcpt_tos[0] if envelope.rcpt_tos else "Unknown",
                "Subject": email_message["Subject"] if email_message["Subject"] else "No Subject",
                "Body": ""
            }
            if email_message.is_multipart():
                for part in email_message.walk():
                    if part.get_content_type() == 'text/plain':
                        email_data["Body"] = part.get_payload(decode=True).decode(errors='ignore')
                        break
            else:
                email_data["Body"] = email_message.get_payload(decode=True).decode(errors='ignore') if email_message.get_payload() else ""
            return result

        self.custom_server.handle_DATA = types.MethodType(patched_handle_DATA, self.custom_server)

        self.controller = Controller(self.custom_server, hostname='0.0.0.0', port=2525)
        self.hostname = self.controller.hostname
        self.port = self.controller.port
        print(f"SMTP Proxy Server running on {self.hostname}:{self.port}...")
        self.controller.start()  # Gọi start() không async, chạy trong thread riêng
        await asyncio.sleep(0)  # Nhượng lại control cho event loop
