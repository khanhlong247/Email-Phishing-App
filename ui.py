import sys
import asyncio
from email.parser import BytesParser
from email.policy import default
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QVBoxLayout, QWidget, QPushButton, QHBoxLayout, QLabel
from PyQt5.QtCore import QThread, pyqtSignal, QObject
from PyQt5.QtGui import QIcon  # Thêm để hỗ trợ logo
import io
from aiosmtpd.controller import Controller
import types

class LogEmitter(QObject):
    new_log = pyqtSignal(str)
    new_email = pyqtSignal(dict)

class LogRedirector(io.StringIO):
    def __init__(self, emitter):
        super().__init__()
        self.emitter = emitter

    def write(self, s):
        super().write(s)
        if s.strip():
            self.emitter.new_log.emit(s)

class ServerThread(QThread):
    server_started = pyqtSignal(str, int)
    new_email_processed = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.controller = None
        self.hostname = None
        self.port = None
        self.loop = None
        self.custom_server = None

    def run(self):
        from smtp.smtp_server import CustomSMTPServer
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
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
            self.new_email_processed.emit(email_data)
            return result

        self.custom_server.handle_DATA = types.MethodType(patched_handle_DATA, self.custom_server)

        self.controller = Controller(self.custom_server, hostname='10.60.136.8', port=2525)
        self.controller.start()
        self.hostname = self.controller.hostname
        self.port = self.controller.port
        self.server_started.emit(self.hostname, self.port)
        try:
            self.loop.run_forever()
        finally:
            self.controller.stop()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Email Checker Desktop App")
        self.setGeometry(100, 100, 800, 600)

        # Thêm logo cho cửa sổ
        self.setWindowIcon(QIcon('logo.png'))

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        main_layout = QVBoxLayout(self.central_widget)

        self.status_label = QLabel("Trạng thái server: Chờ")
        main_layout.addWidget(self.status_label)

        content_layout = QHBoxLayout()

        left_column = QVBoxLayout()
        left_label = QLabel("Nội dung email tới")
        left_column.addWidget(left_label)
        self.email_content = QTextEdit()
        self.email_content.setReadOnly(True)
        left_column.addWidget(self.email_content)
        content_layout.addLayout(left_column)

        right_column = QVBoxLayout()
        right_label = QLabel("Quá trình lọc mail")
        right_column.addWidget(right_label)
        self.process_log = QTextEdit()
        self.process_log.setReadOnly(True)
        right_column.addWidget(self.process_log)
        content_layout.addLayout(right_column)

        main_layout.addLayout(content_layout)

        button_layout = QHBoxLayout()

        self.start_button = QPushButton("Start Server")
        self.start_button.clicked.connect(self.start_server)
        button_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Server")
        self.stop_button.clicked.connect(self.stop_server)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)

        main_layout.addLayout(button_layout)

        self.emitter = LogEmitter()
        self.emitter.new_log.connect(self.append_log)
        self.emitter.new_email.connect(self.update_email_content)

        self.redirector = LogRedirector(self.emitter)
        self.original_stdout = sys.stdout
        sys.stdout = self.redirector

        self.server_thread = None

        self.start_server()

    def append_log(self, text):
        if "SMTP Server is being initialized" in text:
            self.status_label.setText("Trạng thái server: Chờ")
            self.email_content.clear()
            self.process_log.clear()
            self.process_log.append(text)
        elif "SMTP Proxy Server running on" in text:
            self.status_label.setText("Trạng thái server: Bật")
            self.process_log.append(text)
        elif "SMTP Proxy Server stopped" in text:
            self.status_label.setText("Trạng thái server: Tắt")
            self.process_log.append(text)
        elif "=== EMAIL RESULT ===" in text:
            self.process_log.append(text)
        elif any(keyword in text for keyword in ["Label:", "https://", "OK", "Email forwarded"]):
            self.process_log.append(text)
        else:
            self.process_log.append(text)

    def update_email_content(self, email_data):
        content = f"From: {email_data['From']}\nTo: {email_data['To']}\nSubject: {email_data['Subject']}\nBody: {email_data['Body']}"
        self.email_content.setText(content)

    def start_server(self):
        if not self.server_thread or not self.server_thread.isRunning():
            self.server_thread = ServerThread(self)
            self.server_thread.server_started.connect(self.on_server_started)
            self.server_thread.new_email_processed.connect(self.emitter.new_email)
            self.server_thread.start()
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.append_log("SMTP Server is being initialized")

    def on_server_started(self, hostname, port):
        self.append_log(f"SMTP Proxy Server running on {hostname}:{port}...")

    def stop_server(self):
        if self.server_thread and self.server_thread.isRunning():
            if self.server_thread.loop:
                self.server_thread.loop.call_soon_threadsafe(self.server_thread.loop.stop)
            self.server_thread.quit()
            if self.server_thread.wait(5000):
                self.append_log("SMTP Proxy Server stopped.")
            else:
                self.append_log("Timeout while stopping SMTP Proxy Server.")
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)

    def closeEvent(self, event):
        sys.stdout = self.original_stdout
        if self.server_thread and self.server_thread.isRunning():
            self.stop_server()
        event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())