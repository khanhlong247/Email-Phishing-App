import sys
import os
import asyncio
import json
import websockets
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel,
    QPushButton, QTextEdit, QHBoxLayout, QSizePolicy
)
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QIcon

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class WebSocketThread(QThread):
    new_data = pyqtSignal(str)

    def __init__(self, host, port, parent=None):
        super().__init__(parent)
        self.host = host
        self.port = port
        self.websocket = None
        self.running = False

    def run(self):
        self.running = True
        uri = f"ws://{self.host}:{self.port}"

        async def connect_and_listen():
            ws = None
            try:
                ws = await websockets.connect(uri)
                self.new_data.emit(f"Connected to {uri}")

                try:
                    await ws.send("connect")
                except Exception:
                    pass

                while self.running:
                    try:
                        data = await asyncio.wait_for(ws.recv(), timeout=30.0)
                    except asyncio.TimeoutError:
                        continue
                    if data is None:
                        break
                    self.new_data.emit(data)

            except Exception as e:
                self.new_data.emit(f"Error: {str(e)}")
            finally:
                try:
                    if ws is not None and not ws.closed:
                        await ws.close()
                except Exception:
                    pass
                self.new_data.emit("Disconnected")
                self.running = False

        try:
            asyncio.run(connect_and_listen())
        except Exception as e:
            self.new_data.emit(f"Error: {str(e)}")
        finally:
            self.running = False

    def stop(self):
        self.running = False

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SMTP WebSocket Client")
        self.setGeometry(100, 100, 1200, 700)
        
        self.setWindowIcon(QIcon(resource_path('logo.png')))

        # Giao diện chính
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        # Trạng thái server
        self.status_label = QLabel("Trạng thái server: Chưa kết nối")
        self.status_label.setStyleSheet("font-weight: bold; color: blue;")
        layout.addWidget(self.status_label)

        # Nút điều khiển
        btn_layout = QHBoxLayout()
        layout.addLayout(btn_layout)

        self.connect_btn = QPushButton("Kết nối tới AWS")
        self.connect_btn.clicked.connect(self.connect_server)
        btn_layout.addWidget(self.connect_btn)

        self.disconnect_btn = QPushButton("Ngắt kết nối")
        self.disconnect_btn.clicked.connect(self.disconnect_server)
        self.disconnect_btn.setEnabled(False)
        btn_layout.addWidget(self.disconnect_btn)

        # Hai khung log: email content và process log
        log_layout = QHBoxLayout()
        layout.addLayout(log_layout)

        # Khung hiển thị nội dung email
        self.email_log = QTextEdit()
        self.email_log.setReadOnly(True)
        self.email_log.setPlaceholderText("Nội dung email tới...")
        self.email_log.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        log_layout.addWidget(self.email_log)

        # Khung hiển thị quá trình xử lý
        self.process_log = QTextEdit()
        self.process_log.setReadOnly(True)
        self.process_log.setPlaceholderText("Quá trình lọc mail...")
        self.process_log.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        log_layout.addWidget(self.process_log)

        # WebSocket thread
        self.ws_thread = None

    def connect_server(self):
        if self.ws_thread and self.ws_thread.running:
            self.append_log("Đã kết nối.")
            return

        host = "3.27.171.246" 
        port = 8765

        self.ws_thread = WebSocketThread(host, port)
        self.ws_thread.new_data.connect(self.append_log)
        self.ws_thread.start()

        self.status_label.setText("Trạng thái server: Đang kết nối...")
        self.connect_btn.setEnabled(False)
        self.disconnect_btn.setEnabled(True)

    def disconnect_server(self):
        if self.ws_thread:
            self.ws_thread.stop()
            self.ws_thread.wait()
        self.status_label.setText("Trạng thái server: Ngắt kết nối")
        self.connect_btn.setEnabled(True)
        self.disconnect_btn.setEnabled(False)

    def append_log(self, text):
        text = text.strip()

        try:
            if text.startswith("{") and text.endswith("}"):
                obj = json.loads(text)
                pretty = json.dumps(obj, indent=2, ensure_ascii=False)
                self.process_log.append(pretty)
                if obj.get("status") == "connected":
                    self.status_label.setText("Trạng thái server: Kết nối")
                return
        except Exception:
            pass

        if "Connected to" in text:
            self.status_label.setText("Trạng thái server: Kết nối")
            self.process_log.append(text)
        elif text.startswith("Disconnected") or text.startswith("Error"):
            self.status_label.setText("Trạng thái server: Ngắt kết nối")
            self.process_log.append(text)
        else:
            self.process_log.append(text)

        if "Subject:" in text or "From:" in text or "To:" in text or "Body:" in text:
            self.email_log.append(text)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
