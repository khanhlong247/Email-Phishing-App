# app.py (cho EC2, server-only với xử lý signal và debug)
import asyncio
import signal
import websockets
from smtp.smtp_server import CustomSMTPServer, start_smtp_server

smtp_controller = None  # Global để cleanup
smtp_server_instance = None  # Instance duy nhất của CustomSMTPServer

async def websocket_handler(websocket, path=None):
    global smtp_server_instance
    try:
        print(f"WebSocket handler started with path: {path}")
        if smtp_server_instance is not None:
            smtp_server_instance.websocket_clients.add(websocket)
            print("WebSocket client added")
        else:
            print("Error: smtp_server_instance is not initialized")
            await websocket.close()
            return

        while True:
            message = await websocket.recv()
            print(f"Received: {message}")
            await websocket.send(f"Echo: {message}")
    except websockets.ConnectionClosed:
        print("WebSocket connection closed")
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        if smtp_server_instance is not None and websocket in smtp_server_instance.websocket_clients:
            smtp_server_instance.websocket_clients.remove(websocket)
            print("WebSocket client removed")

async def start_websocket_server():
    print("Starting WebSocket server on 0.0.0.0:8765...")
    server = await websockets.serve(websocket_handler, '0.0.0.0', 8765)
    print("WebSocket server started successfully")
    await server.wait_closed()

async def main():
    global smtp_controller, smtp_server_instance
    print("Starting SMTP server...")
    smtp_server_instance = CustomSMTPServer()  # ✅ Khởi tạo instance duy nhất
    smtp_controller = start_smtp_server()
    print("SMTP server started successfully")

    await start_websocket_server()

def signal_handler():
    global smtp_controller
    print("Received SIGTERM, stopping...")
    if smtp_controller is not None:
        smtp_controller.stop()
    asyncio.get_event_loop().stop()

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    signal.signal(signal.SIGTERM, lambda s, f: signal_handler())
    signal.signal(signal.SIGINT, lambda s, f: signal_handler())
    
    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        signal_handler()
    finally:
        loop.close()
