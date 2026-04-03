"""
Windows System Tray app cho AI Proxy.
Chạy proxy trong background với icon ở system tray.
Double-click start.bat hoặc chạy: python tray_app.py
"""

import os
import threading
import logging

import uvicorn
from PIL import Image, ImageDraw
from pystray import Icon, MenuItem, Menu
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

LOCAL_PORT = int(os.getenv("LOCAL_PORT", "9999"))


def create_icon_image():
    """Tạo icon đơn giản cho system tray."""
    img = Image.new("RGB", (64, 64), color=(40, 40, 40))
    draw = ImageDraw.Draw(img)
    draw.rectangle([4, 4, 60, 60], fill=(30, 130, 76))
    draw.text((12, 18), "AI", fill="white")
    return img


class ProxyTrayApp:
    def __init__(self):
        self.server_thread = None
        self.icon = None

    def start_server(self):
        config = uvicorn.Config("proxy:app", host="127.0.0.1", port=LOCAL_PORT, log_level="info")
        server = uvicorn.Server(config)
        server.run()

    def on_quit(self, icon, item):
        icon.stop()
        os._exit(0)

    def run(self):
        self.server_thread = threading.Thread(target=self.start_server, daemon=True)
        self.server_thread.start()
        logger.info("Proxy server started on port %d", LOCAL_PORT)

        menu = Menu(
            MenuItem(f"AI Proxy - Port {LOCAL_PORT}", lambda: None, enabled=False),
            MenuItem("Quit", self.on_quit),
        )

        self.icon = Icon("AI Proxy", create_icon_image(), "AI Proxy", menu)
        self.icon.run()


if __name__ == "__main__":
    app = ProxyTrayApp()
    app.run()
