"""Windows system-tray launcher for the proxy.

Requires the optional tray extra: ``uv sync --extra tray``.
"""

from __future__ import annotations

import logging
import os
import threading

import uvicorn
from PIL import Image, ImageDraw  # ty: ignore[unresolved-import]
from pystray import Icon, Menu, MenuItem  # ty: ignore[unresolved-import]

from . import settings
from .env import env_str

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

TRAY_TITLE = env_str("TRAY_TITLE", "Claude Cloak") or "Claude Cloak"


def create_icon_image() -> Image.Image:
    img = Image.new("RGB", (64, 64), color=(40, 40, 40))
    draw = ImageDraw.Draw(img)
    draw.rectangle([4, 4, 60, 60], fill=(30, 130, 76))
    draw.text((12, 18), "AI", fill="white")
    return img


class ProxyTrayApp:
    def __init__(self) -> None:
        self.server_thread: threading.Thread | None = None
        self.icon: Icon | None = None

    def start_server(self) -> None:
        config = uvicorn.Config(
            "claude_cloak.app:app",
            host=settings.LOCAL_HOST,
            port=settings.LOCAL_PORT,
            log_level="info",
        )
        uvicorn.Server(config).run()

    def on_quit(self, icon, item) -> None:
        icon.stop()
        os._exit(0)

    def run(self) -> None:
        self.server_thread = threading.Thread(target=self.start_server, daemon=True)
        self.server_thread.start()
        logger.info("Proxy server started on port %d", settings.LOCAL_PORT)

        menu = Menu(
            MenuItem(f"{TRAY_TITLE} - Port {settings.LOCAL_PORT}", lambda: None, enabled=False),
            MenuItem("Quit", self.on_quit),
        )
        self.icon = Icon(TRAY_TITLE, create_icon_image(), TRAY_TITLE, menu)
        self.icon.run()


def main() -> None:
    ProxyTrayApp().run()


if __name__ == "__main__":
    main()
