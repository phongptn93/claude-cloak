"""HTML pages: /dashboard and /config."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from ..web import config_html, dashboard_html

router = APIRouter()


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse(content=dashboard_html())


@router.get("/config", response_class=HTMLResponse)
async def config_page():
    """Config console. Reachable only from ADMIN_IPS (enforced upstream)."""
    return HTMLResponse(content=config_html())
