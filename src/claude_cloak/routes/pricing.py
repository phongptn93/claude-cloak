"""GET /pricing and the admin refresh for the remote price table."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from .. import state
from ..pricing import PRICING_REMOTE_URL, pricing_view, refresh_remote_pricing

router = APIRouter()


@router.get("/pricing")
async def pricing():
    """The rates in force today, where they came from, and unpriced models seen."""
    return {**pricing_view(), "unpriced_models": state.quota_stats["unpriced_models"]}


@router.post("/admin/pricing/refresh")
async def refresh_pricing():
    """Fetch PRICING_REMOTE_URL now instead of waiting for the next interval."""
    if not PRICING_REMOTE_URL:
        raise HTTPException(status_code=409, detail="PRICING_REMOTE_URL is not set")
    ok = await refresh_remote_pricing()
    view = pricing_view()
    if not ok:
        raise HTTPException(status_code=502, detail=view["last_error"] or "refresh failed")
    return view
