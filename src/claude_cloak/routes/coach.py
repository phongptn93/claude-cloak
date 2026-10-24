"""GET /coach."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from ..coach import _compute_coach_view, _save_coach_stats
from ..coach_insights import set_rec_status

router = APIRouter()


@router.get("/coach")
async def coach():
    """Privacy-safe coaching insights derived from proxied traffic.

    Counts only — no prompt text, code or file paths are ever stored or
    returned. Powers the Coaching section of /dashboard.
    """
    return JSONResponse(_compute_coach_view())


@router.post("/admin/coach/recommendations")
async def mark_recommendation(request: Request):
    """Mark a recommendation done / dismissed / snoozed / open for every
    dashboard viewer (auth via ADMIN_IPS middleware).

    Body: ``{"id": "...", "status": "done|dismissed|snoozed|open", "days": 7}``.
    """
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    rec_id = str(payload.get("id") or "")
    if not rec_id or len(rec_id) > 300:
        raise HTTPException(status_code=400, detail="id is required")
    try:
        mark = set_rec_status(rec_id, str(payload.get("status") or ""), payload.get("days") or 7)
    except (TypeError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    _save_coach_stats(force=True)
    return mark
