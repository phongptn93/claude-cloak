"""GET /coach."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ..coach import _compute_coach_view

router = APIRouter()


@router.get("/coach")
async def coach():
    """Privacy-safe coaching insights derived from proxied traffic.

    Counts only — no prompt text, code or file paths are ever stored or
    returned. Powers the Coaching section of /dashboard.
    """
    return JSONResponse(_compute_coach_view())
