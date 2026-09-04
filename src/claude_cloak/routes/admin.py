"""Admin maintenance endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from .. import state
from ..access import current_user_period_key
from ..quota.persist import _save_quota_stats
from ..quota.users import _reset_user_bucket, _user_bucket_view
from ..terminal import BG_GREEN, BOLD, GREEN, RESET, log

router = APIRouter()


@router.post("/admin/quota/reset/{label}")
async def admin_reset_user(label: str):
    """Manually zero out one user's cap counters (auth via ADMIN_IPS middleware)."""
    b = state.quota_stats["by_user"].get(label)
    if b is None:
        raise HTTPException(status_code=404, detail="user not found")
    _reset_user_bucket(b, current_user_period_key())
    _save_quota_stats(force=True)
    log(f"  {BG_GREEN}{BOLD} RESET {RESET} {GREEN}per-user quota reset for '{label}'{RESET}")
    return _user_bucket_view(b)
