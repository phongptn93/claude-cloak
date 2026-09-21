"""Proxy access keys: issue, verify, and persist URL/header credentials.

`ALLOWED_IPS` is the right gate for an office with a fixed egress address and
the wrong one for a laptop on 4G whose address changes every hour. A proxy key
is the second door: a high-entropy secret the client carries in its base URL
(``/k/<key>``) or in the ``PROXY_KEY_HEADER``, bound to a user label so cost
attribution and per-user caps keep working exactly as they do for a whitelisted
IP.

Only the SHA-256 of a key is stored. The plaintext exists once, in the response
to the call that created it — losing it means issuing a new key, never reading
the old one back.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets
import time
from datetime import datetime, timedelta

from . import settings, state
from .access import is_valid_label
from .terminal import RESET, YELLOW, log

# The alphabet secrets.token_urlsafe emits. Anything else in the key position
# of a URL is rejected before it reaches the store, so a scan for /k/../.. or
# a query string smuggled into the segment never becomes a lookup.
KEY_SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
KEY_ID_RE = re.compile(r"^[a-f0-9]{6,32}$")

NOTE_MAX_CHARS = 120
MAX_TTL_DAYS = 3650


def _now() -> datetime:
    return datetime.now()


def _now_iso() -> str:
    return _now().isoformat(timespec="seconds")


def hash_secret(secret: str) -> str:
    """Digest stored in place of the key.

    A plain SHA-256 is enough here and a slow KDF would be theatre: the secret
    is 192 bits from the system CSPRNG, so there is no dictionary to run
    against the digest and nothing a salt would separate.
    """
    return hashlib.sha256(secret.encode()).hexdigest()


def generate_secret() -> str:
    return secrets.token_urlsafe(settings.PROXY_KEY_BYTES)


def _keys() -> dict:
    return state.proxy_keys["keys"]


def _reindex() -> None:
    """Rebuild the digest -> id map every lookup goes through."""
    state.proxy_keys["by_hash"] = {
        rec["hash"]: rec["id"] for rec in _keys().values() if rec.get("hash")
    }


def _parse_expiry(rec: dict) -> datetime | None:
    raw = rec.get("expires_at") or ""
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        # An unreadable expiry is treated as expired: a key whose lifetime we
        # cannot establish must not be the one that keeps working.
        return _now() - timedelta(seconds=1)


def is_expired(rec: dict) -> bool:
    expiry = _parse_expiry(rec)
    return expiry is not None and expiry <= _now()


def key_status(rec: dict) -> str:
    if not rec.get("enabled", True):
        return "disabled"
    if is_expired(rec):
        return "expired"
    return "active"


def public_view(rec: dict) -> dict:
    """Everything the console renders — never the digest, never the secret."""
    return {
        "id": rec.get("id", ""),
        "label": rec.get("label", ""),
        "note": rec.get("note", ""),
        "prefix": rec.get("prefix", ""),
        "enabled": bool(rec.get("enabled", True)),
        "status": key_status(rec),
        "created_at": rec.get("created_at", ""),
        "created_ip": rec.get("created_ip", ""),
        "expires_at": rec.get("expires_at", ""),
        "last_used_at": rec.get("last_used_at", ""),
        "last_used_ip": rec.get("last_used_ip", ""),
        "use_count": int(rec.get("use_count", 0) or 0),
    }


def list_keys() -> list[dict]:
    return sorted(
        (public_view(rec) for rec in _keys().values()),
        key=lambda k: (k["label"], k["created_at"]),
    )


def active_key_count() -> int:
    return sum(1 for rec in _keys().values() if key_status(rec) == "active")


def create_key(
    label: str,
    note: str = "",
    expires_in_days: int = 0,
    created_ip: str = "",
) -> tuple[str, dict]:
    """Mint a key for `label`. Returns (plaintext secret, record).

    The caller must show the secret to the operator immediately; this is the
    only moment it exists outside the client that will carry it.
    """
    label = (label or "").strip()
    if not is_valid_label(label):
        raise ValueError("invalid label — allowed: letters, digits, dot, dash, underscore")
    try:
        days = int(expires_in_days or 0)
    except (TypeError, ValueError):
        raise ValueError("expiry must be a whole number of days") from None
    if days < 0 or days > MAX_TTL_DAYS:
        raise ValueError(f"expiry must be between 0 and {MAX_TTL_DAYS} days")

    secret = generate_secret()
    record = {
        "id": secrets.token_hex(6),
        "label": label,
        "note": " ".join(str(note or "").split())[:NOTE_MAX_CHARS],
        "hash": hash_secret(secret),
        # Enough to tell two of a user's keys apart in the console, far too
        # little to guess the rest of the secret from.
        "prefix": secret[:6],
        "enabled": True,
        "created_at": _now_iso(),
        "created_ip": created_ip,
        "expires_at": (_now() + timedelta(days=days)).isoformat(timespec="seconds") if days else "",
        "last_used_at": "",
        "last_used_ip": "",
        "use_count": 0,
    }
    _keys()[record["id"]] = record
    _reindex()
    save_keys(force=True)
    return secret, record


def get_key(key_id: str) -> dict | None:
    if not key_id or not KEY_ID_RE.match(key_id):
        return None
    return _keys().get(key_id)


def update_key(
    key_id: str,
    *,
    enabled: bool | None = None,
    note: str | None = None,
    label: str | None = None,
    expires_in_days: int | None = None,
) -> dict | None:
    """Patch one key in place. Returns the record, or None when unknown."""
    rec = get_key(key_id)
    if rec is None:
        return None
    if enabled is not None:
        rec["enabled"] = bool(enabled)
    if note is not None:
        rec["note"] = " ".join(str(note).split())[:NOTE_MAX_CHARS]
    if label is not None:
        label = label.strip()
        if not is_valid_label(label):
            raise ValueError("invalid label — allowed: letters, digits, dot, dash, underscore")
        rec["label"] = label
    if expires_in_days is not None:
        try:
            days = int(expires_in_days)
        except (TypeError, ValueError):
            raise ValueError("expiry must be a whole number of days") from None
        if days < 0 or days > MAX_TTL_DAYS:
            raise ValueError(f"expiry must be between 0 and {MAX_TTL_DAYS} days")
        rec["expires_at"] = (
            (_now() + timedelta(days=days)).isoformat(timespec="seconds") if days else ""
        )
    save_keys(force=True)
    return rec


def delete_key(key_id: str) -> bool:
    rec = get_key(key_id)
    if rec is None:
        return False
    del _keys()[key_id]
    _reindex()
    save_keys(force=True)
    return True


def verify_secret(secret: str) -> tuple[dict | None, str]:
    """Resolve a presented key. Returns (record, reason); record is None unless
    reason == "ok".

    The lookup is a dict hit on the digest, so it leaks no timing signal about
    a key it does not hold.
    """
    if not secret or not KEY_SECRET_RE.match(secret):
        return None, "malformed"
    key_id = state.proxy_keys["by_hash"].get(hash_secret(secret))
    rec = _keys().get(key_id) if key_id else None
    if rec is None:
        return None, "unknown"
    status = key_status(rec)
    if status != "active":
        return None, status
    return rec, "ok"


def record_use(rec: dict, client_ip: str) -> None:
    """Note that a key was just accepted — the console's 'is this still in use?'"""
    rec["use_count"] = int(rec.get("use_count", 0) or 0) + 1
    rec["last_used_at"] = _now_iso()
    rec["last_used_ip"] = client_ip or ""
    save_keys()


def load_keys() -> bool:
    """Read the key file into state. Returns True when one was loaded.

    A missing file is the normal first-boot case. A corrupt one is reported and
    skipped rather than crashing the proxy — but it is NOT silently replaced:
    the next write rewrites it, so the operator sees the warning first.
    """
    _keys().clear()
    state.proxy_keys["by_hash"] = {}
    path = settings.PROXY_KEYS_PATH
    if not os.path.exists(path):
        return False
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        log(f"  {YELLOW}proxy keys could not be read from {path} ({exc}){RESET}")
        return False
    if not isinstance(data, dict):
        return False
    version = data.get("version")
    if not isinstance(version, int) or version > settings.PROXY_KEYS_SCHEMA_VERSION:
        log(f"  {YELLOW}proxy key file {path} has unsupported version {version!r}{RESET}")
        return False
    for rec in data.get("keys") or []:
        if not isinstance(rec, dict):
            continue
        key_id, digest = rec.get("id"), rec.get("hash")
        if not isinstance(key_id, str) or not isinstance(digest, str) or not digest:
            continue
        rec.setdefault("label", "")
        rec.setdefault("note", "")
        rec.setdefault("prefix", "")
        rec.setdefault("enabled", True)
        rec.setdefault("created_at", "")
        rec.setdefault("created_ip", "")
        rec.setdefault("expires_at", "")
        rec.setdefault("last_used_at", "")
        rec.setdefault("last_used_ip", "")
        rec.setdefault("use_count", 0)
        _keys()[key_id] = rec
    _reindex()
    return True


def save_keys(force: bool = False) -> None:
    """Atomically persist the key file, debounced like the quota counters."""
    now = time.monotonic()
    if (
        not force
        and now - state.runtime.last_keys_save_at < settings.PROXY_KEYS_PERSIST_INTERVAL_SECONDS
    ):
        return
    if not _keys() and not os.path.exists(settings.PROXY_KEYS_PATH):
        # Nothing to record and nothing to clear — don't litter an empty key
        # file next to every local install that never issues one.
        return
    payload = {
        "version": settings.PROXY_KEYS_SCHEMA_VERSION,
        "saved_at": _now_iso(),
        "keys": list(_keys().values()),
    }
    tmp_path = settings.PROXY_KEYS_PATH + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        # Digests, not secrets — but they still name every user who may reach
        # the proxy, so keep the file to its owner where the OS supports it.
        with contextlib.suppress(OSError):
            os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, settings.PROXY_KEYS_PATH)
        state.runtime.last_keys_save_at = now
    except OSError as exc:
        log(
            f"  {YELLOW}proxy keys could not be written to {settings.PROXY_KEYS_PATH} ({exc}){RESET}"
        )
