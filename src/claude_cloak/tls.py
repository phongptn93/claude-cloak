"""Certificate expiry, surfaced so renewal failures are noticed early.

Let's Encrypt certificates are short-lived and certbot renews them on a timer.
That works until it silently does not — a webroot moved, port 80 closed, the
deploy hook failing — and the first symptom is every client losing the proxy
at once. Reporting days-remaining in /health and on the dashboard turns that
into something visible days ahead of the outage.
"""

from __future__ import annotations

import datetime
import importlib
import ssl
from pathlib import Path

from . import settings

# Certbot renews at 1/3 of remaining lifetime (30 days for a 90-day cert), so
# anything under this means renewal has already missed at least one window.
WARN_DAYS = 21
CRITICAL_DAYS = 7


def _not_after(certfile: str) -> datetime.datetime | None:
    try:
        # There is no public stdlib call that reads notAfter from a file on
        # disk. This one is private but long-stable, and a diagnostic must
        # never be able to take the proxy down — any failure here just leaves
        # the field absent.
        decode = importlib.import_module("_ssl")._test_decode_cert  # ty: ignore[unresolved-attribute]
        decoded = decode(certfile)
        seconds = ssl.cert_time_to_seconds(decoded["notAfter"])
    except Exception:
        return None
    return datetime.datetime.fromtimestamp(seconds, tz=datetime.UTC)


def certificate_view() -> dict:
    if not settings.TLS_ENABLED:
        return {
            "enabled": False,
            "status": "disabled",
            "detail": "no TLS_CERTFILE/TLS_KEYFILE — traffic is plaintext",
        }

    certfile = settings.TLS_CERTFILE
    if not Path(certfile).is_file():
        return {"enabled": True, "status": "missing", "certfile": certfile}

    expires = _not_after(certfile)
    if expires is None:
        return {"enabled": True, "status": "unreadable", "certfile": certfile}

    days = (expires - datetime.datetime.now(tz=datetime.UTC)).total_seconds() / 86400
    if days <= 0:
        status = "expired"
    elif days < CRITICAL_DAYS:
        status = "critical"
    elif days < WARN_DAYS:
        status = "warning"
    else:
        status = "ok"

    return {
        "enabled": True,
        "status": status,
        "certfile": certfile,
        "expires_at": expires.isoformat(timespec="seconds"),
        "days_remaining": round(days, 1),
    }
