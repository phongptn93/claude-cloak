"""Plain-HTTP side listener for ACME renewal and HTTPS redirection.

Running this in-process means certbot can renew with ``--webroot`` while the
proxy keeps serving, instead of ``--standalone`` which needs port 80 free and
therefore a stop/start window on every renewal.

It is deliberately tiny and shares nothing with the main app: no middleware,
no identity handling, no upstream. The only thing it will ever read from disk
is a file directly under ``<ACME_WEBROOT>/.well-known/acme-challenge/``.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import settings
from .terminal import DIM, RESET, log

CHALLENGE_PREFIX = "/.well-known/acme-challenge/"
# ACME tokens are base64url; anything else is not a token we issued.
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def _challenge_body(path: str) -> bytes | None:
    if not settings.ACME_WEBROOT or not path.startswith(CHALLENGE_PREFIX):
        return None
    token = path[len(CHALLENGE_PREFIX) :]
    if not TOKEN_RE.match(token):
        return None
    root = Path(settings.ACME_WEBROOT).resolve()
    target = (root / ".well-known" / "acme-challenge" / token).resolve()
    # Belt and braces: the regex already forbids separators and dots.
    if not target.is_relative_to(root) or not target.is_file():
        return None
    return target.read_bytes()


def _https_location(path: str, host_header: str) -> str:
    host = settings.PUBLIC_HOSTNAME or host_header.split(":")[0]
    port = settings.PUBLIC_HTTPS_PORT or settings.LOCAL_PORT
    suffix = "" if port == 443 else f":{port}"
    return f"https://{host}{suffix}{path}"


async def acme_app(scope, receive, send) -> None:
    if scope["type"] != "http":
        return

    path = scope.get("path") or "/"
    headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope.get("headers", [])}

    body = _challenge_body(path)
    if body is not None:
        log(f"  {DIM}acme: served challenge {path}{RESET}")
        await _respond(send, 200, b"text/plain", body)
        return

    location = _https_location(path, headers.get("host", ""))
    await _respond(send, 301, b"text/plain", b"", extra=[(b"location", location.encode())])


async def _respond(send, status: int, content_type: bytes, body: bytes, extra=()) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", content_type),
                (b"content-length", str(len(body)).encode()),
                *extra,
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
