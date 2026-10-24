"""Whose credential reaches Anthropic: the client's own, or one held here.

``UPSTREAM_AUTH_MODE=client`` (default) forwards each client's Authorization
or x-api-key untouched. ``server`` drops it and sends a credential from
``UPSTREAM_CREDENTIALS`` instead. A proxy key may override both: its
``auth_mode`` (inherit / client / server) and the ``credential`` it uses.

Secrets never leave this module in a response or a log line — only the
credential's name, its kind and a four-character tail to tell two apart.
"""

from __future__ import annotations

from . import settings

AUTH_MODES = ("client", "server")
KEY_AUTH_MODES = ("inherit", *AUTH_MODES)
OAUTH_PREFIX = "sk-ant-oat"
# Anthropic only accepts a subscription OAuth token with this beta enabled.
OAUTH_BETA = "oauth-2025-04-20"
_AUTH_HEADERS = ("authorization", "x-api-key")


class UpstreamAuthError(Exception):
    """Server auth applies but no usable credential is configured."""


def credential_kind(secret: str) -> str:
    return "oauth" if secret.startswith(OAUTH_PREFIX) else "api_key"


def credentials_view() -> list[dict]:
    default = default_credential()
    return [
        {
            "name": name,
            "kind": credential_kind(secret),
            "tail": secret[-4:],
            "default": name == default,
        }
        for name, secret in settings.UPSTREAM_CREDENTIALS.items()
    ]


def default_credential() -> str | None:
    creds = settings.UPSTREAM_CREDENTIALS
    if settings.UPSTREAM_CREDENTIAL_DEFAULT in creds:
        return settings.UPSTREAM_CREDENTIAL_DEFAULT
    return next(iter(creds), None)


def resolve(key_record: dict | None) -> tuple[str, str | None]:
    """(mode, credential name) for a request; the name is None in client mode."""
    rec = key_record or {}
    mode = rec.get("auth_mode") or "inherit"
    if mode not in AUTH_MODES:
        mode = settings.UPSTREAM_AUTH_MODE
    if mode == "client":
        return "client", None
    name = rec.get("credential") or default_credential()
    if not name:
        raise UpstreamAuthError(
            "server auth is on but UPSTREAM_CREDENTIALS is empty — add a credential "
            "or set UPSTREAM_AUTH_MODE=client"
        )
    if name not in settings.UPSTREAM_CREDENTIALS:
        raise UpstreamAuthError(f"credential {name!r} is not in UPSTREAM_CREDENTIALS")
    return "server", name


def _set_beta(headers: dict, add: bool) -> None:
    key = next((k for k in headers if k.lower() == "anthropic-beta"), None)
    betas = [b.strip() for b in (headers.pop(key, "") if key else "").split(",") if b.strip()]
    betas = [b for b in betas if b != OAUTH_BETA]
    if add:
        betas.append(OAUTH_BETA)
    if betas:
        headers[key or "anthropic-beta"] = ",".join(betas)


def apply(headers: dict, key_record: dict | None) -> str | None:
    """Rewrite the upstream auth headers in place for this request.

    Returns the server credential's name when one was injected, else None.
    Raises UpstreamAuthError when server auth applies and cannot be honoured;
    the caller answers the client rather than falling back to a credential
    that would bill someone else.
    """
    mode, name = resolve(key_record)
    if mode == "client":
        return None
    for k in [k for k in headers if k.lower() in _AUTH_HEADERS]:
        del headers[k]
    secret = settings.UPSTREAM_CREDENTIALS[name]
    if credential_kind(secret) == "oauth":
        headers["authorization"] = f"Bearer {secret}"
        _set_beta(headers, add=True)
    else:
        headers["x-api-key"] = secret
        # A client logged in with OAuth sends the OAuth beta; an API key
        # request carrying it is rejected.
        _set_beta(headers, add=False)
    return name
