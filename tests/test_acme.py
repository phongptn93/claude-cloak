"""The port-80 side listener: ACME challenges and HTTPS redirection."""

from __future__ import annotations

import httpx
import pytest

from claude_cloak import settings
from claude_cloak.acme import acme_app


@pytest.fixture
def webroot(tmp_path, monkeypatch):
    challenge_dir = tmp_path / ".well-known" / "acme-challenge"
    challenge_dir.mkdir(parents=True)
    (challenge_dir / "tok3n-ABC_xyz").write_text("tok3n-ABC_xyz.thumbprint")
    monkeypatch.setattr(settings, "ACME_WEBROOT", str(tmp_path))
    monkeypatch.setattr(settings, "PUBLIC_HOSTNAME", "cloak.eastus.cloudapp.azure.com")
    monkeypatch.setattr(settings, "LOCAL_PORT", 443)
    monkeypatch.setattr(settings, "PUBLIC_HTTPS_PORT", 0)
    return tmp_path


async def _get(path, host="cloak.eastus.cloudapp.azure.com"):
    transport = httpx.ASGITransport(app=acme_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://side") as c:
        return await c.get(path, headers={"host": host}, follow_redirects=False)


async def test_serves_a_challenge_file(webroot):
    r = await _get("/.well-known/acme-challenge/tok3n-ABC_xyz")
    assert r.status_code == 200
    assert r.text == "tok3n-ABC_xyz.thumbprint"


async def test_unknown_token_redirects_rather_than_404s(webroot):
    r = await _get("/.well-known/acme-challenge/missing")
    assert r.status_code == 301


@pytest.mark.parametrize(
    "token",
    ["../../../etc/passwd", "..%2f..%2fetc%2fpasswd", "a/b", "."],
)
async def test_traversal_attempts_never_read_outside_the_webroot(webroot, token):
    r = await _get(f"/.well-known/acme-challenge/{token}")
    assert r.status_code == 301
    assert "root:" not in r.text


async def test_everything_else_redirects_to_https(webroot):
    r = await _get("/v1/messages")
    assert r.status_code == 301
    assert r.headers["location"] == "https://cloak.eastus.cloudapp.azure.com/v1/messages"


async def test_non_default_https_port_is_carried_into_the_redirect(webroot, monkeypatch):
    monkeypatch.setattr(settings, "LOCAL_PORT", 9443)
    r = await _get("/health")
    assert r.headers["location"] == "https://cloak.eastus.cloudapp.azure.com:9443/health"


async def test_host_header_is_used_when_no_public_hostname_is_set(webroot, monkeypatch):
    monkeypatch.setattr(settings, "PUBLIC_HOSTNAME", "")
    r = await _get("/health", host="vm.westus.cloudapp.azure.com:80")
    assert r.headers["location"] == "https://vm.westus.cloudapp.azure.com/health"


async def test_challenges_are_not_served_without_a_configured_webroot(monkeypatch):
    monkeypatch.setattr(settings, "ACME_WEBROOT", "")
    r = await _get("/.well-known/acme-challenge/tok3n-ABC_xyz")
    assert r.status_code == 301


async def test_published_port_overrides_the_bound_port_in_the_redirect(webroot, monkeypatch):
    """A container publishing 443:9999 binds 9999 but clients reach 443."""
    monkeypatch.setattr(settings, "LOCAL_PORT", 9999)
    monkeypatch.setattr(settings, "PUBLIC_HTTPS_PORT", 443)
    r = await _get("/health")
    assert r.headers["location"] == "https://cloak.eastus.cloudapp.azure.com/health"
