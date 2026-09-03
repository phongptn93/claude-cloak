"""Certificate expiry reporting."""

from __future__ import annotations

import subprocess

import pytest

from claude_cloak import settings
from claude_cloak.tls import certificate_view


def _issue(tmp_path, days: int):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", str(days), "-subj", "/CN=t"],
        check=True, capture_output=True,
    )
    return cert, key


@pytest.fixture
def cert_factory(tmp_path, monkeypatch):
    def make(days: int):
        cert, key = _issue(tmp_path, days)
        monkeypatch.setattr(settings, "TLS_CERTFILE", str(cert))
        monkeypatch.setattr(settings, "TLS_KEYFILE", str(key))
        monkeypatch.setattr(settings, "TLS_ENABLED", True)
        return cert
    return make


def test_disabled_when_no_certificate_is_configured(monkeypatch):
    monkeypatch.setattr(settings, "TLS_ENABLED", False)
    view = certificate_view()
    assert view["status"] == "disabled"
    assert view["enabled"] is False


@pytest.mark.parametrize(
    ("days", "status"),
    [(89, "ok"), (30, "ok"), (14, "warning"), (3, "critical")],
)
def test_status_tracks_remaining_lifetime(cert_factory, days, status):
    cert_factory(days)
    view = certificate_view()
    assert view["status"] == status
    assert view["days_remaining"] == pytest.approx(days, abs=1.1)


def test_a_missing_file_is_reported_rather_than_raising(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "TLS_ENABLED", True)
    monkeypatch.setattr(settings, "TLS_CERTFILE", str(tmp_path / "nope.pem"))
    assert certificate_view()["status"] == "missing"


def test_an_unparseable_file_never_raises(monkeypatch, tmp_path):
    junk = tmp_path / "junk.pem"
    junk.write_text("not a certificate")
    monkeypatch.setattr(settings, "TLS_ENABLED", True)
    monkeypatch.setattr(settings, "TLS_CERTFILE", str(junk))
    assert certificate_view()["status"] == "unreadable"


async def test_health_exposes_the_certificate_block():
    import httpx

    from claude_cloak.app import create_app

    transport = httpx.ASGITransport(app=create_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        body = (await c.get("/health")).json()
    assert "tls" in body and "status" in body["tls"]
