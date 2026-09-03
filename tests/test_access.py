"""IP whitelist, user labels, caps, and URL-prefix parsing."""

from __future__ import annotations

import pytest

from claude_cloak import access, settings


@pytest.mark.parametrize(
    ("raw", "ip", "expected"),
    [
        ("203.0.113.5", "203.0.113.5", True),
        ("203.0.113.5", "203.0.113.6", False),
        ("198.51.100.0/24", "198.51.100.77", True),
        ("198.51.100.0/24", "198.51.101.1", False),
        ("2001:db8::/32", "2001:db8::1", True),
        ("2001:db8::/32", "2001:dba::1", False),
    ],
)
def test_is_ip_allowed(monkeypatch, raw, ip, expected):
    monkeypatch.setattr(settings, "ALLOWED_NETWORKS", settings.parse_allowed_networks(raw))
    assert access.is_ip_allowed(ip) is expected


def test_parse_allowed_networks_skips_garbage():
    assert settings.parse_allowed_networks("nonsense, 203.0.113.5 ,") != []
    assert len(settings.parse_allowed_networks("nonsense,,")) == 0


def test_label_for_ip_uses_map_then_falls_back():
    assert access.label_for_ip("203.0.113.5") == "phong"
    assert access.label_for_ip("10.0.0.1") == "10.0.0.1"
    assert access.label_for_ip("") == "unknown"


def test_cap_for_label_prefers_explicit_override(monkeypatch):
    monkeypatch.setattr(settings, "USER_QUOTA_DEFAULT_USD", 20.0)
    assert access.cap_for_label("phong") == 50.0
    assert access.cap_for_label("nobody") == 20.0


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/u/phong/v1/messages", ("phong", "/v1/messages")),
        ("/u/phong", ("phong", "/")),
        ("/u/phong/", ("phong", "/")),
        ("/v1/messages", (None, "/v1/messages")),
        # Pre-existing behaviour: dots are inside USER_LABEL_PATTERN, so ".."
        # parses as a label. Harmless for the filesystem (the label only names
        # a quota bucket and the remainder is sent as an upstream URL path),
        # but it does let a caller create a ".." bucket.
        ("/u/../../etc/passwd", ("..", "/../etc/passwd")),
        ("/u/bad label/v1", (None, "/u/bad label/v1")),
    ],
)
def test_parse_user_prefix(path, expected):
    assert access.parse_user_prefix(path) == expected


def test_period_key_shapes(monkeypatch):
    monkeypatch.setattr(settings, "USER_QUOTA_PERIOD", "monthly")
    assert len(access.current_user_period_key()) == 7  # YYYY-MM
    monkeypatch.setattr(settings, "USER_QUOTA_PERIOD", "daily")
    assert len(access.current_user_period_key()) == 10  # YYYY-MM-DD
    assert access.seconds_until_user_period_reset() > 0
