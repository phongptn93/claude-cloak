"""Config console: coercion, view shape, and live application (INV-1)."""

from __future__ import annotations

import pytest

from claude_cloak import config_console, settings


def test_coerce_by_type():
    coerce = config_console._config_coerce
    assert coerce({"type": "bool"}, "true") is True
    assert coerce({"type": "bool"}, False) is False
    assert coerce({"type": "int", "min": 0, "max": 10}, "7") == 7
    assert coerce({"type": "float"}, "1.5") == 1.5
    assert coerce({"type": "str"}, " x ") == "x"


def test_coerce_rejects_out_of_range():
    with pytest.raises(ValueError):
        config_console._config_coerce({"type": "int", "min": 1, "max": 5}, "99")
    with pytest.raises(ValueError):
        config_console._config_coerce({"type": "int"}, "not-a-number")


def test_every_spec_declares_a_known_scope():
    for spec in config_console.CONFIG_SPECS:
        assert spec["scope"] in ("live", "restart", "locked"), spec["key"]


def test_live_specs_point_at_a_real_settings_attribute():
    """INV-1: a live knob must resolve on the settings module, or /config/apply
    would write into a dead name instead of the running configuration."""
    for spec in config_console.CONFIG_SPECS:
        var = spec.get("var")
        if var:
            assert hasattr(settings, var), f"{spec['key']} -> settings.{var} missing"


def test_view_is_read_only_without_a_token(monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_TOKEN", "")
    view = config_console._config_view(authenticated=False)
    assert view["auth_configured"] is False
    assert view["editable"] is False
    assert view["sections"]


def test_secrets_are_never_rendered(monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_TOKEN", "super-secret-value")
    view = config_console._config_view(authenticated=True)
    rendered = repr(view)
    assert "super-secret-value" not in rendered


def test_apply_patches_the_live_setting_and_persists(monkeypatch, tmp_path):
    written = {}
    monkeypatch.setattr(config_console, "save_to_env", lambda k, v: written.__setitem__(k, v))
    monkeypatch.setattr(settings, "TIMING_JITTER_MAX_MS", 150)

    result = config_console._config_apply({"TIMING_JITTER_MAX_MS": 175})

    assert result["applied"]["TIMING_JITTER_MAX_MS"] == "175"
    assert settings.TIMING_JITTER_MAX_MS == 175, "live edit must hit the settings module"
    assert written["TIMING_JITTER_MAX_MS"] == "175"


def test_apply_refuses_locked_keys(monkeypatch):
    monkeypatch.setattr(config_console, "save_to_env", lambda k, v: None)
    result = config_console._config_apply({"DEPLOY_MODE": "server"})
    assert not result["applied"]
    assert "locked" in result["rejected"]["DEPLOY_MODE"]
