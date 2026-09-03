"""`.env` resolution and in-place key updates."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from claude_cloak import env


def _reload_with(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: str):
    env_file = tmp_path / ".env"
    env_file.write_text(content, encoding="utf-8")
    monkeypatch.setenv("CLAUDE_CLOAK_ENV", str(env_file))
    return importlib.reload(env), env_file


def test_override_wins(tmp_path, monkeypatch):
    mod, env_file = _reload_with(tmp_path, monkeypatch, "LOCAL_PORT=1234\n")
    assert Path(mod.ENV_PATH) == env_file.resolve()


def test_save_to_env_appends_then_replaces(tmp_path, monkeypatch):
    mod, env_file = _reload_with(tmp_path, monkeypatch, "LOCAL_PORT=1234\n")
    mod.save_to_env("SESSION_SECRET", "abc")
    assert "SESSION_SECRET=abc" in env_file.read_text()
    mod.save_to_env("SESSION_SECRET", "def")
    text = env_file.read_text()
    assert "SESSION_SECRET=def" in text
    assert text.count("SESSION_SECRET=") == 1


def test_save_to_env_does_not_write_into_a_commented_example(tmp_path, monkeypatch):
    """A commented sample line must not swallow the real value."""
    mod, env_file = _reload_with(tmp_path, monkeypatch, "# ADMIN_TOKEN=replace-me\n")
    mod.save_to_env("ADMIN_TOKEN", "real-secret")
    text = env_file.read_text()
    assert "# ADMIN_TOKEN=replace-me" in text
    assert "\nADMIN_TOKEN=real-secret\n" in text


def test_env_key():
    assert env.env_key("x-app") == "CAPTURED_X_APP"
    assert env.env_key("User-Agent") == "CAPTURED_USER_AGENT"


def test_typed_readers(monkeypatch):
    monkeypatch.setenv("CLOAK_T_INT", "7")
    monkeypatch.setenv("CLOAK_T_BAD", "nope")
    monkeypatch.setenv("CLOAK_T_BOOL", "TRUE")
    monkeypatch.setenv("CLOAK_T_LIST", " a , b ,, c ")
    assert env.env_int("CLOAK_T_INT", 1) == 7
    assert env.env_int("CLOAK_T_BAD", 1) == 1
    assert env.env_float("CLOAK_T_BAD", 2.5) == 2.5
    assert env.env_bool("CLOAK_T_BOOL", False) is True
    assert env.env_bool("CLOAK_T_MISSING", True) is True
    assert env.env_list("CLOAK_T_LIST") == ["a", "b", "c"]
