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


def test_env_bool_treats_an_empty_value_as_false_not_as_the_default(monkeypatch):
    """`TIMING_JITTER=` in a .env means off — matching the pre-refactor code."""
    monkeypatch.setenv("CLOAK_T_EMPTY", "")
    assert env.env_bool("CLOAK_T_EMPTY", True) is False
    monkeypatch.delenv("CLOAK_T_EMPTY")
    assert env.env_bool("CLOAK_T_EMPTY", True) is True


def test_env_int_survives_an_empty_value(monkeypatch):
    """The original `int(os.getenv(...))` raised at import; a default is safer."""
    monkeypatch.setenv("CLOAK_T_EMPTY_INT", "")
    assert env.env_int("CLOAK_T_EMPTY_INT", 42) == 42


def _resolve_in(monkeypatch, cwd: Path, repo_root: Path) -> Path:
    """Resolve with CLAUDE_CLOAK_ENV unset and both anchors redirected."""
    monkeypatch.delenv("CLAUDE_CLOAK_ENV", raising=False)
    monkeypatch.setattr(env.Path, "cwd", staticmethod(lambda: cwd))
    monkeypatch.setattr(env, "__file__", str(repo_root / "src" / "claude_cloak" / "env.py"))
    return env.resolve_env_path()


def test_root_env_wins_over_the_legacy_client_copy(tmp_path, monkeypatch):
    """A stale client/.env must never shadow the root file it was migrated to."""
    (tmp_path / "client").mkdir()
    (tmp_path / "client" / ".env").write_text("LOCAL_PORT=1\n", encoding="utf-8")
    (tmp_path / ".env").write_text("LOCAL_PORT=2\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    assert _resolve_in(monkeypatch, elsewhere, tmp_path) == (tmp_path / ".env").resolve()


def test_legacy_client_env_is_still_read_and_reported(tmp_path, monkeypatch, capsys):
    """Pre-move installs keep working, loudly."""
    (tmp_path / "client").mkdir()
    legacy = tmp_path / "client" / ".env"
    legacy.write_text("LOCAL_PORT=1\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    assert _resolve_in(monkeypatch, elsewhere, tmp_path) == legacy.resolve()
    assert "legacy" in capsys.readouterr().err
