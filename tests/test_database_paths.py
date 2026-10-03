"""Tests for user-home resolution used by session and Sentinel persistence."""

from pathlib import Path
from types import SimpleNamespace

import core.database as db


SESSION = "session-path-test"
NETWORK = "network-path-test"


def test_normal_user_uses_path_home(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.setattr(db.Path, "home", staticmethod(lambda: tmp_path))

    assert db.get_db_path(SESSION) == tmp_path / ".netlab" / "sessions" / f"{SESSION}.db"
    assert db.get_sentinel_db_path(NETWORK) == tmp_path / ".netlab" / "sentinel" / f"{NETWORK}.db"


def test_sudo_user_uses_real_users_home(monkeypatch, tmp_path: Path):
    real_home = tmp_path / "real-user"
    monkeypatch.setenv("SUDO_USER", "real-user")
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.setattr(db.Path, "home", staticmethod(lambda: Path("/root")))
    monkeypatch.setattr(
        db.pwd,
        "getpwnam",
        lambda username: SimpleNamespace(pw_dir=str(real_home)),
    )

    assert db.get_db_path(SESSION).parent == real_home / ".netlab" / "sessions"
    assert db.get_sentinel_db_path(NETWORK).parent == real_home / ".netlab" / "sentinel"


def test_sudo_uid_is_fallback_when_sudo_user_is_absent(monkeypatch, tmp_path: Path):
    real_home = tmp_path / "uid-user"
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setenv("SUDO_UID", "1001")
    monkeypatch.setattr(db.Path, "home", staticmethod(lambda: Path("/root")))
    monkeypatch.setattr(
        db.pwd,
        "getpwuid",
        lambda uid: SimpleNamespace(pw_dir=str(real_home)),
    )

    assert db.get_db_path(SESSION).parent == real_home / ".netlab" / "sessions"
    assert db.get_sentinel_db_path(NETWORK).parent == real_home / ".netlab" / "sentinel"


def test_unresolvable_sudo_identity_refuses_root_fallback(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SUDO_USER", "missing-user")
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.setenv("HOME", "/root")
    monkeypatch.setattr(db.Path, "home", staticmethod(lambda: Path("/root")))
    monkeypatch.setattr(db.pwd, "getpwnam", lambda username: (_ for _ in ()).throw(KeyError(username)))

    try:
        db.get_db_path(SESSION)
    except RuntimeError as exc:
        assert "refusing to use /root/.netlab" in str(exc)
    else:
        raise AssertionError("unresolvable sudo identity must not use /root")
