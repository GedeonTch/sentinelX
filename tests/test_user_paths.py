"""Credential home resolution and root policy; no real credential data or network."""
from types import SimpleNamespace
import os

import pytest

import core.user_paths as user_paths

posix_only = pytest.mark.skipif(os.name == 'nt', reason='POSIX pwd/geteuid resolution')


@posix_only
def test_posix_home_comes_from_effective_uid_not_sudo_environment(monkeypatch, tmp_path):
    expected = tmp_path / "effective-user"
    expected.mkdir()
    monkeypatch.setattr(user_paths.os, "geteuid", lambda: 1204)
    monkeypatch.setenv("HOME", "/root")
    monkeypatch.setenv("SUDO_USER", "contradictory")
    monkeypatch.setenv("SUDO_UID", "0")
    monkeypatch.setattr(user_paths.pwd, "getpwuid", lambda uid: (
        SimpleNamespace(pw_dir=str(expected)) if uid == 1204 else pytest.fail("wrong UID")))

    assert user_paths.real_user_home() == expected


@posix_only
@pytest.mark.parametrize("error", [KeyError(1550), OSError("account lookup failed")])
def test_unknown_effective_uid_fails_without_environment_fallback(monkeypatch, error):
    monkeypatch.setattr(user_paths.os, "geteuid", lambda: 1550)
    monkeypatch.setenv("HOME", "/tmp/not-a-fallback")
    monkeypatch.setattr(user_paths.pwd, "getpwuid", lambda uid: (_ for _ in ()).throw(error))

    with pytest.raises(user_paths.CredentialHomeError):
        user_paths.real_user_home()


@posix_only
@pytest.mark.parametrize("home_kind", ["missing", "relative", "unreadable"])
def test_invalid_or_unusable_effective_home_fails(monkeypatch, tmp_path, home_kind):
    home = tmp_path / "missing" if home_kind == "missing" else tmp_path
    if home_kind == "relative":
        home = "relative-home"
    monkeypatch.setattr(user_paths.os, "geteuid", lambda: 1204)
    monkeypatch.setattr(user_paths.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir=home))
    if home_kind == "unreadable":
        monkeypatch.setattr(user_paths.os, "access", lambda *args, **kwargs: False)

    with pytest.raises(user_paths.CredentialHomeError):
        user_paths.real_user_home()


def test_windows_compatibility_uses_path_home_without_admin_policy(monkeypatch, tmp_path):
    if hasattr(user_paths.os, "geteuid"):
        monkeypatch.delattr(user_paths.os, "geteuid")
    monkeypatch.setattr(user_paths.Path, "home", staticmethod(lambda: tmp_path))
    assert user_paths.real_user_home() == tmp_path
    user_paths.require_unprivileged_credentials()


@posix_only
@pytest.mark.parametrize("sudo_user,sudo_uid", [("alice", "1000"), (None, None)])
def test_root_is_refused_with_or_without_sudo_identity(monkeypatch, sudo_user, sudo_uid):
    monkeypatch.setattr(user_paths.os, "geteuid", lambda: 0)
    if sudo_user is None:
        monkeypatch.delenv("SUDO_USER", raising=False)
        monkeypatch.delenv("SUDO_UID", raising=False)
    else:
        monkeypatch.setenv("SUDO_USER", sudo_user)
        monkeypatch.setenv("SUDO_UID", sudo_uid)
    with pytest.raises(user_paths.CredentialPrivilegeError, match="privilèges root"):
        user_paths.require_unprivileged_credentials()
