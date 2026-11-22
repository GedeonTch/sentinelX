"""Credential-specific user identity and home-directory resolution.

This module deliberately does not depend on ``core.database``: database and
non-credential storage retain their existing path-resolution behavior.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    import pwd
except ImportError:  # pragma: no cover - pwd is unavailable on Windows
    pwd = None  # type: ignore[assignment]


ROOT_CREDS_MESSAGE = (
    "Les commandes creds ne peuvent pas être exécutées avec les privilèges root. "
    "Relancez SentinelX sans sudo."
)


class CredentialPrivilegeError(PermissionError):
    """Credential operations are not allowed for the effective root user."""


class CredentialHomeError(RuntimeError):
    """The effective user's home cannot safely be used for credential data."""


def is_effective_root() -> bool:
    """Return whether POSIX effective UID is zero; Windows has no such policy."""
    geteuid = getattr(os, "geteuid", None)
    return callable(geteuid) and geteuid() == 0


def require_unprivileged_credentials() -> None:
    """Refuse credential operations under effective root, when POSIX supports it."""
    if is_effective_root():
        raise CredentialPrivilegeError(ROOT_CREDS_MESSAGE)


def real_user_home() -> Path:
    """Resolve the credentials home for the process's effective UID.

    On POSIX the account database is authoritative. Environment variables such
    as HOME, SUDO_USER and SUDO_UID are intentionally ignored. On platforms
    without ``geteuid`` (notably Windows), retain ``Path.home()`` behavior and
    do not add an Administrator policy.
    """
    geteuid = getattr(os, "geteuid", None)
    if not callable(geteuid):
        return Path.home()

    try:
        uid = geteuid()
    except (OSError, TypeError, ValueError) as exc:
        raise CredentialHomeError("Unable to determine the effective user for credential storage") from None
    if uid == 0:
        raise CredentialHomeError("Credential storage is unavailable to the effective root user")
    if pwd is None:
        raise CredentialHomeError("POSIX user information is unavailable for credential storage")

    try:
        account: Any = pwd.getpwuid(uid)
        raw_home = account.pw_dir
    except (KeyError, OSError, TypeError, ValueError, AttributeError):
        raise CredentialHomeError("Unable to resolve the effective user's home for credential storage") from None

    if not isinstance(raw_home, (str, os.PathLike)) or not raw_home:
        raise CredentialHomeError("The effective user's home is invalid for credential storage")
    try:
        home = Path(raw_home)
        if not home.is_absolute() or not home.is_dir():
            raise CredentialHomeError("The effective user's home is invalid for credential storage")
        if not os.access(home, os.R_OK | os.X_OK, effective_ids=True):
            raise CredentialHomeError("The effective user's home is inaccessible for credential storage")
    except (OSError, TypeError, ValueError, NotImplementedError):
        raise CredentialHomeError("The effective user's home is inaccessible for credential storage") from None
    return home
