"""
core/dependencies.py — Environment checks for SentinelX NetLab V1

Verifies that the host is ready before any real scan:
- Python >= 3.10 (running interpreter)
- nmap on PATH
- enum4linux on PATH
- ~/.netlab/ exists (or can be created) and is writable

Returns one typed DependencyCheck per item. Never a single global bool
as the primary result. Never scans, never creates Finding objects.

Rules enforced here:
- ZERO import sqlite3
- ZERO import from cli
- ZERO print()
- ZERO scan / Finding generation
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

REQUIRED_PYTHON: Tuple[int, int] = (3, 10)
EXTERNAL_TOOLS: Tuple[str, ...] = ("nmap", "enum4linux")
NETLAB_HOME_NAME: str = ".netlab"
_WRITE_PROBE_NAME: str = ".doctor_write_probe"
_VERSION_TIMEOUT_SECONDS: int = 5
_VERSION_PATTERN = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


@dataclass
class DependencyCheck:
    """Result of checking one dependency (interpreter or external tool).

    Attributes:
        name: Tool or runtime name (e.g. "nmap", "python").
        present: True if the item is usable (binary on PATH, Python
            running, or ~/.netlab/ exists and is writable).
        version: Detected version string for tools, or a detail string
            for ~/.netlab/ (resolved path on success, error reason on
            failure). None when unknown.
    """

    name: str
    present: bool
    version: Optional[str] = None


def check_python() -> DependencyCheck:
    """Return a check for the running Python interpreter.

    The interpreter is always present when this function runs. The version
    is taken from sys.version_info (major.minor.micro).

    Returns:
        DependencyCheck: name="python", present=True, version populated.
    """
    info = sys.version_info
    version = f"{info.major}.{info.minor}.{info.micro}"
    return DependencyCheck(name="python", present=True, version=version)


def check_external_tool(name: str) -> DependencyCheck:
    """Look up an external tool on PATH and try to read its version.

    Missing tools return present=False. A found binary that fails version
    detection still returns present=True with version=None. Never raises
    for a missing or broken tool.

    Args:
        name: Executable name as it appears on PATH (e.g. "nmap").

    Returns:
        DependencyCheck: Presence and optional version for this tool.
    """
    executable_path = shutil.which(name)
    if executable_path is None:
        return DependencyCheck(name=name, present=False, version=None)
    version = _detect_version(executable_path)
    return DependencyCheck(name=name, present=True, version=version)


def netlab_home_path() -> Path:
    """Return the NetLab home directory (session DBs live under it).

    Returns:
        Path: ``Path.home() / ".netlab"`` — never a hardcoded absolute path.
    """
    return Path.home() / ".netlab"


def check_netlab_dir() -> DependencyCheck:
    """Ensure ~/.netlab/ exists (create it if needed) and is writable.

    Does not create ``sessions/`` and does not touch SQLite. A write probe
    file is created then deleted inside ~/.netlab/ only.

    Returns:
        DependencyCheck: name=".netlab". present=True when the directory
        is usable. version holds the resolved path or an error detail.
        Never raises.
    """
    path = netlab_home_path()
    try:
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
        if not path.is_dir():
            return DependencyCheck(
                name=NETLAB_HOME_NAME,
                present=False,
                version=f"{path} exists but is not a directory",
            )
        _probe_directory_writable(path)
    except OSError as exc:
        if not path.exists():
            detail = f"cannot create {path}: {exc}"
        else:
            detail = f"{path} is not writable: {exc}"
        return DependencyCheck(
            name=NETLAB_HOME_NAME,
            present=False,
            version=detail,
        )
    return DependencyCheck(
        name=NETLAB_HOME_NAME,
        present=True,
        version=str(path),
    )


def _probe_directory_writable(directory: Path) -> None:
    """Write and delete a probe file. Raises OSError if the write fails.

    Args:
        directory: Target directory (must already exist).
    """
    probe = directory / _WRITE_PROBE_NAME
    probe.write_text("ok", encoding="utf-8")
    try:
        probe.unlink()
    except OSError:
        return


def check_environment() -> List[DependencyCheck]:
    """Run all NetLab environment checks.

    Order: python, each name in EXTERNAL_TOOLS, then ~/.netlab/.

    Returns:
        List[DependencyCheck]: One entry per verified item.
    """
    checks: List[DependencyCheck] = [check_python()]
    for name in EXTERNAL_TOOLS:
        checks.append(check_external_tool(name))
    checks.append(check_netlab_dir())
    return checks


def environment_ready(checks: List[DependencyCheck]) -> bool:
    """Return True only if every required check is usable.

    Python is usable when its version is >= 3.10.
    External tools and ~/.netlab/ are usable when present is True.

    Args:
        checks: Output of check_environment() (or an equivalent list).

    Returns:
        bool: True when a scan may be attempted from an environment standpoint.
    """
    by_name = {check.name: check for check in checks}
    python_check = by_name.get("python")
    if python_check is None or not python_version_ok(python_check.version):
        return False
    for name in EXTERNAL_TOOLS:
        tool = by_name.get(name)
        if tool is None or not tool.present:
            return False
    netlab = by_name.get(NETLAB_HOME_NAME)
    if netlab is None or not netlab.present:
        return False
    return True


def check_status(check: DependencyCheck) -> str:
    """Return a machine-readable status for one check.

    Values:
        "ok" — usable for NetLab
        "missing" — external tool not on PATH
        "python_too_old" — interpreter below 3.10
        "failed" — ~/.netlab/ missing, not creatable, or not writable

    Args:
        check: One DependencyCheck.

    Returns:
        str: Status token for the CLI to display.
    """
    if check.name == "python":
        return "ok" if python_version_ok(check.version) else "python_too_old"
    if check.name == NETLAB_HOME_NAME:
        return "ok" if check.present else "failed"
    if check.present:
        return "ok"
    return "missing"


def python_version_ok(version: Optional[str]) -> bool:
    """Return True if version is Python 3.10 or newer.

    Args:
        version: Dotted version string (e.g. "3.12.3"), or None.

    Returns:
        bool: False when version is missing or below 3.10.
    """
    parsed = _parse_dotted_version(version)
    if parsed is None:
        return False
    major, minor = parsed[0], parsed[1]
    return (major, minor) >= REQUIRED_PYTHON


def _parse_dotted_version(version: Optional[str]) -> Optional[Tuple[int, int, int]]:
    """Parse a dotted version into (major, minor, micro).

    Args:
        version: Dotted version string, or None.

    Returns:
        Tuple of three ints, or None if parsing fails.
    """
    if version is None:
        return None
    parts = version.strip().split(".")
    if len(parts) < 2:
        return None
    try:
        major = int(parts[0])
        minor = int(parts[1])
        micro = int(parts[2]) if len(parts) > 2 else 0
    except ValueError:
        return None
    return (major, minor, micro)


def _detect_version(executable_path: str) -> Optional[str]:
    """Run ``<tool> --version`` and extract a dotted version if possible.

    Any OS error, timeout, or empty output yields None. Does not raise.

    Args:
        executable_path: Absolute path from shutil.which.

    Returns:
        Optional[str]: Dotted version, first output line, or None.
    """
    try:
        result = subprocess.run(
            [executable_path, "--version"],
            capture_output=True,
            text=True,
            timeout=_VERSION_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = f"{result.stdout or ''}{result.stderr or ''}".strip()
    if not output:
        return None
    first_line = output.splitlines()[0].strip()
    match = _VERSION_PATTERN.search(first_line)
    if match:
        return match.group(1)
    return first_line if first_line else None
