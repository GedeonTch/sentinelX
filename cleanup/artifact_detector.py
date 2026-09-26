"""
cleanup/artifact_detector.py — Detect NetLab artifacts for a session

Role: Identify files and directories created by NetLab during a specific
      audit session. Returns a list of Artifact objects that exist on disk.
      Never modifies anything.

Artifacts tracked in V1:
    SESSION_DB  — ~/.netlab/sessions/<session_id>.db
    REPORT      — ~/.netlab/reports/<session_id>.<format>
    TMP_DIR     — /tmp/netlab-<session_id>/

Explicitly NOT tracked:
    Sentinel DBs — ~/.netlab/sentinel/<network_id>.db
    These are keyed by network identity, not session. Their lifecycle is
    independent and they must not be deleted by a session cleanup.

Ownership is determined by naming convention, not OS metadata:
    - The path must be under an allowed root directory
    - The filename must match the session_id convention exactly
    - Any path that does not satisfy both conditions → SKIP

Rules enforced here:
    - ZERO import sqlite3
    - ZERO print() — display via core/logger.py if needed (this module is
      a library, display is handled by callers)
    - ZERO modification of files
    - ALWAYS validate session_id before constructing any path
    - NEVER use glob patterns that could match unintended files
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List

# Import path validation from database — reuses the existing regex check
# to prevent path traversal via session_id.
# No sqlite3 import — we only use the validator function.
from core.database import _validate_session_id


# ---------------------------------------------------------------------------
# Artifact types
# ---------------------------------------------------------------------------

class ArtifactType(str, Enum):
    """Category of a NetLab artifact."""
    SESSION_DB  = "session_db"
    REPORT      = "report"
    TMP_DIR     = "tmp_dir"


# ---------------------------------------------------------------------------
# Artifact dataclass
# ---------------------------------------------------------------------------

@dataclass
class Artifact:
    """A file or directory created by NetLab during a session.

    Attributes:
        path:          Absolute Path to the artifact.
        artifact_type: Category (SESSION_DB, REPORT, TMP_DIR).
        session_id:    The session that owns this artifact.
        exists:        True if the path exists on disk at detection time.
        size_bytes:    File size in bytes. 0 for directories or missing files.
    """
    path: Path
    artifact_type: ArtifactType
    session_id: str
    exists: bool
    size_bytes: int


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def detect_artifacts(session_id: str) -> List[Artifact]:
    """Return all NetLab artifacts for a session that currently exist on disk.

    Validates session_id via the existing path-safety check before constructing
    any filesystem paths. Only artifacts that exist at call time are returned.
    Sentinel DBs are intentionally excluded (separate lifecycle).

    Args:
        session_id: Audit session identifier.

    Returns:
        List[Artifact]: Existing artifacts owned by this session, sorted by
                        artifact_type (reports first, session_db last — mirrors
                        the safe deletion order in restore.py).

    Raises:
        ValueError: If session_id contains unsafe characters or is empty.
    """
    _validate_session_id(session_id)

    candidates: List[Artifact] = []
    candidates.extend(_detect_reports(session_id))
    candidates.extend(_detect_tmp_dir(session_id))
    candidates.extend(_detect_session_db(session_id))

    # Return only artifacts that exist right now
    return [a for a in candidates if a.exists]


# ---------------------------------------------------------------------------
# Individual detectors
# ---------------------------------------------------------------------------

def _detect_session_db(session_id: str) -> List[Artifact]:
    """Detect the session SQLite database.

    Path: ~/.netlab/sessions/<session_id>.db
    Ownership rule: filename == f"{session_id}.db" — exact match only.

    Args:
        session_id: Validated session identifier.

    Returns:
        List[Artifact]: Single-element list (the DB may or may not exist).
    """
    path = Path.home() / ".netlab" / "sessions" / f"{session_id}.db"
    return [_make_artifact(path, ArtifactType.SESSION_DB, session_id)]


def _detect_reports(session_id: str) -> List[Artifact]:
    """Detect report files generated for this session.

    Path pattern: ~/.netlab/reports/<session_id>.<any_extension>
    Ownership rule: filename must start with f"{session_id}." — exact prefix
    followed by a dot. This prevents "session-abc" from matching
    "session-abcdef.html".

    Args:
        session_id: Validated session identifier.

    Returns:
        List[Artifact]: Zero or more report artifacts.
    """
    reports_dir = Path.home() / ".netlab" / "reports"
    artifacts: List[Artifact] = []

    if not reports_dir.exists() or not reports_dir.is_dir():
        return artifacts

    prefix = f"{session_id}."
    for entry in reports_dir.iterdir():
        # Strict: must be a regular file, name must start with "<session_id>."
        if entry.is_file() and entry.name.startswith(prefix):
            artifacts.append(_make_artifact(entry, ArtifactType.REPORT, session_id))

    return artifacts


def _detect_tmp_dir(session_id: str) -> List[Artifact]:
    """Detect the temporary working directory for this session.

    Path: /tmp/netlab-<session_id>/
    Ownership rule: directory name == f"netlab-{session_id}" — exact match.
    In V1 this directory is not created automatically, but we check for it
    in case a future module creates it.

    Args:
        session_id: Validated session identifier.

    Returns:
        List[Artifact]: Single-element list (the dir may or may not exist).
    """
    path = Path("/tmp") / f"netlab-{session_id}"
    artifact = Artifact(
        path=path,
        artifact_type=ArtifactType.TMP_DIR,
        session_id=session_id,
        exists=path.exists() and path.is_dir(),
        size_bytes=0,  # Directories don't have a meaningful single size
    )
    return [artifact]


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_artifact(path: Path, artifact_type: ArtifactType, session_id: str) -> Artifact:
    """Build an Artifact from a path, detecting existence and size.

    Args:
        path:          Path to check.
        artifact_type: Category of this artifact.
        session_id:    Owning session.

    Returns:
        Artifact: Populated with current filesystem state.
    """
    exists = path.exists() and path.is_file()
    size_bytes = 0
    if exists:
        try:
            size_bytes = path.stat().st_size
        except OSError:
            size_bytes = 0
    return Artifact(
        path=path,
        artifact_type=artifact_type,
        session_id=session_id,
        exists=exists,
        size_bytes=size_bytes,
    )
