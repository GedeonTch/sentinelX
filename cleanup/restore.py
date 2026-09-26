"""
cleanup/restore.py — Destructive lab cleanup for a single NetLab session

Role: Take artifacts detected for one session_id, confirm with the exact
      word "yes", then delete them. This is NOT an undelete or backup restore.
      There is no recovery mechanism.

Flow: detect → validate ownership → preview → confirm ("yes") → delete → verify

Rules enforced here:
    - ZERO import sqlite3
    - ZERO print() — display via core.logger.display
    - NEVER delete outside the three artifact families for this session
    - NEVER touch ~/.netlab/sentinel/
    - NEVER delete without verifying session_id ownership
    - Confirmation is exact "yes" after strip() — not y/Y/YES
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Tuple

from rich import box
from rich.table import Table

from cleanup.artifact_detector import Artifact, ArtifactType, detect_artifacts
from core.database import _validate_session_id
from core.logger import display


# ---------------------------------------------------------------------------
# Public status — CLI maps PARTIAL to exit code 1
# ---------------------------------------------------------------------------

class RestoreStatus(str, Enum):
    """Outcome of restore_session() after display has already happened."""

    NOTHING_TO_CLEAN = "nothing_to_clean"
    NO_SAFE_ARTIFACTS = "no_safe_artifacts"
    CANCELLED = "cancelled"
    SUCCESS = "success"
    PARTIAL = "partial"


@dataclass
class DeletionResult:
    """Outcome of attempting to delete one artifact."""

    artifact: Artifact
    success: bool
    error: str = ""


_DELETE_ORDER = {
    ArtifactType.REPORT: 0,
    ArtifactType.TMP_DIR: 1,
    ArtifactType.SESSION_DB: 2,
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def restore_session(session_id: str) -> RestoreStatus:
    """Interactive destructive cleanup of NetLab artifacts for one session.

    Args:
        session_id: Audit session to clean. Must pass _validate_session_id.

    Returns:
        RestoreStatus: NOTHING_TO_CLEAN / NO_SAFE_ARTIFACTS / CANCELLED /
        SUCCESS / PARTIAL. PARTIAL means at least one deletion failed after
        confirmation.

    Raises:
        ValueError: If session_id is empty or contains unsafe characters.
    """
    _validate_session_id(session_id)

    artifacts = detect_artifacts(session_id)
    if not artifacts:
        display("[green]No artifacts found for this session.[/green]")
        return RestoreStatus.NOTHING_TO_CLEAN

    safe, skipped = _validate_artifacts(artifacts, session_id)
    for artifact in skipped:
        display(f"[yellow]⚠ SKIP — out of scope: {artifact.path}[/yellow]")

    if not safe:
        display("[yellow]No artifacts passed ownership validation.[/yellow]")
        return RestoreStatus.NO_SAFE_ARTIFACTS

    safe = _sort_for_deletion(safe)
    _render_preview(safe)

    if not _confirm_deletion():
        display("[yellow]Cleanup cancelled.[/yellow]")
        return RestoreStatus.CANCELLED

    results = _delete_artifacts(safe)
    _render_results(results)

    if any(not item.success for item in results):
        display("[red]Cleanup finished with failures (partial).[/red]")
        return RestoreStatus.PARTIAL

    display("[green]Cleanup completed.[/green]")
    return RestoreStatus.SUCCESS


# ---------------------------------------------------------------------------
# Confirmation
# ---------------------------------------------------------------------------

def _confirm_deletion() -> bool:
    """Return True only if the user types exactly 'yes' (after strip)."""
    raw = input("Type 'yes' to confirm deletion: ").strip()
    return raw == "yes"


# ---------------------------------------------------------------------------
# Ownership / path safety
# ---------------------------------------------------------------------------

def _validate_artifacts(
    artifacts: List[Artifact],
    session_id: str,
) -> Tuple[List[Artifact], List[Artifact]]:
    """Split artifacts into owned-and-safe vs skipped.

    Args:
        artifacts: Detected artifacts (must not be trusted blindly).
        session_id: Requested session (already validated).

    Returns:
        Tuple of (safe_to_delete, skipped).
    """
    safe: List[Artifact] = []
    skipped: List[Artifact] = []
    for artifact in artifacts:
        if _is_owned(artifact, session_id):
            safe.append(artifact)
        else:
            skipped.append(artifact)
    return safe, skipped


def _is_owned(artifact: Artifact, session_id: str) -> bool:
    """Return True if this artifact belongs to session_id and stays in-family.

    Allowed families only:
        ~/.netlab/sessions/<session_id>.db
        ~/.netlab/reports/<session_id>.<ext>
        /tmp/netlab-<session_id>/

    Symlinks whose resolved target leaves the allowed root are rejected.
    TMP_DIR that is itself a symlink is rejected (never rmtree through a link).
    """
    if artifact.session_id != session_id:
        return False

    try:
        if artifact.artifact_type == ArtifactType.SESSION_DB:
            return _is_owned_session_db(artifact.path, session_id)
        if artifact.artifact_type == ArtifactType.REPORT:
            return _is_owned_report(artifact.path, session_id)
        if artifact.artifact_type == ArtifactType.TMP_DIR:
            return _is_owned_tmp_dir(artifact.path, session_id)
    except OSError:
        return False
    return False


def _is_owned_session_db(path: Path, session_id: str) -> bool:
    """SESSION_DB must be exactly ~/.netlab/sessions/<session_id>.db."""
    sessions_root = (Path.home() / ".netlab" / "sessions").resolve()
    expected_name = f"{session_id}.db"
    if path.name != expected_name:
        return False
    parent = path.parent.resolve()
    if parent != sessions_root:
        return False
    return _resolved_stays_under(path, sessions_root)


def _is_owned_report(path: Path, session_id: str) -> bool:
    """REPORT must be a file named <session_id>.* directly in ~/.netlab/reports/."""
    reports_root = (Path.home() / ".netlab" / "reports").resolve()
    prefix = f"{session_id}."
    if not path.name.startswith(prefix):
        return False
    parent = path.parent.resolve()
    if parent != reports_root:
        return False
    return _resolved_stays_under(path, reports_root)


def _is_owned_tmp_dir(path: Path, session_id: str) -> bool:
    """TMP_DIR must be exactly /tmp/netlab-<session_id> and not a symlink."""
    tmp_parent = Path("/tmp").resolve()
    expected_name = f"netlab-{session_id}"
    if path.name != expected_name:
        return False
    parent = path.parent.resolve()
    if parent != tmp_parent:
        return False
    if path.exists() and path.is_symlink():
        return False
    return _resolved_stays_under(path, tmp_parent / expected_name)


def _resolved_stays_under(path: Path, root: Path) -> bool:
    """True if path.resolve() is root or a descendant of root.

    Used to reject symlinks (and .. components) that escape the allowed root.
    """
    try:
        resolved = path.resolve()
        root_resolved = root.resolve()
        return resolved == root_resolved or resolved.is_relative_to(root_resolved)
    except (OSError, ValueError):
        return False


def _sort_for_deletion(artifacts: List[Artifact]) -> List[Artifact]:
    """Reports first, tmp dir next, session database last."""
    return sorted(
        artifacts,
        key=lambda a: (_DELETE_ORDER.get(a.artifact_type, 99), str(a.path)),
    )


# ---------------------------------------------------------------------------
# Deletion + verify
# ---------------------------------------------------------------------------

def _delete_artifacts(artifacts: List[Artifact]) -> List[DeletionResult]:
    """Delete each artifact, verify absence, continue on per-item failure.

    Missing paths (gone between preview and action) are treated as success
    with error 'already missing' — the desired end state is already true.
    Permission and other OS errors are failures; remaining items still run.
    """
    results: List[DeletionResult] = []
    for artifact in artifacts:
        results.append(_delete_one(artifact))
    return results


def _delete_one(artifact: Artifact) -> DeletionResult:
    """Delete a single validated artifact and verify it is gone."""
    path = artifact.path
    try:
        if artifact.artifact_type == ArtifactType.TMP_DIR:
            if path.exists() and path.is_symlink():
                return DeletionResult(artifact, False, "Refusing to delete symlink directory")
            if not path.exists():
                return DeletionResult(artifact, True, "already missing")
            shutil.rmtree(path)
        else:
            try:
                path.unlink()
            except FileNotFoundError:
                return DeletionResult(artifact, True, "already missing")

        if path.exists() or path.is_symlink():
            return DeletionResult(artifact, False, "Path still exists after deletion")
        return DeletionResult(artifact, True)
    except PermissionError as exc:
        return DeletionResult(artifact, False, str(exc))
    except OSError as exc:
        return DeletionResult(artifact, False, str(exc))


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _render_preview(artifacts: List[Artifact]) -> None:
    """Show what will be deleted before any filesystem change."""
    table = Table(title="Artifacts to delete", box=box.ROUNDED)
    table.add_column("Type", style="bold")
    table.add_column("Path")
    table.add_column("Size", justify="right")
    for artifact in artifacts:
        size = "—" if artifact.artifact_type == ArtifactType.TMP_DIR else str(artifact.size_bytes)
        table.add_row(artifact.artifact_type.value, str(artifact.path), size)
    display(table)
    display("[yellow]This permanently deletes NetLab lab artifacts. Type yes to continue.[/yellow]")


def _render_results(results: List[DeletionResult]) -> None:
    """Show per-artifact success or failure after deletion attempts."""
    table = Table(title="Cleanup results", box=box.ROUNDED)
    table.add_column("Status")
    table.add_column("Type")
    table.add_column("Path")
    table.add_column("Detail")
    for item in results:
        if item.success:
            status = "[green]deleted[/green]" if item.error != "already missing" else "[green]already gone[/green]"
        else:
            status = "[red]failed[/red]"
        table.add_row(
            status,
            item.artifact.artifact_type.value,
            str(item.artifact.path),
            item.error or "—",
        )
    display(table)
