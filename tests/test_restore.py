"""
tests/test_restore.py — Unit tests for cleanup/restore.py

Strategy:
- Path.home() redirected to tmp_path — no real ~/.netlab writes
- input() mocked for confirmation
- /tmp family tests use constructed Artifact paths (no need to create /tmp)
- Integration tests that delete tmp dirs use a unique name under the real /tmp
  and always rmtree in a finally block

Security-critical tests:
- other session artifacts skipped
- path outside the three families skipped
- symlink whose target escapes the allowed root skipped
- sentinel paths skipped
- cancellation never deletes
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cleanup.artifact_detector import Artifact, ArtifactType
from cleanup.restore import (
    RestoreStatus,
    _confirm_deletion,
    _delete_artifacts,
    _is_owned,
    _sort_for_deletion,
    _validate_artifacts,
    restore_session,
)

SESSION = "session-test-restore"
OTHER = "session-other-restore"


@pytest.fixture(autouse=True)
def patch_home(tmp_path, monkeypatch):
    """Redirect ~/.netlab-relative paths to tmp_path."""
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    (tmp_path / ".netlab" / "sessions").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".netlab" / "reports").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".netlab" / "sentinel").mkdir(parents=True, exist_ok=True)
    return tmp_path


def _session_db(tmp_path: Path, session_id: str = SESSION, data: bytes = b"db") -> Path:
    path = tmp_path / ".netlab" / "sessions" / f"{session_id}.db"
    path.write_bytes(data)
    return path


def _report(tmp_path: Path, session_id: str = SESSION, suffix: str = ".html", text: str = "<html/>") -> Path:
    path = tmp_path / ".netlab" / "reports" / f"{session_id}{suffix}"
    path.write_text(text)
    return path


def _artifact(path: Path, artifact_type: ArtifactType, session_id: str = SESSION) -> Artifact:
    exists = path.exists()
    size = path.stat().st_size if exists and path.is_file() else 0
    return Artifact(
        path=path,
        artifact_type=artifact_type,
        session_id=session_id,
        exists=exists,
        size_bytes=size,
    )


# ---------------------------------------------------------------------------
# session_id validation
# ---------------------------------------------------------------------------

class TestSessionIdValidation:
    def test_empty_session_id_raises(self):
        with pytest.raises(ValueError):
            restore_session("")

    def test_path_traversal_raises(self):
        with pytest.raises(ValueError):
            restore_session("../../etc/passwd")

    def test_slash_raises(self):
        with pytest.raises(ValueError):
            restore_session("session/evil")


# ---------------------------------------------------------------------------
# Empty / nothing to clean
# ---------------------------------------------------------------------------

class TestEmpty:
    def test_no_artifacts_returns_nothing_to_clean(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda *a, **k: "yes")
        status = restore_session(SESSION)
        assert status == RestoreStatus.NOTHING_TO_CLEAN


# ---------------------------------------------------------------------------
# Confirmation
# ---------------------------------------------------------------------------

class TestConfirmation:
    def test_yes_accepted(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda *a, **k: "yes")
        assert _confirm_deletion() is True

    def test_yes_with_whitespace_accepted(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda *a, **k: "  yes  ")
        assert _confirm_deletion() is True

    @pytest.mark.parametrize("value", ["n", "y", "Y", "YES", "Yes", "", "   ", "oui"])
    def test_non_yes_rejected(self, monkeypatch, value):
        monkeypatch.setattr("builtins.input", lambda *a, **k: value)
        assert _confirm_deletion() is False


# ---------------------------------------------------------------------------
# Cancellation — zero deletions
# ---------------------------------------------------------------------------

class TestCancellation:
    @pytest.mark.parametrize("answer", ["n", "y", "YES", ""])
    def test_cancel_leaves_files(self, tmp_path, monkeypatch, answer):
        db_path = _session_db(tmp_path)
        report = _report(tmp_path)
        monkeypatch.setattr("builtins.input", lambda *a, **k: answer)
        status = restore_session(SESSION)
        assert status == RestoreStatus.CANCELLED
        assert db_path.exists()
        assert report.exists()


# ---------------------------------------------------------------------------
# Nominal delete after yes
# ---------------------------------------------------------------------------

class TestNominal:
    def test_db_and_report_deleted_after_yes(self, tmp_path, monkeypatch):
        db_path = _session_db(tmp_path)
        report = _report(tmp_path)
        json_report = _report(tmp_path, suffix=".json", text="{}")
        monkeypatch.setattr("builtins.input", lambda *a, **k: "yes")
        status = restore_session(SESSION)
        assert status == RestoreStatus.SUCCESS
        assert not db_path.exists()
        assert not report.exists()
        assert not json_report.exists()

    def test_db_deleted_last(self, tmp_path, monkeypatch):
        db_path = _session_db(tmp_path)
        report = _report(tmp_path)
        order: list = []

        import cleanup.restore as restore_mod

        real_delete = restore_mod._delete_one

        def tracking_delete(artifact):
            order.append(artifact.artifact_type)
            return real_delete(artifact)

        monkeypatch.setattr("builtins.input", lambda *a, **k: "yes")
        monkeypatch.setattr("cleanup.restore._delete_one", tracking_delete)
        status = restore_session(SESSION)
        assert status == RestoreStatus.SUCCESS
        assert order[0] == ArtifactType.REPORT
        assert order[-1] == ArtifactType.SESSION_DB
        assert not db_path.exists()
        assert not report.exists()


# ---------------------------------------------------------------------------
# Ownership / path safety
# ---------------------------------------------------------------------------

class TestOwnership:
    def test_other_session_db_not_owned(self, tmp_path):
        path = _session_db(tmp_path, session_id=OTHER)
        artifact = _artifact(path, ArtifactType.SESSION_DB, session_id=SESSION)
        assert _is_owned(artifact, SESSION) is False

    def test_session_id_field_mismatch_skipped(self, tmp_path):
        path = _session_db(tmp_path)
        artifact = _artifact(path, ArtifactType.SESSION_DB, session_id=OTHER)
        safe, skipped = _validate_artifacts([artifact], SESSION)
        assert safe == []
        assert skipped == [artifact]

    def test_sentinel_db_not_owned(self, tmp_path):
        path = tmp_path / ".netlab" / "sentinel" / f"{SESSION}.db"
        path.write_bytes(b"sentinel")
        artifact = _artifact(path, ArtifactType.SESSION_DB, session_id=SESSION)
        assert _is_owned(artifact, SESSION) is False

    def test_path_outside_netlab_not_owned(self, tmp_path):
        evil = tmp_path / "passwd"
        evil.write_text("root")
        artifact = _artifact(evil, ArtifactType.SESSION_DB, session_id=SESSION)
        assert _is_owned(artifact, SESSION) is False

    def test_etc_passwd_not_owned(self):
        artifact = Artifact(
            path=Path("/etc/passwd"),
            artifact_type=ArtifactType.SESSION_DB,
            session_id=SESSION,
            exists=True,
            size_bytes=1,
        )
        assert _is_owned(artifact, SESSION) is False

    def test_report_in_subdirectory_not_owned(self, tmp_path):
        nested = tmp_path / ".netlab" / "reports" / "nested"
        nested.mkdir()
        path = nested / f"{SESSION}.html"
        path.write_text("nope")
        artifact = _artifact(path, ArtifactType.REPORT, session_id=SESSION)
        assert _is_owned(artifact, SESSION) is False

    def test_whitelist_not_owned(self, tmp_path):
        path = tmp_path / ".netlab" / "baseline_whitelist.yaml"
        path.write_text("allowed_new_macs: []\n")
        artifact = Artifact(
            path=path,
            artifact_type=ArtifactType.REPORT,
            session_id=SESSION,
            exists=True,
            size_bytes=path.stat().st_size,
        )
        assert _is_owned(artifact, SESSION) is False

    def test_symlink_escaping_session_db_rejected(self, tmp_path):
        target = tmp_path / "outside.db"
        target.write_bytes(b"secret")
        link = tmp_path / ".netlab" / "sessions" / f"{SESSION}.db"
        link.symlink_to(target)
        artifact = _artifact(link, ArtifactType.SESSION_DB, session_id=SESSION)
        assert _is_owned(artifact, SESSION) is False

    def test_symlink_escaping_report_rejected(self, tmp_path):
        target = tmp_path / "outside.html"
        target.write_text("secret")
        link = tmp_path / ".netlab" / "reports" / f"{SESSION}.html"
        link.symlink_to(target)
        artifact = _artifact(link, ArtifactType.REPORT, session_id=SESSION)
        assert _is_owned(artifact, SESSION) is False

    def test_tmp_dir_wrong_name_rejected(self):
        artifact = Artifact(
            path=Path("/tmp") / f"netlab-{OTHER}",
            artifact_type=ArtifactType.TMP_DIR,
            session_id=SESSION,
            exists=False,
            size_bytes=0,
        )
        assert _is_owned(artifact, SESSION) is False

    def test_valid_session_db_owned(self, tmp_path):
        path = _session_db(tmp_path)
        artifact = _artifact(path, ArtifactType.SESSION_DB)
        assert _is_owned(artifact, SESSION) is True

    def test_valid_report_owned(self, tmp_path):
        path = _report(tmp_path)
        artifact = _artifact(path, ArtifactType.REPORT)
        assert _is_owned(artifact, SESSION) is True

    def test_valid_tmp_dir_path_owned_without_existing_dir(self):
        artifact = Artifact(
            path=Path("/tmp") / f"netlab-{SESSION}",
            artifact_type=ArtifactType.TMP_DIR,
            session_id=SESSION,
            exists=False,
            size_bytes=0,
        )
        assert _is_owned(artifact, SESSION) is True

    def test_restore_does_not_delete_sentinel(self, tmp_path, monkeypatch):
        db_path = _session_db(tmp_path)
        sentinel = tmp_path / ".netlab" / "sentinel" / "aabbccddee12.db"
        sentinel.write_bytes(b"sentinel")
        monkeypatch.setattr("builtins.input", lambda *a, **k: "yes")
        status = restore_session(SESSION)
        assert status == RestoreStatus.SUCCESS
        assert not db_path.exists()
        assert sentinel.exists()

    def test_other_session_files_untouched(self, tmp_path, monkeypatch):
        ours = _session_db(tmp_path)
        other = _session_db(tmp_path, session_id=OTHER)
        _report(tmp_path, session_id=OTHER, text="other")
        monkeypatch.setattr("builtins.input", lambda *a, **k: "yes")
        status = restore_session(SESSION)
        assert status == RestoreStatus.SUCCESS
        assert not ours.exists()
        assert other.exists()


# ---------------------------------------------------------------------------
# Sort order
# ---------------------------------------------------------------------------

class TestSort:
    def test_session_db_last(self, tmp_path):
        db = _artifact(_session_db(tmp_path), ArtifactType.SESSION_DB)
        report = _artifact(_report(tmp_path), ArtifactType.REPORT)
        tmp_art = Artifact(
            path=Path("/tmp") / f"netlab-{SESSION}",
            artifact_type=ArtifactType.TMP_DIR,
            session_id=SESSION,
            exists=False,
            size_bytes=0,
        )
        ordered = _sort_for_deletion([db, tmp_art, report])
        types = [a.artifact_type for a in ordered]
        assert types == [
            ArtifactType.REPORT,
            ArtifactType.TMP_DIR,
            ArtifactType.SESSION_DB,
        ]


# ---------------------------------------------------------------------------
# Missing between preview and action / permission / partial
# ---------------------------------------------------------------------------

class TestFailureHandling:
    def test_already_missing_is_not_fatal(self, tmp_path):
        path = tmp_path / ".netlab" / "sessions" / f"{SESSION}.db"
        artifact = Artifact(
            path=path,
            artifact_type=ArtifactType.SESSION_DB,
            session_id=SESSION,
            exists=False,
            size_bytes=0,
        )
        results = _delete_artifacts([artifact])
        assert len(results) == 1
        assert results[0].success is True
        assert results[0].error == "already missing"

    def test_missing_between_preview_and_yes(self, tmp_path, monkeypatch):
        db_path = _session_db(tmp_path)
        report = _report(tmp_path)

        def eat_then_yes(_prompt: str = "") -> str:
            db_path.unlink()
            return "yes"

        monkeypatch.setattr("builtins.input", eat_then_yes)
        status = restore_session(SESSION)
        assert status == RestoreStatus.SUCCESS
        assert not db_path.exists()
        assert not report.exists()

    def test_permission_error_continues(self, tmp_path, monkeypatch):
        db_path = _session_db(tmp_path)
        report = _report(tmp_path)
        real_unlink = Path.unlink

        def fake_unlink(self, *args, **kwargs):
            if self.suffix == ".html":
                raise PermissionError("denied")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", fake_unlink)
        monkeypatch.setattr("builtins.input", lambda *a, **k: "yes")
        status = restore_session(SESSION)
        assert status == RestoreStatus.PARTIAL
        assert db_path.exists() is False
        assert report.exists() is True

    def test_verify_failure_when_unlink_is_noop(self, tmp_path, monkeypatch):
        path = _session_db(tmp_path)
        artifact = _artifact(path, ArtifactType.SESSION_DB)
        monkeypatch.setattr(Path, "unlink", lambda self, *a, **k: None)
        results = _delete_artifacts([artifact])
        assert results[0].success is False
        assert "still exists" in results[0].error.lower()
        assert path.exists()


# ---------------------------------------------------------------------------
# Tmp dir deletion (real /tmp, unique session id)
# ---------------------------------------------------------------------------

class TestTmpDirDelete:
    def test_rmtree_tmp_dir(self):
        session_id = "s019tmp1"
        tmp_dir = Path("/tmp") / f"netlab-{session_id}"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        (tmp_dir / "scratch.txt").write_text("x")
        artifact = Artifact(
            path=tmp_dir,
            artifact_type=ArtifactType.TMP_DIR,
            session_id=session_id,
            exists=True,
            size_bytes=0,
        )
        try:
            assert _is_owned(artifact, session_id) is True
            results = _delete_artifacts([artifact])
            assert results[0].success is True
            assert not tmp_dir.exists()
        finally:
            if tmp_dir.exists():
                import shutil
                shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Injected unsafe artifacts
# ---------------------------------------------------------------------------

class TestNoSafeArtifacts:
    def test_injected_unsafe_only(self, monkeypatch):
        evil = Artifact(
            path=Path("/etc/passwd"),
            artifact_type=ArtifactType.SESSION_DB,
            session_id=SESSION,
            exists=True,
            size_bytes=1,
        )
        monkeypatch.setattr(
            "cleanup.restore.detect_artifacts",
            lambda _sid: [evil],
        )
        monkeypatch.setattr("builtins.input", lambda *a, **k: "yes")
        status = restore_session(SESSION)
        assert status == RestoreStatus.NO_SAFE_ARTIFACTS
        assert Path("/etc/passwd").exists()
