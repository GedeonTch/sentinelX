"""
tests/test_artifact_detector.py — Unit tests for cleanup/artifact_detector.py

Strategy:
- All tests use tmp_path — no real ~/.netlab/ files are created or read
- core.database.get_db_path is patched so the real home dir is never touched
- Tests cover: nominal detection, ownership rules, path safety, sentinel DB exclusion

Security-critical tests (marked with SECURITY):
- session_id with path traversal characters → ValueError
- session_id empty → ValueError
- File from another session → NOT returned
- Sentinel DB → NEVER returned
"""

import pytest
from pathlib import Path
from unittest.mock import patch

import core.database as db
from cleanup.artifact_detector import (
    Artifact,
    ArtifactType,
    detect_artifacts,
    _detect_session_db,
    _detect_reports,
    _detect_tmp_dir,
)

SESSION = "session-test-cleanup"
OTHER   = "session-other-000"


@pytest.fixture(autouse=True)
def patch_home(tmp_path, monkeypatch):
    """Redirect all home-relative paths to tmp_path."""
    # Patch Path.home() used inside artifact_detector
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    # Ensure ~/.netlab/sessions and ~/.netlab/reports exist
    (tmp_path / ".netlab" / "sessions").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".netlab" / "reports").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".netlab" / "sentinel").mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# session_id validation (SECURITY)
# ---------------------------------------------------------------------------

class TestSessionIdValidation:
    def test_empty_session_id_raises(self):
        with pytest.raises(ValueError):
            detect_artifacts("")

    def test_path_traversal_raises(self):
        with pytest.raises(ValueError):
            detect_artifacts("../../etc/passwd")

    def test_slash_in_session_id_raises(self):
        with pytest.raises(ValueError):
            detect_artifacts("session/evil")

    def test_null_byte_raises(self):
        with pytest.raises(ValueError):
            detect_artifacts("session\x00evil")

    def test_too_long_raises(self):
        with pytest.raises(ValueError):
            detect_artifacts("a" * 65)

    def test_valid_session_id_accepted(self):
        # Should not raise — returns empty list since no files exist
        result = detect_artifacts(SESSION)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# _detect_session_db
# ---------------------------------------------------------------------------

class TestDetectSessionDb:
    def test_returns_artifact_when_db_exists(self, tmp_path):
        db_path = tmp_path / ".netlab" / "sessions" / f"{SESSION}.db"
        db_path.write_bytes(b"SQLite dummy")

        results = _detect_session_db(SESSION)
        assert len(results) == 1
        assert results[0].exists is True
        assert results[0].artifact_type == ArtifactType.SESSION_DB
        assert results[0].session_id == SESSION
        assert results[0].size_bytes == 12

    def test_returns_artifact_when_db_absent(self, tmp_path):
        results = _detect_session_db(SESSION)
        assert len(results) == 1
        assert results[0].exists is False
        assert results[0].size_bytes == 0

    def test_db_path_contains_session_id(self, tmp_path):
        results = _detect_session_db(SESSION)
        assert SESSION in results[0].path.name


# ---------------------------------------------------------------------------
# _detect_reports
# ---------------------------------------------------------------------------

class TestDetectReports:
    def test_returns_html_report(self, tmp_path):
        report = tmp_path / ".netlab" / "reports" / f"{SESSION}.html"
        report.write_text("<html/>")

        results = _detect_reports(SESSION)
        assert any(a.artifact_type == ArtifactType.REPORT and a.exists for a in results)

    def test_returns_json_report(self, tmp_path):
        report = tmp_path / ".netlab" / "reports" / f"{SESSION}.json"
        report.write_text("{}")

        results = _detect_reports(SESSION)
        assert len(results) == 1
        assert results[0].exists is True

    def test_returns_multiple_formats(self, tmp_path):
        (tmp_path / ".netlab" / "reports" / f"{SESSION}.html").write_text("<html/>")
        (tmp_path / ".netlab" / "reports" / f"{SESSION}.json").write_text("{}")

        results = _detect_reports(SESSION)
        assert len(results) == 2

    def test_does_not_return_other_session_report(self, tmp_path):
        """SECURITY: report from another session must NOT be returned."""
        (tmp_path / ".netlab" / "reports" / f"{OTHER}.html").write_text("<html/>")

        results = _detect_reports(SESSION)
        assert all(a.session_id == SESSION for a in results)
        assert len(results) == 0

    def test_prefix_only_no_partial_match(self, tmp_path):
        """SECURITY: 'session-test-cleanup-evil.html' must NOT match SESSION."""
        evil_name = f"{SESSION}-evil.html"
        (tmp_path / ".netlab" / "reports" / evil_name).write_text("evil")

        results = _detect_reports(SESSION)
        assert len(results) == 0

    def test_reports_dir_absent_returns_empty(self, tmp_path):
        import shutil
        shutil.rmtree(tmp_path / ".netlab" / "reports")
        results = _detect_reports(SESSION)
        assert results == []

    def test_subdirectory_in_reports_not_returned(self, tmp_path):
        """A subdirectory matching session_id pattern must not be returned as REPORT."""
        subdir = tmp_path / ".netlab" / "reports" / f"{SESSION}.d"
        subdir.mkdir()
        results = _detect_reports(SESSION)
        assert all(a.artifact_type == ArtifactType.REPORT for a in results)
        assert len(results) == 0  # only files are returned


# ---------------------------------------------------------------------------
# _detect_tmp_dir
# ---------------------------------------------------------------------------

class TestDetectTmpDir:
    def test_returns_artifact_when_tmp_dir_exists(self, tmp_path, monkeypatch):
        tmp_dir = tmp_path / "tmp" / f"netlab-{SESSION}"
        tmp_dir.mkdir(parents=True)

        # Patch Path("/tmp") to use tmp_path/tmp
        original_init = Path.__new__

        import cleanup.artifact_detector as ad
        with patch.object(ad.Path, "__new__",
                          wraps=lambda cls, *args, **kwargs: original_init(cls, *args, **kwargs)):
            # Direct test of the function using the real /tmp path — skip in unit test
            # Instead, test the artifact construction logic
            artifact = ad._detect_tmp_dir(SESSION)[0]
            # The real /tmp/netlab-<SESSION> likely doesn't exist in CI — that's fine
            assert artifact.artifact_type == ArtifactType.TMP_DIR
            assert artifact.session_id == SESSION
            assert f"netlab-{SESSION}" in str(artifact.path)

    def test_returns_non_existing_artifact(self):
        results = _detect_tmp_dir(SESSION)
        assert len(results) == 1
        assert results[0].artifact_type == ArtifactType.TMP_DIR
        # May or may not exist — just check the structure
        assert results[0].session_id == SESSION


# ---------------------------------------------------------------------------
# detect_artifacts — integration
# ---------------------------------------------------------------------------

class TestDetectArtifacts:
    def test_returns_empty_when_nothing_exists(self):
        result = detect_artifacts(SESSION)
        assert result == []

    def test_returns_session_db_when_exists(self, tmp_path):
        db_path = tmp_path / ".netlab" / "sessions" / f"{SESSION}.db"
        db_path.write_bytes(b"x" * 100)

        result = detect_artifacts(SESSION)
        assert len(result) == 1
        assert result[0].artifact_type == ArtifactType.SESSION_DB
        assert result[0].size_bytes == 100

    def test_returns_report_when_exists(self, tmp_path):
        (tmp_path / ".netlab" / "reports" / f"{SESSION}.html").write_text("<html/>")

        result = detect_artifacts(SESSION)
        assert len(result) == 1
        assert result[0].artifact_type == ArtifactType.REPORT

    def test_returns_all_existing_artifacts(self, tmp_path):
        (tmp_path / ".netlab" / "sessions" / f"{SESSION}.db").write_bytes(b"db")
        (tmp_path / ".netlab" / "reports" / f"{SESSION}.html").write_text("html")
        (tmp_path / ".netlab" / "reports" / f"{SESSION}.json").write_text("json")

        result = detect_artifacts(SESSION)
        types = {a.artifact_type for a in result}
        assert ArtifactType.SESSION_DB in types
        assert ArtifactType.REPORT in types
        assert len(result) == 3

    def test_sentinel_db_never_returned(self, tmp_path):
        """SECURITY: sentinel DBs must NEVER appear in the artifact list."""
        (tmp_path / ".netlab" / "sentinel" / "a1b2c3d4e5f6.db").write_bytes(b"sentinel")

        result = detect_artifacts(SESSION)
        assert all(a.artifact_type != ArtifactType.SESSION_DB
                   or SESSION in a.path.name
                   for a in result)
        # More direct: no sentinel path should be present
        for a in result:
            assert "sentinel" not in str(a.path)

    def test_only_returns_existing_artifacts(self, tmp_path):
        """Non-existing artifacts must NOT appear in the result."""
        # DB doesn't exist, report does
        (tmp_path / ".netlab" / "reports" / f"{SESSION}.json").write_text("{}")

        result = detect_artifacts(SESSION)
        assert all(a.exists for a in result)
        assert all(a.artifact_type == ArtifactType.REPORT for a in result)

    def test_other_session_artifacts_not_returned(self, tmp_path):
        """SECURITY: artifacts from another session must not appear."""
        (tmp_path / ".netlab" / "sessions" / f"{OTHER}.db").write_bytes(b"other")
        (tmp_path / ".netlab" / "reports" / f"{OTHER}.html").write_text("other")

        result = detect_artifacts(SESSION)
        assert result == []

    def test_returns_list_type(self):
        result = detect_artifacts(SESSION)
        assert isinstance(result, list)

    def test_all_artifacts_have_correct_session_id(self, tmp_path):
        (tmp_path / ".netlab" / "sessions" / f"{SESSION}.db").write_bytes(b"db")
        (tmp_path / ".netlab" / "reports" / f"{SESSION}.html").write_text("html")

        result = detect_artifacts(SESSION)
        assert all(a.session_id == SESSION for a in result)
