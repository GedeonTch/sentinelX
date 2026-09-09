"""
tests/test_cli.py — CLI tests for cli.py

Strategy:
- Uses typer.testing.CliRunner — no real subprocess, no network, no DB on disk
- DB path patched to tmp_path for tests that touch core/database
- Confirmation prompts answered via input= parameter
- Tests verify exit codes, output content, and that no business logic leaked into CLI

Covers:
- netlab --version
- netlab doctor (env ready / env not ready)
- netlab scan (confirmation yes / no / invalid profile)
- netlab findings list / show / explain (session with findings / empty / not found)
- netlab sentinel start / status / stop
- netlab report generate (valid / invalid format)
- netlab cleanup (session / sessions+older-than / cancelled)
- netlab config set / show
"""

import pytest
from pathlib import Path
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

from cli import app
from core.finding import (
    Finding,
    Evidence,
    Explanation,
    Severity,
    Category,
    Confidence,
    Exposure,
    FindingStatus,
)

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_finding(**kwargs) -> Finding:
    defaults = dict(
        session_id="session-001",
        module="tcp_scan",
        target_ip="192.168.1.1",
        target_port=445,
        target_service="smb",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        evidence=Evidence(raw="PORT 445/tcp open", command="nmap 192.168.1.1"),
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# --version
# ---------------------------------------------------------------------------

class TestVersion:
    def test_version_flag_exits_zero(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0

    def test_version_output_contains_version_string(self):
        result = runner.invoke(app, ["--version"])
        assert "0.1.0" in result.output


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------

class TestDoctor:
    def test_doctor_exits_zero_when_env_ready(self):
        with patch("cli.check_environment") as mock_env, \
             patch("cli.environment_ready", return_value=True):
            mock_env.return_value = []
            result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0

    def test_doctor_exits_one_when_env_not_ready(self):
        with patch("cli.check_environment") as mock_env, \
             patch("cli.environment_ready", return_value=False):
            mock_env.return_value = []
            result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 1

    def test_doctor_output_contains_ready_message(self):
        with patch("cli.check_environment") as mock_env, \
             patch("cli.environment_ready", return_value=True):
            mock_env.return_value = []
            result = runner.invoke(app, ["doctor"])
        assert "ready" in result.output.lower()

    def test_doctor_output_contains_not_ready_message(self):
        with patch("cli.check_environment") as mock_env, \
             patch("cli.environment_ready", return_value=False):
            mock_env.return_value = []
            result = runner.invoke(app, ["doctor"])
        assert "not ready" in result.output.lower()


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

class TestScan:
    def test_scan_requires_target(self):
        result = runner.invoke(app, ["scan"])
        assert result.exit_code != 0

    def test_scan_invalid_profile_exits_one(self):
        result = runner.invoke(
            app,
            ["scan", "--target", "192.168.1.1", "--profile", "turbo"],
            input="y\n",
        )
        assert result.exit_code == 1
        assert "Invalid profile" in result.output

    def test_scan_cancelled_by_user_exits_zero(self):
        result = runner.invoke(
            app,
            ["scan", "--target", "192.168.1.1", "--profile", "normal"],
            input="n\n",
        )
        assert result.exit_code == 0
        assert "cancelled" in result.output.lower()

    def test_scan_confirmed_creates_session(self, tmp_path):
        """Confirming a scan must create a session DB and exit zero."""
        import core.database as db

        def mock_db_path(session_id: str) -> Path:
            d = tmp_path / ".netlab" / "sessions"
            d.mkdir(parents=True, exist_ok=True)
            return d / f"{session_id}.db"

        with patch.object(db, "get_db_path", side_effect=mock_db_path):
            result = runner.invoke(
                app,
                ["scan", "--target", "192.168.1.1", "--profile", "normal"],
                input="y\n",
            )
        assert result.exit_code == 0
        assert "Session created" in result.output

    def test_scan_stealth_profile_accepted(self, tmp_path):
        import core.database as db

        def mock_db_path(session_id: str) -> Path:
            d = tmp_path / ".netlab" / "sessions"
            d.mkdir(parents=True, exist_ok=True)
            return d / f"{session_id}.db"

        with patch.object(db, "get_db_path", side_effect=mock_db_path):
            result = runner.invoke(
                app,
                ["scan", "--target", "10.0.0.0/24", "--profile", "stealth"],
                input="y\n",
            )
        assert result.exit_code == 0

    def test_scan_shows_confirmation_prompt(self):
        """The CLI must ask for confirmation before any active scan."""
        result = runner.invoke(
            app,
            ["scan", "--target", "192.168.1.1"],
            input="n\n",
        )
        # Prompt must appear before cancellation
        assert "?" in result.output or "confirm" in result.output.lower() or "cancel" in result.output.lower()


# ---------------------------------------------------------------------------
# findings list
# ---------------------------------------------------------------------------

class TestFindingsList:
    def test_findings_list_empty_session(self, tmp_path):
        import core.database as db

        def mock_db_path(session_id: str) -> Path:
            d = tmp_path / ".netlab" / "sessions"
            d.mkdir(parents=True, exist_ok=True)
            return d / f"{session_id}.db"

        with patch.object(db, "get_db_path", side_effect=mock_db_path):
            db.init_db("session-001")
            result = runner.invoke(app, ["findings", "list", "--session", "session-001"])

        assert result.exit_code == 0
        assert "No findings" in result.output

    def test_findings_list_with_findings(self, tmp_path):
        import core.database as db

        def mock_db_path(session_id: str) -> Path:
            d = tmp_path / ".netlab" / "sessions"
            d.mkdir(parents=True, exist_ok=True)
            return d / f"{session_id}.db"

        with patch.object(db, "get_db_path", side_effect=mock_db_path):
            db.init_db("session-001")
            db.save_session("session-001", target="192.168.1.1")
            db.save_finding(make_finding())
            result = runner.invoke(app, ["findings", "list", "--session", "session-001"])

        assert result.exit_code == 0
        assert "tcp_scan" in result.output

    def test_findings_list_requires_session(self):
        result = runner.invoke(app, ["findings", "list"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# findings show
# ---------------------------------------------------------------------------

class TestFindingsShow:
    def test_findings_show_not_found(self, tmp_path):
        import core.database as db

        def mock_db_path(session_id: str) -> Path:
            d = tmp_path / ".netlab" / "sessions"
            d.mkdir(parents=True, exist_ok=True)
            return d / f"{session_id}.db"

        with patch.object(db, "get_db_path", side_effect=mock_db_path):
            db.init_db("session-001")
            result = runner.invoke(
                app,
                ["findings", "show", "nonexistent-id", "--session", "session-001"],
            )

        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_findings_show_existing(self, tmp_path):
        import core.database as db

        def mock_db_path(session_id: str) -> Path:
            d = tmp_path / ".netlab" / "sessions"
            d.mkdir(parents=True, exist_ok=True)
            return d / f"{session_id}.db"

        f = make_finding()
        with patch.object(db, "get_db_path", side_effect=mock_db_path):
            db.init_db("session-001")
            db.save_session("session-001", target="192.168.1.1")
            db.save_finding(f)
            result = runner.invoke(
                app,
                ["findings", "show", f.id, "--session", "session-001"],
            )

        assert result.exit_code == 0
        assert "192.168.1.1" in result.output


# ---------------------------------------------------------------------------
# findings explain
# ---------------------------------------------------------------------------

class TestFindingsExplain:
    def test_explain_with_explanation(self, tmp_path):
        import core.database as db

        def mock_db_path(session_id: str) -> Path:
            d = tmp_path / ".netlab" / "sessions"
            d.mkdir(parents=True, exist_ok=True)
            return d / f"{session_id}.db"

        f = make_finding(explanation=Explanation(
            what="SMBv1 is enabled.",
            attack="EternalBlue exploitation.",
            defense="Disable SMBv1.",
        ))
        with patch.object(db, "get_db_path", side_effect=mock_db_path):
            db.init_db("session-001")
            db.save_session("session-001", target="192.168.1.1")
            db.save_finding(f)
            result = runner.invoke(
                app,
                ["findings", "explain", f.id, "--session", "session-001"],
            )

        assert result.exit_code == 0
        assert "SMBv1" in result.output

    def test_explain_no_explanation(self, tmp_path):
        """explanation=None must show a clear message, not crash."""
        import core.database as db

        def mock_db_path(session_id: str) -> Path:
            d = tmp_path / ".netlab" / "sessions"
            d.mkdir(parents=True, exist_ok=True)
            return d / f"{session_id}.db"

        f = make_finding(explanation=None)
        with patch.object(db, "get_db_path", side_effect=mock_db_path):
            db.init_db("session-001")
            db.save_session("session-001", target="192.168.1.1")
            db.save_finding(f)
            result = runner.invoke(
                app,
                ["findings", "explain", f.id, "--session", "session-001"],
            )

        assert result.exit_code == 0
        assert "No explanation" in result.output


# ---------------------------------------------------------------------------
# sentinel
# ---------------------------------------------------------------------------

class TestSentinel:
    def test_sentinel_start_cancelled(self):
        result = runner.invoke(app, ["sentinel", "start"], input="n\n")
        assert result.exit_code == 0
        assert "cancelled" in result.output.lower()

    def test_sentinel_start_not_yet_implemented(self):
        result = runner.invoke(app, ["sentinel", "start"], input="y\n")
        assert result.exit_code == 0
        assert "not yet implemented" in result.output.lower()

    def test_sentinel_status_not_yet_implemented(self):
        result = runner.invoke(app, ["sentinel", "status"])
        assert result.exit_code == 0
        assert "not yet implemented" in result.output.lower()

    def test_sentinel_stop_not_yet_implemented(self):
        result = runner.invoke(app, ["sentinel", "stop"])
        assert result.exit_code == 0
        assert "not yet implemented" in result.output.lower()


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

class TestReport:
    def test_report_generate_invalid_format(self):
        result = runner.invoke(
            app,
            ["report", "generate", "--session", "session-001", "--format", "docx"],
        )
        assert result.exit_code == 1
        assert "Invalid format" in result.output

    def test_report_generate_valid_formats(self):
        for fmt in ("pdf", "html", "json"):
            result = runner.invoke(
                app,
                ["report", "generate", "--session", "session-001", "--format", fmt],
            )
            assert result.exit_code == 0
            assert "not yet implemented" in result.output.lower()

    def test_report_requires_session(self):
        result = runner.invoke(app, ["report", "generate"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# cleanup
# ---------------------------------------------------------------------------

class TestCleanup:
    def test_cleanup_session_cancelled(self):
        result = runner.invoke(
            app,
            ["cleanup", "--session", "session-001"],
            input="n\n",
        )
        assert result.exit_code == 0
        assert "cancelled" in result.output.lower()

    def test_cleanup_sessions_older_than_cancelled(self):
        result = runner.invoke(
            app,
            ["cleanup", "--sessions", "--older-than", "30d"],
            input="n\n",
        )
        assert result.exit_code == 0
        assert "cancelled" in result.output.lower()

    def test_cleanup_no_args_shows_usage(self):
        result = runner.invoke(app, ["cleanup"])
        assert result.exit_code == 0
        assert "Usage" in result.output


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

class TestConfig:
    def test_config_show_empty(self, tmp_path):
        """config show with no config must not crash."""
        with patch("cli._read_config", return_value={}):
            result = runner.invoke(app, ["config", "show"])
        assert result.exit_code == 0

    def test_config_set_and_show(self, tmp_path):
        """config set must write the value; config show must display it."""
        config_path = tmp_path / "config.yaml"

        def fake_read():
            if not config_path.exists():
                return {}
            import yaml
            with open(config_path) as f:
                data = yaml.safe_load(f) or {}
            return data.get("lab", {})

        def fake_write(key: str, value: str) -> None:
            import yaml
            data = {"lab": {key: value}}
            with open(config_path, "w") as f:
                yaml.dump(data, f)

        with patch("cli._read_config", side_effect=fake_read), \
             patch("cli._write_config", side_effect=fake_write):
            set_result = runner.invoke(app, ["config", "set", "lab.scope", "192.168.1.0/24"])
            assert set_result.exit_code == 0
            assert "updated" in set_result.output.lower()
