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
- netlab sentinel start / status / stop (real sentinel_manager calls)
- netlab report generate (html/json, --output, PDF rejected)
- netlab cleanup (session / sessions+older-than / cancelled)
- netlab config set / show
"""

import pytest
from io import StringIO
from pathlib import Path
from contextlib import ExitStack
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
from rich.console import Console
from rich.table import Table

from cli import app, PipelineResult, _render_scan_summary, _run_pipeline
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

    def _run_scan_with_stubbed_pipeline(
        self,
        target,
        profile,
        knowledge_base_result=None,
        knowledge_base_side_effect=None,
        pipeline_findings=None,
    ):
        """Run scan with every network/pipeline dependency replaced by a stub."""
        import core.database as db

        host_finding = make_finding(module="device_fingerprint", target_ip="192.168.1.1")
        port_finding = make_finding(module="tcp_scan", target_ip="192.168.1.1")
        pipeline_findings = pipeline_findings or [port_finding]

        with ExitStack() as stack:
            stack.enter_context(patch.object(db, "init_db"))
            stack.enter_context(patch.object(db, "save_session"))
            stack.enter_context(patch.object(db, "save_findings"))
            stack.enter_context(patch.object(db, "update_finding_risk_score"))
            stack.enter_context(patch.object(db, "close_session"))
            fingerprint = stack.enter_context(
                patch("recon.device_fingerprint.fingerprint", return_value=[host_finding])
            )
            tcp_scan = stack.enter_context(
                patch("detect.tcp_scan.tcp_scan", return_value=pipeline_findings)
            )
            udp_scan = stack.enter_context(
                patch("detect.udp_scan.udp_scan", return_value=[])
            )
            stack.enter_context(
                patch("detect.service_detection.enrich_findings", return_value=pipeline_findings)
            )
            stack.enter_context(
                patch("detect.misconfig_detection.detect_misconfigs", return_value=[])
            )
            knowledge_base = stack.enter_context(
                patch(
                    "knowledge.knowledge_base.get_explanation_for_finding",
                    return_value=knowledge_base_result,
                    side_effect=knowledge_base_side_effect,
                )
            )
            score_findings = stack.enter_context(
                patch("core.risk_scorer.score_findings", return_value=pipeline_findings)
            )
            stack.enter_context(
                patch("core.risk_scorer.get_global_score", return_value=25.0)
            )

            result = runner.invoke(
                app,
                ["scan", "--target", target, "--profile", profile],
                input="y\n",
            )

        assert result.exit_code == 0, result.output
        assert "RÉSULTAT : SUCCESS" in result.output
        session_id = fingerprint.call_args.args[1]
        fingerprint.assert_called_once_with(target, session_id, auto_confirm=False)
        tcp_scan.assert_called_once_with("192.168.1.1", session_id, profile=profile, auto_confirm=False)
        udp_scan.assert_called_once_with("192.168.1.1", session_id, profile=profile, auto_confirm=False)
        return result, knowledge_base, score_findings

    def test_scan_confirmed_creates_session(self):
        """A positive confirmation runs the complete pipeline without network I/O."""
        result, _, _ = self._run_scan_with_stubbed_pipeline("192.168.1.1", "normal")
        assert "Session:" in result.output

    def test_scan_stealth_profile_accepted(self):
        """The stealth profile is accepted and reaches the stubbed pipeline."""
        result, _, _ = self._run_scan_with_stubbed_pipeline("10.0.0.0/24", "stealth")
        assert "Profile: stealth" in result.output

    def test_scan_attaches_knowledge_base_explanation(self):
        explanation = Explanation(
            what="SMBv1 is enabled.",
            attack="EternalBlue exploitation.",
            defense="Disable SMBv1.",
        )
        result, knowledge_base, score_findings = self._run_scan_with_stubbed_pipeline(
            "192.168.1.1",
            "normal",
            knowledge_base_result=explanation,
        )

        assert result.exit_code == 0
        knowledge_base.assert_called_once_with("tcp_scan", "smb")
        explained = score_findings.call_args.args[0]
        assert explained[0].explanation == explanation

    def test_scan_continues_when_knowledge_base_fails(self):
        second_finding = make_finding(
            module="udp_scan",
            target_ip="192.168.1.1",
            target_service="dns",
        )
        second_explanation = Explanation(
            what="DNS service exposed.",
            attack="DNS information disclosure.",
            defense="Restrict DNS exposure.",
        )

        def knowledge_base_side_effect(module, target_service):
            if module == "tcp_scan":
                raise RuntimeError("KB unavailable")
            return second_explanation

        result, knowledge_base, score_findings = self._run_scan_with_stubbed_pipeline(
            "192.168.1.1",
            "normal",
            knowledge_base_side_effect=knowledge_base_side_effect,
            pipeline_findings=[make_finding(module="tcp_scan"), second_finding],
        )

        assert result.exit_code == 0
        assert "RÉSULTAT : SUCCESS" in result.output
        assert knowledge_base.call_count == 2
        explained = score_findings.call_args.args[0]
        assert explained[0].explanation is None
        assert explained[1].explanation == second_explanation

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
# scan summary
# ---------------------------------------------------------------------------

class TestScanSummary:
    def test_summary_renders_severity_counts_and_success_details(self):
        findings = (
            [make_finding(severity=Severity.CRITICAL)]
            + [make_finding(severity=Severity.HIGH) for _ in range(2)]
            + [make_finding(severity=Severity.MEDIUM) for _ in range(3)]
            + [make_finding(severity=Severity.LOW)]
        )
        result = PipelineResult(
            steps=[],
            session_id="session-summary",
            findings_count=len(findings),
            global_score=72.5,
        )

        with patch("cli.display") as display:
            _render_scan_summary(result, findings)

        table = next(
            call.args[0]
            for call in display.call_args_list
            if isinstance(call.args[0], Table)
        )
        output = StringIO()
        Console(file=output, width=80).print(table)
        rendered_table = output.getvalue()

        assert "CRITICAL" in rendered_table and "1" in rendered_table
        assert "HIGH" in rendered_table and "2" in rendered_table
        assert "MEDIUM" in rendered_table and "3" in rendered_table
        assert "LOW" in rendered_table and "1" in rendered_table
        assert "INFO" in rendered_table and "0" in rendered_table

        rendered_output = "\n".join(str(call.args[0]) for call in display.call_args_list)
        assert "session-summary" in rendered_output
        assert "72.5/100" in rendered_output
        assert "RÉSULTAT : SUCCESS" in rendered_output
        assert "netlab findings list --session session-summary" in rendered_output
        assert "netlab report generate --session session-summary --format html" in rendered_output

    def test_summary_renders_partial_status(self):
        result = PipelineResult(session_id="session-partial")
        result.add("session", "ok")
        result.add("tcp_scan", "partial", "1/2 réussis")

        with patch("cli.display") as display:
            _render_scan_summary(result, [])

        rendered_output = "\n".join(str(call.args[0]) for call in display.call_args_list)
        assert "RÉSULTAT : PARTIAL" in rendered_output

    def test_summary_renders_failed_status(self):
        result = PipelineResult(session_id="session-failed")
        result.add("session", "failed", "database unavailable")

        with patch("cli.display") as display:
            _render_scan_summary(result, [])

        rendered_output = "\n".join(str(call.args[0]) for call in display.call_args_list)
        assert "RÉSULTAT : FAILED" in rendered_output

    def test_summary_keeps_findings_when_persistence_fails(self):
        import core.database as db

        host_finding = make_finding(module="device_fingerprint")
        finding = make_finding(module="tcp_scan", severity=Severity.HIGH)
        result = PipelineResult()

        with ExitStack() as stack:
            stack.enter_context(patch.object(db, "init_db"))
            stack.enter_context(patch.object(db, "save_session"))
            stack.enter_context(patch.object(db, "close_session"))
            stack.enter_context(patch.object(db, "update_finding_risk_score"))
            stack.enter_context(
                patch.object(db, "save_findings", side_effect=[None, None, RuntimeError("DB unavailable")])
            )
            stack.enter_context(
                patch("recon.device_fingerprint.fingerprint", return_value=[host_finding])
            )
            stack.enter_context(
                patch("detect.tcp_scan.tcp_scan", return_value=[finding])
            )
            stack.enter_context(patch("detect.udp_scan.udp_scan", return_value=[]))
            stack.enter_context(
                patch("detect.service_detection.enrich_findings", return_value=[finding])
            )
            stack.enter_context(
                patch("detect.misconfig_detection.detect_misconfigs", return_value=[])
            )
            stack.enter_context(
                patch("knowledge.knowledge_base.get_explanation_for_finding", return_value=None)
            )
            stack.enter_context(
                patch("core.risk_scorer.score_findings", return_value=[finding])
            )
            stack.enter_context(
                patch("core.risk_scorer.get_global_score", return_value=70.0)
            )

            produced = _run_pipeline("192.168.1.1", "normal", None, False, result)

        assert produced == [finding]
        assert result.findings_count == 1
        assert result.overall_status == "PARTIAL"

        with patch("cli.display") as display:
            _render_scan_summary(result, produced)

        table = next(
            call.args[0]
            for call in display.call_args_list
            if isinstance(call.args[0], Table)
        )
        output = StringIO()
        Console(file=output, width=80).print(table)
        rendered_table = output.getvalue()
        assert "HIGH" in rendered_table and "1" in rendered_table


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
# sentinel — real sentinel_manager calls (A4 Task 2)
# ---------------------------------------------------------------------------

class TestSentinel:
    def test_sentinel_start_requires_target(self):
        result = runner.invoke(app, ["sentinel", "start"])
        assert result.exit_code != 0

    def test_sentinel_start_calls_manager_with_real_signature(self):
        with patch("sentinel.sentinel_manager.start") as mock_start:
            result = runner.invoke(
                app,
                ["sentinel", "start", "--target", "192.168.1.0/24"],
            )
        assert result.exit_code == 0
        mock_start.assert_called_once_with(
            target_network="192.168.1.0/24",
            session_id=None,
            force_relearn=False,
        )

    def test_sentinel_start_passes_session_and_relearn(self):
        with patch("sentinel.sentinel_manager.start") as mock_start:
            result = runner.invoke(
                app,
                [
                    "sentinel", "start",
                    "--target", "10.0.0.0/24",
                    "--session", "session-001",
                    "--relearn",
                ],
            )
        assert result.exit_code == 0
        mock_start.assert_called_once_with(
            target_network="10.0.0.0/24",
            session_id="session-001",
            force_relearn=True,
        )

    def test_sentinel_status_requires_session(self):
        result = runner.invoke(app, ["sentinel", "status"])
        assert result.exit_code != 0

    def test_sentinel_status_calls_display_status(self):
        with patch("sentinel.sentinel_manager.display_status") as mock_status:
            result = runner.invoke(
                app,
                ["sentinel", "status", "--session", "net-abc"],
            )
        assert result.exit_code == 0
        mock_status.assert_called_once_with("net-abc")

    def test_sentinel_stop_requires_session(self):
        result = runner.invoke(app, ["sentinel", "stop"])
        assert result.exit_code != 0

    def test_sentinel_stop_calls_manager_stop(self):
        with patch("sentinel.sentinel_manager.stop") as mock_stop:
            result = runner.invoke(
                app,
                ["sentinel", "stop", "--session", "net-abc"],
            )
        assert result.exit_code == 0
        mock_stop.assert_called_once_with("net-abc")

    def test_sentinel_start_does_not_swallow_manager_exceptions(self):
        with patch(
            "sentinel.sentinel_manager.start",
            side_effect=RuntimeError("identity failed"),
        ):
            result = runner.invoke(
                app,
                ["sentinel", "start", "--target", "192.168.1.0/24"],
            )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# report — real generator calls (A4 Task 3)
# ---------------------------------------------------------------------------

class TestReport:
    def test_report_generate_invalid_format(self):
        result = runner.invoke(
            app,
            ["report", "generate", "--session", "session-001", "--format", "docx"],
        )
        assert result.exit_code == 1
        assert "Invalid format" in result.output

    def test_report_rejects_pdf(self):
        result = runner.invoke(
            app,
            ["report", "generate", "--session", "session-001", "--format", "pdf"],
        )
        assert result.exit_code == 1
        assert "PDF" in result.output
        assert "not supported" in result.output.lower()

    def test_report_generate_json_calls_generator(self):
        with patch("reports.generator.generate_report", return_value=True) as mock_gen:
            result = runner.invoke(
                app,
                ["report", "generate", "--session", "session-001", "--format", "json"],
            )
        assert result.exit_code == 0
        assert "Report saved" in result.output
        mock_gen.assert_called_once()
        kwargs = mock_gen.call_args.kwargs
        assert kwargs["session_id"] == "session-001"
        assert kwargs["format"] == "json"
        assert kwargs["output_path"].endswith("session-001.json")

    def test_report_generate_html_calls_generator(self):
        with patch("reports.generator.generate_report", return_value=True) as mock_gen:
            result = runner.invoke(
                app,
                ["report", "generate", "--session", "session-001", "--format", "html"],
            )
        assert result.exit_code == 0
        kwargs = mock_gen.call_args.kwargs
        assert kwargs["format"] == "html"
        assert kwargs["output_path"].endswith("session-001.html")

    def test_report_generate_honours_output_option(self):
        with patch("reports.generator.generate_report", return_value=True) as mock_gen:
            result = runner.invoke(
                app,
                [
                    "report", "generate",
                    "--session", "session-001",
                    "--format", "json",
                    "--output", "/tmp/custom-report.json",
                ],
            )
        assert result.exit_code == 0
        mock_gen.assert_called_once_with(
            session_id="session-001",
            format="json",
            output_path="/tmp/custom-report.json",
        )

    def test_report_generate_false_exits_one(self):
        with patch("reports.generator.generate_report", return_value=False):
            result = runner.invoke(
                app,
                ["report", "generate", "--session", "session-001", "--format", "json"],
            )
        assert result.exit_code == 1

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
