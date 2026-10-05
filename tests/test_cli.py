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
- netlab cleanup (--session restore_session / --sessions older-than stub / cancelled)
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
from recon.device_fingerprint import DiscoveryCancelled, DiscoveryFailed
from detect.tcp_scan import TcpScanCancelled, TcpScanFailed
from detect.udp_scan import UdpScanCancelled, UdpScanFailed
from core.finding import (
    Finding,
    format_finding_id,
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
        use_yes=False,
        expose_mocks=False,
    ):
        """Run scan with every network/pipeline dependency replaced by a stub."""
        import core.database as db

        host_finding = make_finding(module="device_fingerprint", target_ip="192.168.1.1")
        port_finding = make_finding(module="tcp_scan", target_ip="192.168.1.1")
        pipeline_findings = pipeline_findings or [port_finding]

        with ExitStack() as stack:
            stack.enter_context(patch.object(db, "init_db"))
            stack.enter_context(patch.object(db, "save_session"))
            save_findings = stack.enter_context(patch.object(db, "save_findings"))
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
            enrich_findings = stack.enter_context(
                patch("detect.service_detection.enrich_findings", return_value=pipeline_findings)
            )
            detect_misconfigs = stack.enter_context(
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

            scan_args = ["scan", "--target", target, "--profile", profile]
            if use_yes:
                scan_args.append("--yes")
            result = runner.invoke(
                app,
                scan_args,
                input="" if use_yes else "y\n",
            )

        assert result.exit_code == 0, result.output
        expected_status = "PARTIAL" if knowledge_base_side_effect else "SUCCESS"
        assert f"RÉSULTAT : {expected_status}" in result.output
        session_id = fingerprint.call_args.args[1]
        fingerprint.assert_called_once_with(target, session_id, auto_confirm=use_yes)
        tcp_scan.assert_called_once_with("192.168.1.1", session_id, profile=profile, auto_confirm=use_yes)
        udp_scan.assert_called_once_with("192.168.1.1", session_id, profile=profile, auto_confirm=use_yes)
        if expose_mocks:
            return result, knowledge_base, score_findings, enrich_findings, detect_misconfigs, save_findings
        return result, knowledge_base, score_findings

    def _run_pipeline_with_port_outcomes(
        self,
        tcp_outcomes,
        udp_outcomes,
        explanation_side_effect=None,
        explanation_import_error=False,
        close_session_side_effect=None,
        scored_findings=None,
    ):
        import core.database as db

        host_findings = [
            make_finding(module="device_fingerprint", target_ip="192.168.1.10"),
            make_finding(module="device_fingerprint", target_ip="192.168.1.20"),
        ]
        result = PipelineResult()
        with ExitStack() as stack:
            stack.enter_context(patch.object(db, "init_db"))
            stack.enter_context(patch.object(db, "save_session"))
            stack.enter_context(patch.object(db, "save_findings"))
            stack.enter_context(patch.object(db, "update_finding_risk_score"))
            close_session = stack.enter_context(
                patch.object(db, "close_session", side_effect=close_session_side_effect)
            )
            stack.enter_context(patch("recon.device_fingerprint.fingerprint", return_value=host_findings))
            tcp_scan = stack.enter_context(
                patch("detect.tcp_scan.tcp_scan", side_effect=tcp_outcomes)
            )
            udp_scan = stack.enter_context(
                patch("detect.udp_scan.udp_scan", side_effect=udp_outcomes)
            )
            stack.enter_context(
                patch(
                    "core.risk_scorer.score_findings",
                    return_value=scored_findings if scored_findings is not None else [],
                )
            )
            stack.enter_context(patch("core.risk_scorer.get_global_score", return_value=None))
            if explanation_import_error:
                import builtins

                real_import = builtins.__import__

                def import_without_knowledge_base(name, *args, **kwargs):
                    if name == "knowledge.knowledge_base":
                        raise RuntimeError("knowledge base import failed")
                    return real_import(name, *args, **kwargs)

                stack.enter_context(
                    patch("builtins.__import__", side_effect=import_without_knowledge_base)
                )
            else:
                stack.enter_context(
                    patch(
                        "knowledge.knowledge_base.get_explanation_for_finding",
                        return_value=None,
                        side_effect=explanation_side_effect,
                    )
                )

            produced = _run_pipeline("192.168.1.0/24", "normal", None, True, result)

        return result, produced, tcp_scan, udp_scan, close_session

    def test_port_scans_all_successful_empty_are_ok(self):
        result, produced, _, _, close_session = self._run_pipeline_with_port_outcomes(
            tcp_outcomes=[[], []], udp_outcomes=[[], []]
        )

        assert len(produced) == 2
        assert result.findings_count == 2
        close_session.assert_called_once_with(
            close_session.call_args.args[0], status="completed", discover_status="OK"
        )
        assert next(s for s in result.steps if s.name == "tcp_scan").status == "ok"
        assert next(s for s in result.steps if s.name == "udp_scan").status == "ok"
        assert "2/2 hosts scanned" in next(
            s for s in result.steps if s.name == "tcp_scan"
        ).detail

    def test_port_scans_all_successful_with_findings_are_ok(self):
        finding = make_finding(module="tcp_scan", target_ip="192.168.1.10")
        result, produced, _, _, close_session = self._run_pipeline_with_port_outcomes(
            tcp_outcomes=[[finding], [finding]], udp_outcomes=[[], []]
        )

        assert result.overall_status == "SUCCESS"
        close_session.assert_called_once_with(
            close_session.call_args.args[0], status="completed", discover_status="OK"
        )
        assert next(s for s in result.steps if s.name == "tcp_scan").status == "ok"

    def test_port_scan_success_and_failure_is_partial(self):
        result, _, _, _, close_session = self._run_pipeline_with_port_outcomes(
            tcp_outcomes=[[], TcpScanFailed("nmap failed")], udp_outcomes=[[], []]
        )

        tcp_step = next(s for s in result.steps if s.name == "tcp_scan")
        assert tcp_step.status == "partial"
        assert "1 failed" in tcp_step.detail
        assert "2/2 hosts scanned" not in tcp_step.detail
        close_session.assert_called_once_with(
            close_session.call_args.args[0], status="partial", discover_status="OK"
        )

    def test_port_scan_success_and_cancellation_is_partial(self):
        result, _, _, _, _ = self._run_pipeline_with_port_outcomes(
            tcp_outcomes=[[], TcpScanCancelled("user cancelled")], udp_outcomes=[[], []]
        )

        tcp_step = next(s for s in result.steps if s.name == "tcp_scan")
        assert tcp_step.status == "partial"
        assert "1 cancelled" in tcp_step.detail

    def test_port_scan_all_failed_is_failed(self):
        result, _, _, _, close_session = self._run_pipeline_with_port_outcomes(
            tcp_outcomes=[TcpScanFailed("first"), TcpScanFailed("second")],
            udp_outcomes=[[], []],
        )

        tcp_step = next(s for s in result.steps if s.name == "tcp_scan")
        assert tcp_step.status == "failed"
        assert "0/2 hosts scanned" in tcp_step.detail
        assert "2 failed" in tcp_step.detail
        assert result.overall_status == "PARTIAL"
        close_session.assert_called_once_with(
            close_session.call_args.args[0], status="partial", discover_status="OK"
        )

    def test_port_scan_all_cancelled_is_cancelled(self):
        result, _, _, _, close_session = self._run_pipeline_with_port_outcomes(
            tcp_outcomes=[TcpScanCancelled("first"), TcpScanCancelled("second")],
            udp_outcomes=[[], []],
        )

        tcp_step = next(s for s in result.steps if s.name == "tcp_scan")
        assert tcp_step.status == "cancelled"
        assert "0/2 hosts scanned" in tcp_step.detail
        assert "2 cancelled" in tcp_step.detail
        assert result.overall_status == "SUCCESS"
        close_session.assert_called_once_with(
            close_session.call_args.args[0], status="completed", discover_status="OK"
        )

    def test_port_scan_failed_and_cancelled_without_success_is_failed(self):
        result, _, _, _, _ = self._run_pipeline_with_port_outcomes(
            tcp_outcomes=[TcpScanFailed("failed"), TcpScanCancelled("cancelled")],
            udp_outcomes=[[], []],
        )

        tcp_step = next(s for s in result.steps if s.name == "tcp_scan")
        assert tcp_step.status == "failed"
        assert "1 failed" in tcp_step.detail
        assert "1 cancelled" in tcp_step.detail

    def test_udp_scan_success_and_failure_is_partial(self):
        result, _, _, _, close_session = self._run_pipeline_with_port_outcomes(
            tcp_outcomes=[[], []],
            udp_outcomes=[[], UdpScanFailed("nmap failed")],
        )

        udp_step = next(s for s in result.steps if s.name == "udp_scan")
        assert udp_step.status == "partial"
        assert "1 failed" in udp_step.detail
        close_session.assert_called_once_with(
            close_session.call_args.args[0], status="partial", discover_status="OK"
        )

    def test_explanation_failure_marks_pipeline_partial_and_session_partial(self):
        finding = make_finding(module="tcp_scan", target_ip="192.168.1.10")
        result, _, _, _, close_session = self._run_pipeline_with_port_outcomes(
            tcp_outcomes=[[finding], [finding]],
            udp_outcomes=[[], []],
            explanation_side_effect=RuntimeError("knowledge base unavailable"),
        )

        explanation_step = next(s for s in result.steps if s.name == "explanation")
        assert explanation_step.status == "partial"
        assert result.overall_status == "PARTIAL"
        close_session.assert_called_once_with(
            close_session.call_args.args[0], status="partial", discover_status="OK"
        )

    def test_close_session_failure_warns_without_changing_success(self):
        finding = make_finding(module="tcp_scan", target_ip="192.168.1.10")
        with patch("cli.display") as display:
            result, produced, _, _, close_session = self._run_pipeline_with_port_outcomes(
                tcp_outcomes=[[finding], [finding]],
                udp_outcomes=[[], []],
                close_session_side_effect=RuntimeError("database is locked"),
                scored_findings=[finding],
            )

        assert result.overall_status == "SUCCESS"
        assert result.findings_count == 3
        assert len(produced) == 3
        assert finding.id in {item.id for item in produced}
        assert "session_close" not in {step.name for step in result.steps}
        close_session.assert_called_once()
        assert any(
            "Warning: session could not be closed cleanly: database is locked" in str(call.args[0])
            for call in display.call_args_list
        )

    def test_close_session_failure_warns_without_changing_partial(self):
        with patch("cli.display") as display:
            result, _, _, _, close_session = self._run_pipeline_with_port_outcomes(
                tcp_outcomes=[[], TcpScanFailed("nmap failed")],
                udp_outcomes=[[], []],
                close_session_side_effect=RuntimeError("database is locked"),
            )

        assert result.overall_status == "PARTIAL"
        assert "session_close" not in {step.name for step in result.steps}
        close_session.assert_called_once()
        assert any(
            "Warning: session could not be closed cleanly: database is locked" in str(call.args[0])
            for call in display.call_args_list
        )

    def test_close_session_failure_warns_without_changing_failed(self):
        result, _, _, close_session = self._run_scan_with_discovery_outcome(
            side_effect=DiscoveryFailed("nmap unavailable"),
            expose_mocks=True,
            close_session_side_effect=RuntimeError("database is locked"),
        )

        assert result.exit_code == 1
        assert "RÉSULTAT : FAILED" in result.output
        assert "Warning: session could not be closed cleanly: database is locked" in result.output
        close_session.assert_called_once()

    def test_empty_findings_ignore_knowledge_base_import_failure(self):
        result, produced, _, _, close_session = self._run_pipeline_with_port_outcomes(
            tcp_outcomes=[[], []],
            udp_outcomes=[[], []],
            explanation_import_error=True,
        )

        explanation_step = next(s for s in result.steps if s.name == "explanation")
        assert len(produced) == 2
        assert result.findings_count == 2
        assert explanation_step.status == "ok"
        assert result.overall_status == "SUCCESS"
        close_session.assert_called_once_with(
            close_session.call_args.args[0], status="completed", discover_status="OK"
        )

    def test_unexpected_pipeline_exception_closes_failed_session(self):
        import core.database as db

        result = PipelineResult()
        host_findings = [
            make_finding(module="device_fingerprint", target_ip="192.168.1.10"),
            make_finding(module="device_fingerprint", target_ip="192.168.1.20"),
        ]
        with ExitStack() as stack:
            stack.enter_context(patch.object(db, "init_db"))
            stack.enter_context(patch.object(db, "save_session"))
            stack.enter_context(patch.object(db, "save_findings"))
            stack.enter_context(patch.object(db, "update_finding_risk_score"))
            close_session = stack.enter_context(patch.object(db, "close_session"))
            stack.enter_context(
                patch("recon.device_fingerprint.fingerprint", return_value=host_findings)
            )
            stack.enter_context(
                patch(
                    "detect.tcp_scan.tcp_scan",
                    side_effect=RuntimeError("unexpected scanner error"),
                )
            )

            with pytest.raises(RuntimeError, match="unexpected scanner error"):
                _run_pipeline("192.168.1.0/24", "normal", None, True, result)

        close_session.assert_called_once_with(
            close_session.call_args.args[0], status="failed", discover_status="OK"
        )

    def _run_scan_with_discovery_outcome(
        self,
        return_value=None,
        side_effect=None,
        expose_mocks=False,
        close_session_side_effect=None,
    ):
        import core.database as db

        with ExitStack() as stack:
            stack.enter_context(patch.object(db, "init_db"))
            stack.enter_context(patch.object(db, "save_session"))
            stack.enter_context(patch.object(db, "save_findings"))
            stack.enter_context(patch.object(db, "update_finding_risk_score"))
            close_session = stack.enter_context(
                patch.object(db, "close_session", side_effect=close_session_side_effect)
            )
            tcp_scan = stack.enter_context(patch("detect.tcp_scan.tcp_scan", return_value=[]))
            udp_scan = stack.enter_context(patch("detect.udp_scan.udp_scan", return_value=[]))
            stack.enter_context(
                patch(
                    "recon.device_fingerprint.fingerprint",
                    return_value=return_value,
                    side_effect=side_effect,
                )
            )
            stack.enter_context(
                patch("core.risk_scorer.score_findings", return_value=[])
            )
            stack.enter_context(
                patch("core.risk_scorer.get_global_score", return_value=None)
            )
            stack.enter_context(
                patch("knowledge.knowledge_base.get_explanation_for_finding", return_value=None)
            )

            result = runner.invoke(
                app,
                ["scan", "--target", "192.168.1.0/24"],
                input="y\n",
            )
            if expose_mocks:
                return result, tcp_scan, udp_scan, close_session
            return result

    def test_discover_success_with_multiple_hosts_is_ok(self):
        findings = [
            make_finding(module="device_fingerprint", target_ip="192.168.1.10"),
            make_finding(module="device_fingerprint", target_ip="192.168.1.20"),
        ]
        result = self._run_scan_with_discovery_outcome(return_value=findings)

        assert result.exit_code == 0
        assert "discover [OK]" in result.output
        assert "2 host(s) found" in result.output
        assert "EMPTY" not in result.output

    def test_discover_success_with_no_hosts_is_empty(self):
        result, tcp_scan, udp_scan, close_session = self._run_scan_with_discovery_outcome(
            return_value=[], expose_mocks=True
        )

        assert result.exit_code == 0
        assert "discover [EMPTY]" in result.output
        assert "EMPTY: discovery succeeded with 0 hosts" in result.output
        tcp_scan.assert_not_called()
        udp_scan.assert_not_called()
        close_session.assert_called_once_with(
            close_session.call_args.args[0], status="completed", discover_status="EMPTY"
        )

    def test_discover_user_cancellation_is_cancelled(self):
        result, tcp_scan, udp_scan, close_session = self._run_scan_with_discovery_outcome(
            side_effect=DiscoveryCancelled("user refused discovery"),
            expose_mocks=True,
        )

        assert result.exit_code == 0
        assert "discover [CANCELLED]" in result.output
        assert "EMPTY" not in result.output
        tcp_scan.assert_not_called()
        udp_scan.assert_not_called()
        close_session.assert_called_once_with(
            close_session.call_args.args[0], status="completed", discover_status="CANCELLED"
        )

    def test_discover_tool_failure_is_failed(self):
        result, tcp_scan, udp_scan, close_session = self._run_scan_with_discovery_outcome(
            side_effect=DiscoveryFailed("nmap unavailable"),
            expose_mocks=True,
        )

        assert result.exit_code == 1
        assert "discover [FAILED]" in result.output
        assert "RÉSULTAT : FAILED" in result.output
        assert "EMPTY" not in result.output
        tcp_scan.assert_not_called()
        udp_scan.assert_not_called()
        close_session.assert_called_once_with(
            close_session.call_args.args[0], status="failed", discover_status="FAILED"
        )

    def test_scan_confirmed_creates_session(self):
        """A positive confirmation runs the complete pipeline without network I/O."""
        result, _, _ = self._run_scan_with_stubbed_pipeline("192.168.1.1", "normal")
        assert "Session:" in result.output

    def test_scan_counter_matches_successfully_persisted_findings(self):
        result, produced, _, _, _ = self._run_pipeline_with_port_outcomes(
            tcp_outcomes=[[], []],
            udp_outcomes=[[], []],
        )

        # Two discovery Findings were persisted even though no port Finding
        # existed. The displayed counter must reflect both persisted rows.
        assert result.findings_count == 2
        assert len(produced) == 2

    def test_scan_counter_for_single_finding(self):
        finding = make_finding(module="device_fingerprint", target_ip="192.168.1.10")
        result = self._run_scan_with_discovery_outcome(return_value=[finding])

        assert result.exit_code == 0
        # This scan produced and persisted exactly one Finding.
        assert "Findings: 1" in result.output

    def test_scan_counter_for_multiple_modules(self):
        tcp_finding = make_finding(
            module="tcp_scan", target_ip="192.168.1.10", target_port=9999,
            target_service="custom-tcp",
        )
        udp_finding = make_finding(
            module="udp_scan", target_ip="192.168.1.20", target_port=9998,
            target_service="custom-udp",
        )
        result, produced, _, _, _ = self._run_pipeline_with_port_outcomes(
            tcp_outcomes=[[tcp_finding], [tcp_finding]],
            udp_outcomes=[[udp_finding], [udp_finding]],
            scored_findings=[tcp_finding, udp_finding],
        )

        assert result.findings_count == 4  # 2 discovery + TCP + UDP
        assert len({finding.id for finding in produced}) == 4

    def test_scan_with_empty_discovery_reports_zero_persisted_findings(self):
        result, _, _, close_session = self._run_scan_with_discovery_outcome(
            return_value=[], expose_mocks=True
        )

        assert "Findings: 0" in result.output
        close_session.assert_called_once()

    def test_scan_stealth_profile_accepted(self):
        """The stealth profile is accepted and reaches the stubbed pipeline."""
        result, _, _ = self._run_scan_with_stubbed_pipeline("10.0.0.0/24", "stealth")
        assert "Profile: stealth" in result.output

    def test_scan_verifies_remaining_pipeline_calls(self):
        (
            result,
            _,
            score_findings,
            enrich_findings,
            detect_misconfigs,
            save_findings,
        ) = self._run_scan_with_stubbed_pipeline(
            "192.168.1.1",
            "normal",
            expose_mocks=True,
        )

        assert result.exit_code == 0
        enrich_findings.assert_called_once()
        enriched_findings = enrich_findings.call_args.args[0]
        session_id = detect_misconfigs.call_args.args[1]
        detect_misconfigs.assert_called_once_with(enriched_findings, session_id)
        score_findings.assert_called_once_with(enriched_findings)
        assert save_findings.call_count == 3
        assert save_findings.call_args_list[1].args[0] == enriched_findings
        assert save_findings.call_args_list[2].args[0] == score_findings.return_value

    def test_scan_yes_skips_global_confirmation(self):
        result, _, _ = self._run_scan_with_stubbed_pipeline(
            "192.168.1.1",
            "normal",
            use_yes=True,
        )

        assert result.exit_code == 0
        assert "Start full scan" not in result.output

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
        knowledge_base.assert_called_once_with("tcp_scan", "smb", cve_refs=[])
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

        def knowledge_base_side_effect(module, target_service, cve_refs=None):
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
        assert "RÉSULTAT : PARTIAL" in result.output
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

        assert len(produced) == 2
        assert finding.id in {item.id for item in produced}
        assert result.findings_count == 2
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
        assert "HIGH" in rendered_table and "2" in rendered_table


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

        f = make_finding()
        with patch.object(db, "get_db_path", side_effect=mock_db_path):
            db.init_db("session-001")
            db.save_session("session-001", target="192.168.1.1")
            db.save_finding(f)
            result = runner.invoke(app, ["findings", "list", "--session", "session-001"])

        assert result.exit_code == 0
        assert "tcp_scan" in result.output
        assert format_finding_id(f.id) in result.output
        assert f.id not in result.output

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
                ["findings", "show", "FD-XXXXXXXX", "--session", "session-001"],
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

    def test_findings_show_accepts_user_facing_id(self, tmp_path):
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
                ["findings", "show", format_finding_id(f.id), "--session", "session-001"],
            )

        assert result.exit_code == 0
        assert "192.168.1.1" in result.output
        assert format_finding_id(f.id) in result.output

    def test_findings_show_reports_ambiguous_user_facing_id(self, tmp_path):
        import core.database as db

        def mock_db_path(session_id: str) -> Path:
            d = tmp_path / ".netlab" / "sessions"
            d.mkdir(parents=True, exist_ok=True)
            return d / f"{session_id}.db"

        first = make_finding(target_ip="192.168.1.10")
        second = make_finding(target_ip="192.168.1.11")
        with patch.object(db, "get_db_path", side_effect=mock_db_path), \
             patch.object(db, "format_finding_id", return_value="FD-1234ABCD"), \
             patch("core.finding.format_finding_id", return_value="FD-1234ABCD"):
            db.init_db("session-001")
            db.save_session("session-001", target="192.168.1.0/24")
            db.save_finding(first)
            db.save_finding(second)
            result = runner.invoke(
                app,
                ["findings", "show", "FD-1234ABCD", "--session", "session-001"],
            )

        assert result.exit_code == 1
        assert "ambiguous" in result.output.lower()
        assert first.id in result.output
        assert second.id in result.output
        assert "internal" in result.output.lower()
        assert "ID" in result.output


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
                ["findings", "explain", format_finding_id(f.id), "--session", "session-001"],
            )

        assert result.exit_code == 0
        assert "SMBv1" in result.output

    def test_explain_no_explanation(self, tmp_path):
        """explanation=None and no matching KB rule must show a clear message."""
        import core.database as db

        def mock_db_path(session_id: str) -> Path:
            d = tmp_path / ".netlab" / "sessions"
            d.mkdir(parents=True, exist_ok=True)
            return d / f"{session_id}.db"

        # Use a module and service with no KB entry to guarantee no explanation.
        f = make_finding(
            module="unknown_module_xyz",
            target_service="unknown_service_xyz",
            explanation=None,
        )
        with patch.object(db, "get_db_path", side_effect=mock_db_path):
            db.init_db("session-001")
            db.save_session("session-001", target="192.168.1.1")
            db.save_finding(f)
            result = runner.invoke(
                app,
                ["findings", "explain", format_finding_id(f.id), "--session", "session-001"],
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

    def test_sentinel_status_does_not_require_session(self):
        with patch("sentinel.sentinel_manager.display_status") as mock_status:
            result = runner.invoke(app, ["sentinel", "status"])
        assert result.exit_code == 0
        mock_status.assert_called_once_with(None)

    def test_sentinel_status_accepts_network(self):
        with patch("sentinel.sentinel_manager.display_status") as mock_status:
            result = runner.invoke(
                app,
                ["sentinel", "status", "--network", "net-abc"],
            )
        assert result.exit_code == 0
        mock_status.assert_called_once_with("net-abc")

    def test_sentinel_status_renders_controlled_missing_network_error(self):
        with patch(
            "sentinel.sentinel_manager.display_status",
            side_effect=ValueError("No known Sentinel network is available."),
        ):
            result = runner.invoke(app, ["sentinel", "status"])
        assert result.exit_code == 0
        assert "Sentinel status unavailable" in result.output

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
    def test_cleanup_session_cancelled(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        sessions = tmp_path / ".netlab" / "sessions"
        sessions.mkdir(parents=True)
        db_path = sessions / "session-001.db"
        db_path.write_bytes(b"db")
        result = runner.invoke(
            app,
            ["cleanup", "--session", "session-001"],
            input="n\n",
        )
        assert result.exit_code == 0
        assert "cancelled" in result.output.lower()
        assert db_path.exists()

    def test_cleanup_session_yes_deletes_db(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        sessions = tmp_path / ".netlab" / "sessions"
        sessions.mkdir(parents=True)
        db_path = sessions / "session-001.db"
        db_path.write_bytes(b"db")
        result = runner.invoke(
            app,
            ["cleanup", "--session", "session-001"],
            input="yes\n",
        )
        assert result.exit_code == 0
        assert not db_path.exists()

    def test_cleanup_session_partial_exits_one(self, monkeypatch):
        from cleanup.restore import RestoreStatus
        monkeypatch.setattr(
            "cleanup.restore.restore_session",
            lambda _sid: RestoreStatus.PARTIAL,
        )
        result = runner.invoke(
            app,
            ["cleanup", "--session", "session-001"],
        )
        assert result.exit_code == 1

    def test_cleanup_invalid_session_exits_one(self):
        result = runner.invoke(app, ["cleanup", "--session", "../evil"])
        assert result.exit_code == 1

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
