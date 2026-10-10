"""CLI coherence regression tests: real temporary SQLite, simulated scanners.

No network scans are performed. The OS tests exercise the real discovery path
with only the subprocess boundary replaced.
"""
import dataclasses
import subprocess
from unittest.mock import Mock

import pytest
import typer
from typer.testing import CliRunner

import cli
import core.database as db
import recon.device_fingerprint as discovery
from core.finding import Finding, Evidence, Severity, Confidence
from detect.tcp_scan import TcpScanCancelled, TcpScanFailed
from detect.udp_scan import UdpScanCancelled

SID = "coherence-test"
IPS = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]


def finding(ip=IPS[0], module="tcp_scan", **kw):
    return Finding(session_id=SID, module=module, target_ip=ip,
                   severity=kw.pop("severity", Severity.INFO),
                   confidence=Confidence.CONFIRMED,
                   evidence=Evidence(raw="simulated", command="test"), **kw)


@pytest.fixture
def pipeline(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "get_db_path", lambda sid: tmp_path / f"{sid}.db")
    hosts = [finding(ip, "device_fingerprint") for ip in IPS]
    monkeypatch.setattr(discovery, "fingerprint", Mock(return_value=hosts))
    monkeypatch.setattr("detect.tcp_scan.tcp_scan", Mock(side_effect=lambda ip, *a, **k: [finding(ip)]))
    monkeypatch.setattr("detect.udp_scan.udp_scan", Mock(return_value=[]))
    monkeypatch.setattr("detect.service_detection.enrich_findings", lambda items, **kw: items)
    monkeypatch.setattr("detect.misconfig_detection.detect_misconfigs", Mock(return_value=[]))
    monkeypatch.setattr("knowledge.knowledge_base.get_explanation_for_finding", lambda *a, **k: None)
    monkeypatch.setattr("core.risk_scorer.score_findings", lambda items: items)
    monkeypatch.setattr("core.risk_scorer.get_global_score", lambda items: None)

    def run(result=None):
        result = result if result is not None else cli.PipelineResult()
        produced = cli._run_pipeline("192.0.2.0/24", "normal", SID, True, result)
        return result, produced
    return run


def summary(monkeypatch, result, produced):
    calls = []
    monkeypatch.setattr(cli, "display", calls.append)
    cli._render_scan_summary(result, produced)
    return "\n".join(str(x) for x in calls), calls


@pytest.mark.parametrize("old_count", [0, 10])
def test_current_and_session_counts(pipeline, monkeypatch, old_count):
    db.init_db(SID)
    db.save_session(SID, target="192.0.2.0/24")
    db.save_findings([finding("198.51.100.1") for _ in range(old_count)])
    result, produced = pipeline()
    text, _ = summary(monkeypatch, result, produced)
    assert "Findings de sécurité enregistrés pendant le scan actuel : 3" in text
    assert "Observations d’inventaire enregistrées pendant le scan actuel : 3" in text
    assert f"Findings de sécurité présents dans la session : {old_count + 3}" in text
    assert "Observations d’inventaire présentes dans la session : 3" in text
    assert f"Total des résultats présents dans la session : {old_count + 6} " in text
    assert len(db.get_findings(SID)) == old_count + 6
    assert result.findings_count == 6
    assert db.get_session(SID)["status"] == "completed"


def test_existing_ids_count_as_recorded_not_new(pipeline, monkeypatch):
    db.init_db(SID)
    db.save_session(SID, target="192.0.2.0/24")
    old = finding()
    inventory = finding(module="device_fingerprint")
    db.save_findings([old, inventory])
    updated = dataclasses.replace(old, severity=Severity.MEDIUM)
    monkeypatch.setattr(discovery, "fingerprint", Mock(return_value=[inventory]))
    monkeypatch.setattr("detect.tcp_scan.tcp_scan", Mock(return_value=[updated]))
    result, produced = pipeline()
    text, _ = summary(monkeypatch, result, produced)
    assert "Findings de sécurité enregistrés pendant le scan actuel : 1" in text
    assert "Observations d’inventaire enregistrées pendant le scan actuel : 1" in text
    assert "Findings de sécurité présents dans la session : 1" in text
    assert "Total des résultats présents dans la session : 2 " in text
    assert "nouveaux" not in text.lower()
    assert {f.id for f in db.get_findings(SID)} == {old.id, inventory.id}


def test_summary_severity_excludes_inventory(monkeypatch):
    items = ([finding(module="device_fingerprint") for _ in range(13)]
             + [finding() for _ in range(14)]
             + [finding(severity=Severity.MEDIUM) for _ in range(2)])
    result = cli.PipelineResult(session_findings=items, findings_count=29)
    text, calls = summary(monkeypatch, result, items)
    table = next(c for c in calls if isinstance(c, cli.Table))
    counts = dict(zip(table.columns[0]._cells, table.columns[1]._cells))
    assert counts["INFO"] == "14"
    assert counts["MEDIUM"] == "2"
    assert "scan actuel : 16" in text and "scan actuel : 13" in text
    assert "29 (sécurité : 16, inventaire : 13)" in text


@pytest.mark.parametrize("outcome,status,discovery_status", [
    ([], "completed", "EMPTY"),
    (discovery.DiscoveryCancelled("refused"), "partial", "CANCELLED"),
    (discovery.DiscoveryFailed("timeout"), "failed", "FAILED"),
])
def test_discover_terminal_states(pipeline, monkeypatch, outcome, status, discovery_status):
    fake = Mock(side_effect=outcome) if isinstance(outcome, Exception) else Mock(return_value=outcome)
    monkeypatch.setattr(discovery, "fingerprint", fake)
    result, produced = pipeline()
    assert db.get_session(SID)["status"] == status
    assert db.get_session(SID)["discover_status"] == discovery_status
    assert produced == []
    assert db.get_scan_outcomes(SID) == []
    assert result.overall_status == {"completed": "SUCCESS", "partial": "PARTIAL", "failed": "FAILED"}[status]


@pytest.mark.parametrize("module,cancel", [("tcp_scan", TcpScanCancelled), ("udp_scan", UdpScanCancelled)])
@pytest.mark.parametrize("partial", [False, True])
def test_port_cancellations(pipeline, monkeypatch, module, cancel, partial):
    outcomes = [[], cancel("refused"), cancel("refused")] if partial else [cancel("refused") for _ in IPS]
    monkeypatch.setattr(f"detect.{module}.{module}", Mock(side_effect=outcomes))
    result, _ = pipeline()
    step = next(s for s in result.steps if s.name == module)
    assert step.status == ("partial" if partial else "cancelled")
    assert result.overall_status == "PARTIAL"
    assert db.get_session(SID)["status"] == "partial"
    rows = [r for r in db.get_scan_outcomes(SID) if r["module"] == module]
    assert sum(r["outcome"] == "cancelled" for r in rows) == (2 if partial else 3)
    assert len([f for f in db.get_findings(SID) if f.module == "device_fingerprint"]) == 3


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt, typer.Abort])
@pytest.mark.parametrize("stage", ["discover", "tcp_scan", "udp_scan", "cve_enrichment", "misconfig_detection", "explanation", "risk_scoring", "persist"])
def test_interruptions_close_partial_and_propagate(pipeline, monkeypatch, interrupt, stage):
    result = cli.PipelineResult()
    if stage == "discover":
        monkeypatch.setattr(discovery, "fingerprint", Mock(side_effect=interrupt()))
    elif stage in ("tcp_scan", "udp_scan"):
        monkeypatch.setattr(f"detect.{stage}.{stage}", Mock(side_effect=[[finding(module=stage)], interrupt()]))
    else:
        paths = {
            "cve_enrichment": "detect.service_detection.enrich_findings",
            "misconfig_detection": "detect.misconfig_detection.detect_misconfigs",
            "explanation": "knowledge.knowledge_base.get_explanation_for_finding",
            "risk_scoring": "core.risk_scorer.score_findings",
        }
        if stage == "persist":
            real_save = db.save_findings
            count = 0
            def save(items):
                nonlocal count
                count += 1
                if count == 5:  # discovery, three TCP saves, final save
                    raise interrupt()
                real_save(items)
            monkeypatch.setattr(db, "save_findings", save)
        else:
            monkeypatch.setattr(paths[stage], Mock(side_effect=interrupt()))
    with pytest.raises(interrupt):
        pipeline(result)
    session = db.get_session(SID)
    assert session["status"] == "partial"
    assert session["end_time"] is not None
    assert result.overall_status == "PARTIAL"
    assert result.steps[-1].name == stage and result.steps[-1].status == "cancelled"
    stored = db.get_findings(SID)
    assert len(stored) >= (0 if stage == "discover" else 3)
    assert {f.id for f in result.current_findings} == {f.id for f in stored}
    if stage in ("tcp_scan", "udp_scan"):
        rows = [r for r in db.get_scan_outcomes(SID) if r["module"] == stage]
        assert sorted(r["outcome"] for r in rows) == ["cancelled", "completed"]
        assert any(f.module == stage for f in stored)
    if stage == "discover":
        assert session["discover_status"] == "CANCELLED"


@pytest.mark.parametrize("fail_count,expected", [(0, "ok"), (1, "partial"), (3, "failed")])
def test_misconfig_states_and_preservation(pipeline, monkeypatch, fail_count, expected):
    monkeypatch.setattr("detect.misconfig_detection.detect_misconfigs", Mock(
        side_effect=[RuntimeError("module failure") for _ in range(fail_count)] + [[] for _ in range(3-fail_count)]))
    result, _ = pipeline()
    step = next(s for s in result.steps if s.name == "misconfig_detection")
    assert step.status == expected
    assert result.overall_status == ("SUCCESS" if not fail_count else "PARTIAL")
    assert db.get_session(SID)["status"] == ("completed" if not fail_count else "partial")
    assert len(db.get_findings(SID)) == 6


@pytest.mark.parametrize("steps", [1, 2])
def test_failure_count_is_steps_not_hosts(monkeypatch, steps):
    result = cli.PipelineResult()
    for module in ["tcp_scan", "udp_scan"][:steps]:
        result.add(module, "partial", "9/13 hosts scanned — 4 failed", failed_hosts=IPS + ["192.0.2.4"])
    text, _ = summary(monkeypatch, result, [])
    assert result.failure_count == steps
    assert f"{steps} " + ("étape en échec ou partiellement exécutée" if steps == 1 else "étapes en échec ou partiellement exécutées") in text
    assert "opération(s)" not in text
    for ip in IPS:
        assert ip in text


def test_session_read_failure_is_unknown_not_zero(pipeline, monkeypatch):
    monkeypatch.setattr(db, "get_findings", Mock(side_effect=OSError("read error")))
    result, produced = pipeline()
    text, _ = summary(monkeypatch, result, produced)
    assert "scan actuel : 3" in text
    assert "Total des résultats présents dans la session : indisponible" in text


REAL_FINGERPRINT = discovery.fingerprint
PING = '<nmaprun>' + ''.join(f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/></host>' for ip in IPS) + '</nmaprun>'
OS = '<nmaprun/>'


def test_os_timeout_keeps_all_hosts_and_continues(pipeline, monkeypatch):
    monkeypatch.setattr(discovery, "fingerprint", REAL_FINGERPRINT)
    ips = IPS + ["192.0.2.4"]
    ping = PING.replace('</nmaprun>', '<host><status state="up"/><address addr="192.0.2.4" addrtype="ipv4"/></host></nmaprun>')
    fake = Mock(side_effect=[subprocess.CompletedProcess([], 0, ping, ''),
        subprocess.CompletedProcess([], 0, OS, ''),
        subprocess.CompletedProcess([], 0, OS, ''), subprocess.TimeoutExpired('nmap', 60),
        subprocess.CompletedProcess([], 0, OS, '')])
    monkeypatch.setattr(discovery.subprocess, "run", fake)
    result, _ = pipeline()
    hosts = [f for f in db.get_findings(SID) if f.module == "device_fingerprint"]
    assert {f.target_ip for f in hosts} == set(ips)
    assert all(f.service_version == "" for f in hosts)
    assert fake.call_count == 5
    assert result.overall_status == "SUCCESS"
    assert len(db.get_scan_outcomes(SID)) == 8


def test_ping_timeout_is_fatal(pipeline, monkeypatch):
    monkeypatch.setattr(discovery, "fingerprint", REAL_FINGERPRINT)
    fake = Mock(side_effect=subprocess.TimeoutExpired('nmap', 300))
    monkeypatch.setattr(discovery.subprocess, "run", fake)
    result, _ = pipeline()
    assert result.overall_status == "FAILED"
    assert db.get_session(SID)["status"] == "failed"
    assert db.get_findings(SID) == []
    assert fake.call_count == 1


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, typer.Abort])
def test_os_unexpected_errors_are_not_masked(pipeline, monkeypatch, error):
    monkeypatch.setattr(discovery, "fingerprint", REAL_FINGERPRINT)
    monkeypatch.setattr(discovery.subprocess, "run", Mock(side_effect=[
        subprocess.CompletedProcess([], 0, PING, ''), error()]))
    result = cli.PipelineResult()
    with pytest.raises(error):
        pipeline(result)
    assert db.get_session(SID)["status"] == ("failed" if error is RuntimeError else "partial")


@pytest.mark.parametrize("error", [KeyboardInterrupt, typer.Abort])
def test_cli_shows_interruption_summary(pipeline, monkeypatch, error):
    monkeypatch.setattr("detect.tcp_scan.tcp_scan", Mock(side_effect=error()))
    result = CliRunner().invoke(cli.app, ["scan", "--target", IPS[0], "--session", SID, "--yes"])
    assert result.exit_code != 0
    assert "RÉSULTAT : PARTIAL" in result.output
    assert "tcp_scan [CANCELLED]" in result.output
    assert db.get_session(SID)["status"] == "partial"


@pytest.mark.parametrize("error", [FileNotFoundError("nmap"), OSError("launch failed"),
                                   UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad output")])
def test_os_environment_failure_keeps_hosts(pipeline, monkeypatch, error):
    monkeypatch.setattr(discovery, "fingerprint", REAL_FINGERPRINT)
    fake = Mock(side_effect=[subprocess.CompletedProcess([], 0, PING, ''), error,
                            subprocess.CompletedProcess([], 0, OS, ''),
                            subprocess.CompletedProcess([], 0, OS, '')])
    monkeypatch.setattr(discovery.subprocess, "run", fake)
    result, _ = pipeline()
    assert result.overall_status == "SUCCESS"
    assert len([f for f in db.get_findings(SID) if f.module == "device_fingerprint"]) == 3
    assert fake.call_count == 4


def test_empty_current_scan_still_reports_old_session(pipeline, monkeypatch):
    db.init_db(SID)
    db.save_session(SID, target=IPS[0])
    db.save_findings([finding(), finding(module="device_fingerprint")])
    monkeypatch.setattr(discovery, "fingerprint", Mock(return_value=[]))
    result, produced = pipeline()
    text, _ = summary(monkeypatch, result, produced)
    assert "Findings de sécurité enregistrés pendant le scan actuel : 0" in text
    assert "Observations d’inventaire enregistrées pendant le scan actuel : 0" in text
    assert "Findings de sécurité présents dans la session : 1" in text
    assert "Observations d’inventaire présentes dans la session : 1" in text
    assert "Total des résultats présents dans la session : 2 " in text


def test_final_save_failure_counts_only_persisted_results(pipeline, monkeypatch):
    extra = finding(module="misconfig_detection.test")
    monkeypatch.setattr("detect.misconfig_detection.detect_misconfigs", Mock(return_value=[extra]))
    real_save = db.save_findings
    calls = 0
    def save(items):
        nonlocal calls
        calls += 1
        if calls == 5:
            raise OSError("disk failure")
        real_save(items)
    monkeypatch.setattr(db, "save_findings", save)
    result, produced = pipeline()
    assert result.overall_status == "PARTIAL"
    assert len(produced) == 6
    assert extra.id not in {f.id for f in db.get_findings(SID)}
    text, _ = summary(monkeypatch, result, produced)
    assert "Findings de sécurité enregistrés pendant le scan actuel : 3" in text
    assert "Total des résultats présents dans la session : 6 " in text


def test_four_tcp_failures_are_one_degraded_step(pipeline, monkeypatch):
    hosts = [finding(f"192.0.2.{i}", "device_fingerprint") for i in range(1, 14)]
    monkeypatch.setattr(discovery, "fingerprint", Mock(return_value=hosts))
    monkeypatch.setattr("detect.tcp_scan.tcp_scan", Mock(side_effect=[[] for _ in range(9)] +
        [TcpScanFailed("failed") for _ in range(4)]))
    result, produced = pipeline()
    tcp = next(s for s in result.steps if s.name == "tcp_scan")
    assert tcp.status == "partial"
    assert "9/13 hosts scanned — 4 failed" == tcp.detail
    assert len(tcp.failed_hosts) == 4
    assert result.failure_count == 1
    assert result.overall_status == "PARTIAL"
    rows = [r for r in db.get_scan_outcomes(SID) if r["module"] == "tcp_scan"]
    assert sum(r["outcome"] == "failed" for r in rows) == 4
    assert sum(r["outcome"] == "completed" for r in rows) == 9
    text, _ = summary(monkeypatch, result, produced)
    for ip in tcp.failed_hosts:
        assert ip in text


def test_interruption_keeps_preceding_failed_host_detail(pipeline, monkeypatch):
    monkeypatch.setattr("detect.tcp_scan.tcp_scan", Mock(side_effect=[TcpScanFailed("failed"), KeyboardInterrupt()]))
    result = cli.PipelineResult()
    with pytest.raises(KeyboardInterrupt):
        pipeline(result)
    step = result.steps[-1]
    assert len(step.failed_hosts) == 1
    assert "1 failed" in step.detail
    text, _ = summary(monkeypatch, result, result.current_findings)
    assert step.failed_hosts[0] in text


@pytest.mark.parametrize("stage", ["discover", "tcp_scan"])
def test_cli_unexpected_error_preserves_original_and_stored_state(pipeline, monkeypatch, stage):
    error = RuntimeError("unexpected-original")
    if stage == "discover":
        monkeypatch.setattr(discovery, "fingerprint", Mock(side_effect=error))
    else:
        monkeypatch.setattr("detect.tcp_scan.tcp_scan", Mock(side_effect=[
            [finding()], error]))
    calls = []
    monkeypatch.setattr(cli, "display", calls.append)
    # Call the command boundary directly to verify exception object identity.
    with pytest.raises(RuntimeError) as caught:
        cli.scan(target=IPS[0], profile="normal", session=SID, yes=True)
    assert caught.value is error
    session = db.get_session(SID)
    assert session["status"] == "failed"
    assert session["end_time"] is not None
    text = "\n".join(str(c) for c in calls)
    assert SID in text
    assert "RÉSULTAT : SUCCESS" not in text
    if stage == "discover":
        assert session["discover_status"] == "FAILED"
        assert "RÉSULTAT : FAILED" in text
        assert "discover [FAILED]" in text
    else:
        assert session["discover_status"] == "OK"
        assert "Erreur inattendue du pipeline" in text
        assert "RÉSULTAT :" not in text
        stored = db.get_findings(SID)
        assert len(stored) == 4  # three inventory observations and the first TCP
        rows = [r for r in db.get_scan_outcomes(SID) if r["module"] == "tcp_scan"]
        assert sorted(r["outcome"] for r in rows) == ["completed", "failed"]


@pytest.mark.parametrize("original", [RuntimeError("original"), KeyboardInterrupt(), typer.Abort()])
def test_render_failure_does_not_replace_original(pipeline, monkeypatch, original):
    monkeypatch.setattr(discovery, "fingerprint", Mock(side_effect=original))
    render = Mock(side_effect=ValueError("render failure must not escape"))
    monkeypatch.setattr(cli, "_render_scan_summary", render)
    with pytest.raises(type(original)) as caught:
        cli.scan(target=IPS[0], profile="normal", session=SID, yes=True)
    assert caught.value is original
    render.assert_called_once()
    assert db.get_session(SID)["status"] == ("failed" if type(original) is RuntimeError else "partial")


def test_minimal_diagnostic_failure_preserves_original(pipeline, monkeypatch):
    original = RuntimeError("original outside discovery")
    monkeypatch.setattr("detect.tcp_scan.tcp_scan", Mock(side_effect=original))
    original_display = cli.display
    def display(item):
        if isinstance(item, str) and "Erreur inattendue du pipeline" in item:
            raise OSError("output unavailable")
        original_display(item)
    monkeypatch.setattr(cli, "display", display)
    with pytest.raises(RuntimeError) as caught:
        cli.scan(target=IPS[0], profile="normal", session=SID, yes=True)
    assert caught.value is original
    assert db.get_session(SID)["status"] == "failed"


def test_real_cli_subprocess_reports_discover_failure(tmp_path):
    """Real Typer invocation; simulated discovery, no network, temporary DB."""
    import os
    import sqlite3
    import sys
    from pathlib import Path

    code = f'''
from pathlib import Path
from unittest.mock import patch
import cli
import core.database as db
with patch.object(db, "get_db_path", side_effect=lambda sid: Path({str(tmp_path)!r}) / (sid + ".db")), patch("recon.device_fingerprint.fingerprint", side_effect=RuntimeError("DISCOVER_ORIGINAL_SUBPROCESS")):
    cli.app()
'''
    child = subprocess.run(
        [sys.executable, "-c", code, "scan", "--target", IPS[0], "--session", SID, "--yes"],
        cwd=Path(cli.__file__).resolve().parent,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "NO_COLOR": "1", "COLUMNS": "120"},
        capture_output=True, text=True, timeout=30,
    )
    assert child.returncode == 1
    assert "RÉSULTAT : FAILED" in child.stdout
    assert "discover [FAILED]" in child.stdout
    assert SID in child.stdout
    assert "RuntimeError: DISCOVER_ORIGINAL_SUBPROCESS" in child.stderr
    assert "RÉSULTAT : SUCCESS" not in child.stdout
    with sqlite3.connect(f"file:{tmp_path / (SID + '.db')}?mode=ro", uri=True) as conn:
        assert conn.execute("SELECT status, discover_status, end_time IS NOT NULL FROM sessions").fetchone() == ("failed", "FAILED", 1)
