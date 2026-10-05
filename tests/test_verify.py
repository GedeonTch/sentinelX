"""Tests for targeted VERIFY orchestration."""

from pathlib import Path
from unittest.mock import patch

import pytest

import core.database as db
from cli import _finding_fingerprint, _run_verify, app
from typer.testing import CliRunner
from core.finding import (
    Category,
    Confidence,
    Evidence,
    Explanation,
    Exposure,
    Finding,
    FindingStatus,
    Severity,
    format_finding_id,
)
from core.risk_scorer import score_findings
from detect.tcp_scan import TcpPortScanResult, _parse_tcp_xml_with_states

SESSION = "verify-session"
runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated_db(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(db, "get_db_path", lambda session_id: tmp_path / f"{session_id}.db")
    db.init_db(SESSION)
    db.save_session(SESSION, target="192.168.10.0/24", profile="normal")


def _tcp_result(findings, states=None):
    if states is None:
        states = {item.target_port: "open" for item in findings if item.target_port is not None}
    return TcpPortScanResult(findings=findings, states=states)


def make_finding(module="tcp_scan", port=23, service="telnet", status=FindingStatus.OPEN):
    return Finding(
        session_id=SESSION,
        module=module,
        target_ip="192.168.10.10",
        target_port=port,
        target_service=service,
        category=Category.SERVICE if module in ("tcp_scan", "udp_scan") else Category.CONFIG,
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        evidence=Evidence(raw="controlled evidence", command="controlled command"),
        status=status,
    )


def test_fingerprint_is_stable_and_contextual():
    session = db.get_session(SESSION)
    finding = make_finding()
    same = make_finding()
    same.id = "different-uuid"
    changed_module = make_finding(module="udp_scan")

    assert _finding_fingerprint(finding, session) == _finding_fingerprint(same, session)
    assert _finding_fingerprint(finding, session) != _finding_fingerprint(changed_module, session)

    other_session = dict(session, id="other-session", target="192.168.20.0/24")
    assert _finding_fingerprint(finding, session) != _finding_fingerprint(finding, other_session)


def test_targeted_tcp_verify_keeps_open_finding_and_session_fields():
    original = make_finding()
    db.save_finding(original)
    before = db.get_session(SESSION)

    current = make_finding()
    current.id = "new-scanner-id"
    with patch("detect.tcp_scan.tcp_scan_port_state", return_value=_tcp_result([current], {23: "open"})) as scan:
        result = _run_verify(SESSION, original.id)

    scan.assert_called_once_with(
        "192.168.10.10", SESSION, profile="normal", ports="23", auto_confirm=True
    )
    stored = db.get_finding_by_id(SESSION, original.id)
    after = db.get_session(SESSION)
    assert result["status"] == "SUCCESS"
    assert result["still_present"]
    assert stored.status == FindingStatus.OPEN
    assert after["status"] == before["status"]
    assert after["discover_status"] == before["discover_status"]


def _rich_finding(status=FindingStatus.OPEN):
    return Finding(
        session_id=SESSION,
        module="tcp_scan",
        target_ip="192.168.10.10",
        target_port=23,
        target_service="telnet",
        category=Category.SERVICE,
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        exposure=Exposure.EXTERNAL,
        evidence=Evidence(raw="historical proof", command="nmap -p 23"),
        explanation=Explanation(what="what", attack="attack", defense="defense"),
        cve_refs=["CVE-2026-0001"],
        cvss_score=8.0,
        remediation_cmd="disable telnet",
        status=status,
    )


def test_still_present_recalculates_current_risk_and_preserves_metadata():
    original = score_findings([_rich_finding()])[0]
    db.save_finding(original)
    current = make_finding()
    current.id = "scanner-generated-id"

    with patch("detect.tcp_scan.tcp_scan_port_state", return_value=_tcp_result([current], {23: "open"})):
        result = _run_verify(SESSION, original.id)

    stored = db.get_finding_by_id(SESSION, original.id)
    assert result["status"] == "SUCCESS"
    assert stored.status == FindingStatus.OPEN
    assert stored.risk_score == 92.0
    assert stored.id == original.id
    assert stored.severity == original.severity
    assert stored.cvss_score == original.cvss_score
    assert stored.cve_refs == original.cve_refs
    assert stored.evidence == original.evidence
    assert stored.explanation == original.explanation
    assert stored.remediation_cmd == original.remediation_cmd


def test_verified_finding_keeps_history_and_reopening_recalculates_risk():
    original = score_findings([_rich_finding()])[0]
    user_id = format_finding_id(original.id)
    db.save_finding(original)
    assert format_finding_id(db.get_finding_by_id(SESSION, original.id).id) == user_id

    with patch("detect.tcp_scan.tcp_scan_port_state", return_value=_tcp_result([], {23: "closed"})):
        result = _run_verify(SESSION, original.id)

    verified = db.get_finding_by_id(SESSION, original.id)
    assert result["status"] == "SUCCESS"
    assert verified.status == FindingStatus.VERIFIED
    assert verified.risk_score == original.risk_score
    assert verified.cvss_score == 8.0
    assert verified.cve_refs == ["CVE-2026-0001"]
    assert verified.evidence == original.evidence
    assert verified.explanation == original.explanation
    assert verified.remediation_cmd == "disable telnet"

    reappeared = make_finding()
    with patch("detect.tcp_scan.tcp_scan_port_state", return_value=_tcp_result([reappeared], {23: "open"})):
        reopened = _run_verify(SESSION, original.id)

    reopened_finding = db.get_finding_by_id(SESSION, original.id)
    assert reopened["status"] == "SUCCESS"
    assert reopened_finding.status == FindingStatus.OPEN
    assert reopened_finding.risk_score == 92.0
    assert reopened_finding.id == original.id
    assert reopened_finding.cve_refs == ["CVE-2026-0001"]


def test_verify_with_identical_data_is_idempotent():
    original = score_findings([_rich_finding()])[0]
    db.save_finding(original)
    current = make_finding()

    with patch("detect.tcp_scan.tcp_scan_port_state", return_value=_tcp_result([current], {23: "open"})):
        first = _run_verify(SESSION, original.id)
    first_stored = db.get_finding_by_id(SESSION, original.id)

    with patch("detect.tcp_scan.tcp_scan_port_state", return_value=_tcp_result([current], {23: "open"})):
        second = _run_verify(SESSION, original.id)
    second_stored = db.get_finding_by_id(SESSION, original.id)

    assert first["status"] == second["status"] == "SUCCESS"
    assert first_stored.to_dict() == second_stored.to_dict()


def test_successful_absence_marks_open_finding_verified():
    original = make_finding()
    db.save_finding(original)

    with patch("detect.tcp_scan.tcp_scan_port_state", return_value=_tcp_result([], {23: "closed"})):
        result = _run_verify(SESSION, original.id)

    stored = db.get_finding_by_id(SESSION, original.id)
    assert result["status"] == "SUCCESS"
    assert [item.id for item in result["verified"]] == [original.id]
    assert stored.status == FindingStatus.VERIFIED


def test_filtered_port_is_partial_and_never_verified():
    original = score_findings([make_finding()])[0]
    db.save_finding(original)

    with patch("detect.tcp_scan.tcp_scan_port_state", return_value=_tcp_result([], {23: "filtered"})):
        result = _run_verify(SESSION, original.id)

    stored = db.get_finding_by_id(SESSION, original.id)
    assert result["status"] == "PARTIAL"
    assert result["inconclusive"][0].id == original.id
    assert stored.status == FindingStatus.OPEN
    assert stored.risk_score == original.risk_score


def test_legacy_empty_tcp_list_is_unknown_not_closed():
    original = make_finding()
    db.save_finding(original)

    with patch("detect.tcp_scan.tcp_scan", return_value=[]):
        result = _run_verify(SESSION, original.id)

    stored = db.get_finding_by_id(SESSION, original.id)
    assert result["status"] == "PARTIAL"
    assert result["inconclusive"][0].id == original.id
    assert stored.status == FindingStatus.OPEN


def test_verified_finding_that_reappears_becomes_open():
    original = make_finding(status=FindingStatus.VERIFIED)
    db.save_finding(original)
    current = make_finding()

    with patch("detect.tcp_scan.tcp_scan_port_state", return_value=_tcp_result([current], {23: "open"})):
        result = _run_verify(SESSION, original.id)

    assert result["status"] == "SUCCESS"
    assert db.get_finding_by_id(SESSION, original.id).status == FindingStatus.OPEN


def test_failed_control_preserves_status_and_current_risk():
    original = score_findings([make_finding()])[0]
    db.save_finding(original)

    from detect.tcp_scan import TcpScanFailed
    with patch("detect.tcp_scan.tcp_scan", side_effect=TcpScanFailed("nmap failed")):
        result = _run_verify(SESSION, original.id)

    stored = db.get_finding_by_id(SESSION, original.id)
    assert result["status"] == "FAILED"
    assert stored.status == FindingStatus.OPEN
    assert stored.risk_score == original.risk_score
    assert result["inconclusive"][0].id == original.id


def test_new_finding_is_persisted_without_merging_with_old_one():
    original = make_finding()
    db.save_finding(original)
    new_finding = make_finding(port=80, service="http")
    new_finding.id = "scanner-generated-id"

    with patch(
        "detect.tcp_scan.tcp_scan_port_state",
        return_value=_tcp_result([new_finding], {23: "closed", 80: "open"}),
    ):
        result = _run_verify(SESSION, original.id)

    stored = db.get_findings(SESSION)
    assert result["status"] == "SUCCESS"
    assert original.id in {item.id for item in result["verified"]}
    assert len(stored) == 2
    assert {item.target_port for item in stored} == {23, 80}
    assert db.get_finding_by_id(SESSION, original.id).status == FindingStatus.VERIFIED


def test_udp_finding_uses_udp_control():
    original = make_finding(module="udp_scan", port=161, service="snmp")
    db.save_finding(original)
    current = make_finding(module="udp_scan", port=161, service="snmp")

    with patch("detect.udp_scan.udp_scan", return_value=[current]) as scan:
        result = _run_verify(SESSION, original.id)

    scan.assert_called_once_with(
        "192.168.10.10", SESSION, profile="normal", ports="161", auto_confirm=True
    )
    assert result["status"] == "SUCCESS"
    assert result["still_present"]


def test_http_misconfig_controls_both_http_ports():
    original = make_finding(
        module="misconfig_detection.http_no_https",
        port=80,
        service="http_no_https",
    )
    db.save_finding(original)
    http = make_finding(module="tcp_scan", port=80, service="http")

    with patch(
        "detect.tcp_scan.tcp_scan_port_state",
        return_value=_tcp_result([http], {80: "open", 443: "closed"}),
    ) as scan:
        result = _run_verify(SESSION, original.id)

    scan.assert_called_once_with(
        "192.168.10.10", SESSION, profile="normal", ports="80,443", auto_confirm=True
    )
    assert result["status"] == "SUCCESS"
    assert result["still_present"]


def test_smb_signing_stays_partial_when_port_445_remains_open():
    original = make_finding(
        module="misconfig_detection.smb_signing_missing",
        port=445,
        service="smb_signing_missing",
    )
    db.save_finding(original)
    smb = make_finding(module="tcp_scan", port=445, service="microsoft-ds")

    with patch(
        "detect.tcp_scan.tcp_scan_port_state",
        return_value=_tcp_result([smb], {445: "open"}),
    ):
        result = _run_verify(SESSION, original.id)

    assert result["status"] == "PARTIAL"
    assert db.get_finding_by_id(SESSION, original.id).status == FindingStatus.OPEN
    assert result["inconclusive"][0].id == original.id


def test_unknown_misconfig_rule_does_not_fallback_to_tcp():
    original = make_finding(
        module="misconfig_detection.unknown_rule",
        port=999,
        service="unknown_rule",
    )
    db.save_finding(original)

    with patch("detect.tcp_scan.tcp_scan") as scan:
        result = _run_verify(SESSION, original.id)

    scan.assert_not_called()
    assert result["status"] == "PARTIAL"
    assert result["inconclusive"][0].id == original.id
    assert db.get_finding_by_id(SESSION, original.id).status == FindingStatus.OPEN


def test_remediated_finding_is_excluded_and_unchanged():
    original = make_finding(status=FindingStatus.REMEDIATED)
    db.save_finding(original)

    with patch("detect.tcp_scan.tcp_scan") as scan:
        result = _run_verify(SESSION)

    scan.assert_not_called()
    assert result["status"] == "PARTIAL"
    assert db.get_finding_by_id(SESSION, original.id).status == FindingStatus.REMEDIATED


def test_tcp_cancellation_preserves_status_and_is_nonconclusive():
    original = make_finding()
    db.save_finding(original)
    from detect.tcp_scan import TcpScanCancelled

    with patch("detect.tcp_scan.tcp_scan", side_effect=TcpScanCancelled("cancelled")):
        result = _run_verify(SESSION, original.id)

    assert result["status"] == "FAILED"
    assert result["inconclusive"][0].id == original.id
    assert db.get_finding_by_id(SESSION, original.id).status == FindingStatus.OPEN


def test_udp_cancellation_preserves_status_and_is_nonconclusive():
    original = make_finding(module="udp_scan", port=161, service="snmp")
    db.save_finding(original)
    from detect.udp_scan import UdpScanCancelled

    with patch("detect.udp_scan.udp_scan", side_effect=UdpScanCancelled("cancelled")):
        result = _run_verify(SESSION, original.id)

    assert result["status"] == "FAILED"
    assert result["inconclusive"][0].id == original.id
    assert db.get_finding_by_id(SESSION, original.id).status == FindingStatus.OPEN


def test_mixed_success_and_partial_is_partial():
    tcp_original = make_finding()
    udp_original = make_finding(module="udp_scan", port=161, service="snmp")
    db.save_finding(tcp_original)
    db.save_finding(udp_original)
    tcp_current = make_finding()
    from detect.udp_scan import UdpScanCancelled

    with patch(
        "detect.tcp_scan.tcp_scan_port_state",
        return_value=_tcp_result([tcp_current], {23: "open"}),
    ), \
         patch("detect.udp_scan.udp_scan", side_effect=UdpScanCancelled("cancelled")):
        result = _run_verify(SESSION)

    assert result["status"] == "PARTIAL"
    assert result["still_present"][0].id == tcp_original.id
    assert result["inconclusive"][0].id == udp_original.id
    assert db.get_finding_by_id(SESSION, tcp_original.id).status == FindingStatus.OPEN
    assert db.get_finding_by_id(SESSION, udp_original.id).status == FindingStatus.OPEN


def test_persistence_error_never_reports_verify_success():
    original = make_finding()
    db.save_finding(original)

    with patch("detect.tcp_scan.tcp_scan_port_state", return_value=_tcp_result([], {23: "closed"})), \
         patch.object(db, "update_finding_status", side_effect=RuntimeError("database locked")):
        result = runner.invoke(
            app,
            ["findings", "rescan", "--session", SESSION, "--finding", original.id],
            input="y\n",
        )

    assert result.exit_code == 1
    assert "VERIFY failed" in result.output
    assert "VERIFY: SUCCESS" not in result.output


def test_global_verify_keeps_unsupported_finding_unchanged():
    supported = make_finding()
    unsupported = make_finding(module="device_fingerprint", port=None, service="host")
    db.save_finding(supported)
    db.save_finding(unsupported)

    with patch("detect.tcp_scan.tcp_scan", return_value=[make_finding()]):
        result = _run_verify(SESSION)

    assert result["status"] == "SUCCESS"
    assert result["inconclusive"] == []
    assert [item.id for item in result["skipped"]] == [unsupported.id]
    assert db.get_finding_by_id(SESSION, unsupported.id).status == FindingStatus.OPEN
    assert db.get_finding_by_id(SESSION, supported.id).status == FindingStatus.OPEN


def test_inventory_only_session_is_not_a_verify_failure():
    inventory = make_finding(module="device_fingerprint", port=None, service="host")
    db.save_finding(inventory)

    result = _run_verify(SESSION)

    assert result["status"] == "SUCCESS"
    assert result["inconclusive"] == []
    assert result["verified"] == []
    assert result["skipped"] == [inventory]
    assert db.get_finding_by_id(SESSION, inventory.id).status == FindingStatus.OPEN


def test_duplicate_current_fingerprint_is_persisted_once():
    original = make_finding()
    db.save_finding(original)
    first = make_finding()
    second = make_finding()
    first.id = "scanner-result-one"
    second.id = "scanner-result-two"

    with patch(
        "detect.tcp_scan.tcp_scan_port_state",
        return_value=_tcp_result([first, second], {23: "open"}),
    ):
        result = _run_verify(SESSION, original.id)

    assert result["status"] == "SUCCESS"
    assert len(db.get_findings(SESSION)) == 1
    assert db.get_findings(SESSION)[0].id == original.id


def test_accepted_finding_is_excluded_and_nonconclusive():
    accepted = make_finding(status=FindingStatus.ACCEPTED)
    db.save_finding(accepted)

    result = _run_verify(SESSION)

    assert result["status"] == "PARTIAL"
    assert result["inconclusive"][0].id == accepted.id
    assert db.get_finding_by_id(SESSION, accepted.id).status == FindingStatus.ACCEPTED


@pytest.mark.parametrize("state", ["open", "closed", "filtered"])
def test_tcp_xml_parser_preserves_port_state(state):
    xml = f"""<?xml version=\"1.0\"?>
<nmaprun><host><address addr=\"192.168.10.10\" addrtype=\"ipv4\"/>
<ports><port protocol=\"tcp\" portid=\"23\"><state state=\"{state}\"/></port></ports>
</host></nmaprun>"""
    findings, states = _parse_tcp_xml_with_states(xml, "192.168.10.10", SESSION)
    assert states[23] == state
    assert bool(findings) is (state == "open")


def test_cli_renders_verify_summary():
    outcome = {
        "status": "PARTIAL",
        "still_present": [1],
        "verified": [1, 2],
        "new": [1],
        "inconclusive": [1, 2, 3],
    }
    with patch("cli._run_verify", return_value=outcome):
        result = runner.invoke(app, ["findings", "rescan", "--session", SESSION], input="y\n")

    assert result.exit_code == 0
    assert "VERIFY: PARTIAL" in result.output
    assert "Findings VERIFIED: 2" in result.output
    assert "Findings non concluantes: 3" in result.output
