"""
tests/test_reports.py — Unit tests for reports/generator.py

Strategy:
- All tests use a tmp_path DB — no real session on disk
- HTML and JSON output written to tmp_path
- Tests verify: file created, scoring formula present, logo reference present,
  severity badges, session info, CVE refs, Finding details in HTML
- JSON: valid JSON, findings array, scoring formula key
- Invariants: no business logic in generator (no score calculation)
"""

import html as html_lib
import json
import re
import shutil
import subprocess
import pytest
from pathlib import Path
from unittest.mock import patch

import core.database as db
from core.finding import (
    Finding, Evidence, Explanation,
    Severity, Category, Confidence, Exposure, FindingStatus,
)
from core.risk_scorer import FORMULA_DESCRIPTION
from reports.generator import generate_report, _count_by_severity, _compute_worst_current_threat


SESSION = "session-report-test"


@pytest.fixture(autouse=True)
def patch_db_path(tmp_path, monkeypatch):
    def mock_get_db_path(session_id: str):
        d = tmp_path / ".netlab" / "sessions"
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{session_id}.db"
    monkeypatch.setattr(db, "get_db_path", mock_get_db_path)
    db.init_db(SESSION)
    db.save_session(SESSION, target="192.168.1.0/24", profile="normal")


def make_finding(
    severity=Severity.HIGH,
    cve_refs=None,
    risk_score=None,
    explanation=None,
    module="tcp_scan",
    target_ip="192.168.1.26",
    target_port=445,
    target_service="microsoft-ds",
    service_version="Microsoft Windows Server 2019",
) -> Finding:
    return Finding(
        session_id=SESSION,
        module=module,
        target_ip=target_ip,
        target_port=target_port,
        target_service=target_service,
        service_version=service_version,
        severity=severity,
        confidence=Confidence.CONFIRMED,
        exposure=Exposure.INTERNAL,
        category=Category.SERVICE,
        evidence=Evidence(
            raw="PORT 445/tcp open microsoft-ds",
            command=f"nmap -sV {target_ip}",
        ),
        cve_refs=cve_refs or ["CVE-2017-0144"],
        cvss_score=9.3,
        risk_score=risk_score,
        explanation=explanation,
        status=FindingStatus.OPEN,
    )


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

class TestJsonReport:
    def test_creates_json_file(self, tmp_path):
        output = tmp_path / "report.json"
        result = generate_report(SESSION, "json", str(output))
        assert result is True
        assert output.exists()

    def test_json_is_valid(self, tmp_path):
        output = tmp_path / "report.json"
        generate_report(SESSION, "json", str(output))
        data = json.loads(output.read_text())
        assert isinstance(data, dict)

    def test_json_contains_findings_array(self, tmp_path):
        db.save_finding(make_finding())
        output = tmp_path / "report.json"
        generate_report(SESSION, "json", str(output))
        data = json.loads(output.read_text())
        assert "findings" in data
        assert isinstance(data["findings"], list)

    def test_json_findings_count_matches(self, tmp_path):
        db.save_finding(make_finding())
        db.save_finding(make_finding(severity=Severity.CRITICAL, target_port=3389))
        output = tmp_path / "report.json"
        generate_report(SESSION, "json", str(output))
        data = json.loads(output.read_text())
        assert data["findings_count"] == 2
        assert len(data["findings"]) == 2

    def test_json_contains_scoring_formula(self, tmp_path):
        output = tmp_path / "report.json"
        generate_report(SESSION, "json", str(output))
        data = json.loads(output.read_text())
        assert "scoring_formula" in data
        assert "risk_score" in data["scoring_formula"]
        assert "Global Risk Score" not in data["scoring_formula"]

    def test_json_distinguishes_current_and_historical_state(self, tmp_path):
        open_finding = make_finding(risk_score=80.0)
        verified = make_finding(risk_score=90.0, target_ip="192.168.1.27")
        verified.status = FindingStatus.VERIFIED
        observation = make_finding(
            module="device_fingerprint", target_ip="192.168.1.28", target_port=None,
        )
        db.save_finding(open_finding)
        db.save_finding(verified)
        db.save_finding(observation)

        output = tmp_path / "report.json"
        assert generate_report(SESSION, "json", str(output)) is True
        data = json.loads(output.read_text())

        assert data["findings_count"] == 3
        assert data["summary"] == {
            "total_findings": 3,
            "open_findings": 1,
            "verified_findings": 1,
            "inventory_observations": 1,
            "worst_current_threat": 80.0,
        }
        by_ip = {item["target_ip"]: item for item in data["findings"]}
        assert by_ip["192.168.1.26"]["current_risk_score"] == 80.0
        assert by_ip["192.168.1.27"]["current_risk_score"] is None
        assert by_ip["192.168.1.27"]["risk_scope"] == "historical_only"
        assert by_ip["192.168.1.27"]["cvss_score"] == 9.3
        assert by_ip["192.168.1.28"]["kind"] == "observation"

    def test_json_contains_session_info(self, tmp_path):
        db.close_session(SESSION, status="completed", discover_status="EMPTY")
        output = tmp_path / "report.json"
        generate_report(SESSION, "json", str(output))
        data = json.loads(output.read_text())
        assert "session" in data
        assert data["session"]["target"] == "192.168.1.0/24"
        assert data["session"]["discover_status"] == "EMPTY"

    def test_json_preserves_null_discover_status_for_legacy_session(self, tmp_path):
        output = tmp_path / "report.json"
        generate_report(SESSION, "json", str(output))
        data = json.loads(output.read_text())
        assert data["session"]["discover_status"] is None

    def test_json_contains_cve_refs(self, tmp_path):
        db.save_finding(make_finding(cve_refs=["CVE-2017-0144", "CVE-2017-0145"]))
        output = tmp_path / "report.json"
        generate_report(SESSION, "json", str(output))
        data = json.loads(output.read_text())
        cves = data["findings"][0]["cve_refs"]
        assert "CVE-2017-0144" in cves

    def test_json_contains_generated_at(self, tmp_path):
        output = tmp_path / "report.json"
        generate_report(SESSION, "json", str(output))
        data = json.loads(output.read_text())
        assert "report_generated_at" in data

    def test_invalid_format_returns_false(self, tmp_path):
        output = tmp_path / "report.pdf"
        result = generate_report(SESSION, "pdf", str(output))
        assert result is False

    def test_unknown_session_returns_false(self, tmp_path):
        output = tmp_path / "report.json"
        result = generate_report("nonexistent-session", "json", str(output))
        assert result is False


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

class TestHtmlReport:
    def test_creates_html_file(self, tmp_path):
        output = tmp_path / "report.html"
        result = generate_report(SESSION, "html", str(output))
        assert result is True
        assert output.exists()

    def test_html_contains_doctype(self, tmp_path):
        output = tmp_path / "report.html"
        generate_report(SESSION, "html", str(output))
        content = output.read_text()
        assert "<!DOCTYPE html>" in content

    def test_html_contains_sentinelx_branding(self, tmp_path):
        output = tmp_path / "report.html"
        generate_report(SESSION, "html", str(output))
        content = output.read_text()
        assert "SentinelX" in content or "SENTINELX" in content

    def test_html_contains_logo_reference(self, tmp_path):
        output = tmp_path / "report.html"
        generate_report(SESSION, "html", str(output))
        content = output.read_text()
        assert "SentinelleX.png" in content

    def test_logo_copied_to_output_dir(self, tmp_path):
        output = tmp_path / "report.html"
        generate_report(SESSION, "html", str(output))
        logo = tmp_path / "SentinelleX.png"
        assert logo.exists()

    def test_html_contains_scoring_formula(self, tmp_path):
        output = tmp_path / "report.html"
        generate_report(SESSION, "html", str(output))
        content = output.read_text()
        assert "risk_score" in content
        assert "confidence" in content
        assert "exposure" in content

    def test_html_contains_session_id(self, tmp_path):
        output = tmp_path / "report.html"
        generate_report(SESSION, "html", str(output))
        content = output.read_text()
        assert SESSION in content

    def test_html_contains_target(self, tmp_path):
        output = tmp_path / "report.html"
        generate_report(SESSION, "html", str(output))
        content = output.read_text()
        assert "192.168.1.0/24" in content

    @pytest.mark.parametrize("discover_status", ["OK", "EMPTY", "CANCELLED", "FAILED"])
    def test_html_shows_discovery_outcome(self, tmp_path, discover_status):
        db.close_session(SESSION, status="completed", discover_status=discover_status)
        output = tmp_path / "report.html"
        generate_report(SESSION, "html", str(output))
        content = output.read_text()
        assert "Discovery" in content
        assert discover_status in content

    def test_html_handles_legacy_null_discovery_outcome(self, tmp_path):
        output = tmp_path / "report.html"
        generate_report(SESSION, "html", str(output))
        content = output.read_text()
        assert "Discovery outcome unavailable" in content

    def test_html_shows_finding_severity(self, tmp_path):
        db.save_finding(make_finding(severity=Severity.CRITICAL))
        output = tmp_path / "report.html"
        generate_report(SESSION, "html", str(output))
        content = output.read_text()
        assert "critical" in content.lower()

    def test_html_shows_cve_refs(self, tmp_path):
        db.save_finding(make_finding(cve_refs=["CVE-2017-0144"]))
        output = tmp_path / "report.html"
        generate_report(SESSION, "html", str(output))
        content = output.read_text()
        assert "CVE-2017-0144" in content

    def test_html_shows_target_ip(self, tmp_path):
        db.save_finding(make_finding(target_ip="192.168.1.26"))
        output = tmp_path / "report.html"
        generate_report(SESSION, "html", str(output))
        content = output.read_text()
        assert "192.168.1.26" in content

    def test_html_shows_explanation_when_present(self, tmp_path):
        f = make_finding(explanation=Explanation(
            what="SMBv1 is enabled.",
            attack="EternalBlue exploitation.",
            defense="Disable SMBv1 via PowerShell: Set-SmbServerConfiguration.",
        ))
        db.save_finding(f)
        output = tmp_path / "report.html"
        generate_report(SESSION, "html", str(output))
        content = output.read_text()
        # Only defense (recommendation) should appear — not pedagogy
        assert "Set-SmbServerConfiguration" in content
        # Pedagogical what/attack must NOT appear in the professional report
        assert "SMBv1 is enabled." not in content
        assert "EternalBlue exploitation." not in content

    def test_html_shows_risk_score_when_set(self, tmp_path):
        f = make_finding(risk_score=87.5)
        db.save_finding(f)
        output = tmp_path / "report.html"
        generate_report(SESSION, "html", str(output))
        content = output.read_text()
        assert "87" in content  # current score displayed
        assert "Worst Current Threat" in content
        assert "Global Network Risk Score" not in content

    def test_html_distinguishes_open_verified_and_inventory(self, tmp_path):
        open_finding = make_finding(risk_score=80.0)
        verified = make_finding(risk_score=90.0, target_ip="192.168.1.27")
        verified.status = FindingStatus.VERIFIED
        observation = make_finding(
            module="device_fingerprint", target_ip="192.168.1.28", target_port=None,
        )
        db.save_finding(open_finding)
        db.save_finding(verified)
        db.save_finding(observation)

        output = tmp_path / "report.html"
        assert generate_report(SESSION, "html", str(output)) is True
        content = output.read_text()

        assert "open" in content
        assert "verified" in content
        assert "not current" in content
        assert "inventory observation" in content
        assert "Global Network Risk Score" not in content

    def test_html_no_findings_shows_empty_state(self, tmp_path):
        output = tmp_path / "report.html"
        generate_report(SESSION, "html", str(output))
        content = output.read_text()
        assert "No findings" in content

    def test_html_contains_legal_notice(self, tmp_path):
        output = tmp_path / "report.html"
        generate_report(SESSION, "html", str(output))
        content = output.read_text()
        assert "authorization" in content.lower() or "LEGAL" in content

    def test_html_format_case_insensitive(self, tmp_path):
        output = tmp_path / "report.html"
        result = generate_report(SESSION, "HTML", str(output))
        assert result is True
        assert output.exists()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_count_by_severity_empty(self):
        counts = _count_by_severity([])
        assert counts["critical"] == 0
        assert counts["high"] == 0

    def test_count_by_severity_counts_open_only(self):
        f_open = make_finding(severity=Severity.HIGH)
        f_remediated = make_finding(severity=Severity.HIGH)
        f_remediated.status = FindingStatus.REMEDIATED
        counts = _count_by_severity([f_open, f_remediated])
        assert counts["high"] == 1  # remediated not counted

    def test_count_by_severity_mixed(self):
        findings = [
            make_finding(severity=Severity.CRITICAL),
            make_finding(severity=Severity.CRITICAL),
            make_finding(severity=Severity.HIGH),
            make_finding(severity=Severity.INFO),
        ]
        counts = _count_by_severity(findings)
        assert counts["critical"] == 2
        assert counts["high"] == 1
        assert counts["info"] == 1

    def test_compute_worst_current_threat_returns_highest(self):
        f1 = make_finding(risk_score=45.0)
        f2 = make_finding(risk_score=87.5)
        f3 = make_finding(risk_score=30.0)
        score = _compute_worst_current_threat([f1, f2, f3])
        assert score == 87.5

    def test_compute_worst_current_threat_keeps_current_possible_score(self):
        f = make_finding(risk_score=90.0)
        f.confidence = Confidence.POSSIBLE
        score = _compute_worst_current_threat([f])
        assert score == 90.0

    def test_compute_worst_current_threat_excludes_non_open(self):
        f = make_finding(risk_score=90.0)
        f.status = FindingStatus.REMEDIATED
        score = _compute_worst_current_threat([f])
        assert score is None

    def test_compute_worst_current_threat_none_when_no_scored_findings(self):
        f = make_finding(risk_score=None)
        score = _compute_worst_current_threat([f])
        assert score is None

    def test_compute_worst_current_threat_empty_list(self):
        assert _compute_worst_current_threat([]) is None


# ---------------------------------------------------------------------------
# T20 — HTML structure, completeness indicators, interactions
#
# Helpers below read the rendered HTML. The completeness and machine states come
# from scan outcomes written by the code under test; nothing here is a real
# nmap result.
# ---------------------------------------------------------------------------

def _render(tmp_path: Path, name: str = "report.html") -> str:
    output = tmp_path / name
    assert generate_report(SESSION, "html", str(output)) is True
    return output.read_text(encoding="utf-8")


def _section(content: str, section_id: str) -> str:
    match = re.search(rf'<section id="{section_id}">(.*?)</section>', content, flags=re.S)
    assert match, f"missing section {section_id}"
    return match.group(1)


def _card(content: str, card_id: str) -> str:
    """Markup of one status card: from its id up to the next card or grid."""
    rest = content[content.index(f'id="{card_id}"'):]
    ends = [i for i in (rest.find('<div class="status-card"', 1),
                        rest.find('<div class="summary-grid">')) if i > 0]
    return rest[:min(ends)] if ends else rest


def _text(fragment: str) -> str:
    plain = re.sub(r"<[^>]+>", " ", fragment)
    return re.sub(r"\s+", " ", html_lib.unescape(plain)).strip()


def _machine_card(content: str, ip: str) -> str:
    for block in re.findall(r'<article class="machine-card">(.*?)</article>', content, flags=re.S):
        if f'>{ip}</span>' in block:
            return _text(block)
    raise AssertionError(f"no machine card for {ip}")


def _device(ip: str, version: str = "Linux 5.x") -> Finding:
    """Inventory observation (device_fingerprint) for one machine."""
    return Finding(
        session_id=SESSION,
        module="device_fingerprint",
        target_ip=ip,
        target_port=None,
        target_service="host",
        service_version=version,
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        exposure=Exposure.INTERNAL,
        category=Category.NETWORK,
        evidence=Evidence(raw="[ping] host up", command=f"nmap -sn {ip}"),
    )


class TestHtmlSectionsT20:

    def test_sections_are_separate_and_in_order(self, tmp_path):
        db.save_finding(_device("192.168.1.20"))
        db.save_finding(make_finding(
            target_ip="192.168.1.26", risk_score=80.0,
            explanation=Explanation(what="w", attack="a", defense="Patch SMB."),
        ))
        content = _render(tmp_path)

        order = re.findall(r'<section id="([a-z]+)">', content)
        assert order == [
            "summary", "session", "machines", "security",
            "inventory", "recommendations", "formula",
        ]
        assert "Security Findings" in _section(content, "security")
        assert "Inventory Observations" in _section(content, "inventory")
        assert "Recommendations" in _section(content, "recommendations")

    def test_inventory_observations_stay_out_of_security_findings(self, tmp_path):
        db.save_finding(_device("192.168.1.20"))
        db.save_finding(make_finding(target_ip="192.168.1.26"))
        content = _render(tmp_path)

        security = _section(content, "security")
        inventory = _section(content, "inventory")
        assert "192.168.1.26" in security and "192.168.1.20" not in security
        assert "192.168.1.20" in inventory and "192.168.1.26" not in inventory
        assert "inventory observation" in inventory
        assert "inventory observation" not in security

    def test_recommendations_show_defense_text_only(self, tmp_path):
        db.save_finding(make_finding(explanation=Explanation(
            what="SMBv1 is enabled.",
            attack="EternalBlue exploitation.",
            defense="Disable SMBv1.",
        )))
        content = _render(tmp_path)

        assert "Disable SMBv1." in _section(content, "recommendations")
        assert "SMBv1 is enabled." not in content
        assert "EternalBlue exploitation." not in content

    def test_recommendations_section_absent_without_defense_text(self, tmp_path):
        db.save_finding(make_finding(explanation=None))
        content = _render(tmp_path)
        assert 'id="recommendations"' not in content

    def test_untrusted_text_is_escaped(self, tmp_path):
        db.save_finding(make_finding(service_version="<img src=x onerror=alert(1)>"))
        content = _render(tmp_path)
        assert "<img src=x onerror" not in content
        assert "&lt;img src=x onerror" in content

    def test_no_external_resources_are_loaded(self, tmp_path):
        content = _render(tmp_path)
        assert not re.search(r'(src|href)="https?://', content)
        assert "@import" not in content
        assert "<link" not in content


class TestTopFindings:

    def test_five_most_critical_first_then_voir_plus_voir_moins(self, tmp_path):
        scores = [10.0, 90.0, 50.0, 70.0, 30.0, 60.0, 20.0]
        for i, score in enumerate(scores):
            db.save_finding(make_finding(risk_score=score, target_port=80,
                                         target_ip=f"192.168.1.{100 + i}"))
        content = _render(tmp_path)
        security = _section(content, "security")

        expected_order = [
            "192.168.1.101",  # 90
            "192.168.1.103",  # 70
            "192.168.1.105",  # 60
            "192.168.1.102",  # 50
            "192.168.1.104",  # 30
            "192.168.1.106",  # 20 (hidden until Voir plus)
            "192.168.1.100",  # 10 (hidden until Voir plus)
        ]
        positions = [security.index(ip) for ip in expected_order]
        assert positions == sorted(positions)
        assert "Top 5 findings" in security
        assert security.count("is-extra") == 2
        assert 'data-more="Voir plus"' in security
        assert 'data-less="Voir moins"' in security
        assert "Voir plus (2)" in security

    def test_verified_finding_never_outranks_an_open_one(self, tmp_path):
        verified = make_finding(risk_score=99.0, target_ip="192.168.1.90")
        verified.status = FindingStatus.VERIFIED
        db.save_finding(verified)
        db.save_finding(make_finding(risk_score=5.0, target_ip="192.168.1.91"))
        content = _render(tmp_path)
        security = _section(content, "security")
        assert security.index("192.168.1.91") < security.index("192.168.1.90")

    def test_no_toggle_when_five_or_fewer(self, tmp_path):
        for i in range(5):
            db.save_finding(make_finding(risk_score=float(i), target_ip=f"192.168.1.{110 + i}"))
        content = _render(tmp_path)
        assert 'class="toggle-more"' not in content
        assert "is-extra" not in _section(content, "security")

    def test_details_are_collapsed_by_default(self, tmp_path):
        db.save_finding(make_finding(risk_score=50.0))
        content = _render(tmp_path)
        assert re.search(r'<details class="finding ', content)
        assert not re.search(r"<details[^>]*\bopen\b", content)


class TestCompletenessIndicators:

    def test_measured_ratio_and_percentage(self, tmp_path):
        db.save_finding(_device("192.168.1.20"))
        db.save_finding(_device("192.168.1.21"))
        db.save_scan_outcome(SESSION, "192.168.1.20", "tcp_scan", "completed", open_ports=0)
        db.save_scan_outcome(SESSION, "192.168.1.21", "tcp_scan", "failed")
        content = _render(tmp_path)

        card = _card(content, "assessment-completeness")
        assert 'data-state="MEASURED"' in card
        assert "1 / 2 machines assessed" in card
        assert "50%" in card

    def test_zero_observed_is_not_applicable_never_a_percentage(self, tmp_path):
        content = _render(tmp_path)

        card = _card(content, "assessment-completeness")
        assert 'data-state="NOT_APPLICABLE"' in card
        assert "Non applicable (0 machine observée)" in card
        assert "%" not in card

    def test_legacy_session_without_scan_table_is_unknown(self, tmp_path):
        db.save_finding(_device("192.168.1.20"))
        conn = db.get_connection(SESSION)
        conn.execute("DROP TABLE scan_outcomes")
        conn.commit()
        conn.close()
        content = _render(tmp_path)

        card = _card(content, "assessment-completeness")
        assert 'data-state="UNKNOWN"' in card
        assert "legacy" in card
        assert "%" not in card

    def test_observed_machines_without_any_recorded_scan_are_zero_of_n(self, tmp_path):
        db.save_finding(_device("192.168.1.20"))
        db.save_finding(_device("192.168.1.21"))
        content = _render(tmp_path)

        card = _card(content, "assessment-completeness")
        assert "0 / 2 machines assessed" in card
        assert "0%" in card

    @pytest.mark.parametrize("discover_status, state", [
        ("OK", "OK"),
        ("EMPTY", "NO_HOSTS_OBSERVED"),
        ("CANCELLED", "UNKNOWN"),
        ("FAILED", "UNKNOWN"),
    ])
    def test_discovery_state_follows_the_recorded_status(self, tmp_path, discover_status, state):
        db.close_session(SESSION, status="completed", discover_status=discover_status)
        content = _render(tmp_path)
        assert f'data-state="{state}"' in _card(content, "discovery-state")

    def test_tcp_completion_never_turns_discovery_into_ok(self, tmp_path):
        db.close_session(SESSION, status="completed", discover_status="FAILED")
        db.save_finding(_device("192.168.1.20"))
        db.save_scan_outcome(SESSION, "192.168.1.20", "tcp_scan", "completed", open_ports=0)
        content = _render(tmp_path)

        assert 'data-state="UNKNOWN"' in _card(content, "discovery-state")
        assert 'data-state="MEASURED"' in _card(content, "assessment-completeness")

    def test_legacy_discovery_status_is_unknown_and_labelled(self, tmp_path):
        content = _render(tmp_path)  # fixture session has no discover_status
        assert "Discovery outcome unavailable" in content
        assert 'data-state="UNKNOWN"' in _card(content, "discovery-state")


class TestMachinesSection:

    def test_machine_without_recorded_scan_is_not_recorded_not_completed(self, tmp_path):
        db.save_finding(_device("192.168.1.20"))
        content = _render(tmp_path)

        card = _machine_card(content, "192.168.1.20")
        assert "Not recorded in this session" in card
        assert "Completed" not in card

    def test_zero_open_ports_host_is_shown_as_completed(self, tmp_path):
        db.save_finding(_device("192.168.1.20"))
        db.save_scan_outcome(SESSION, "192.168.1.20", "tcp_scan", "completed", open_ports=0)
        content = _render(tmp_path)

        card = _machine_card(content, "192.168.1.20")
        assert "TCP scan Completed · 0 open port(s)" in card
        assert "Open TCP ports —" in card

    def test_failed_and_cancelled_scans_are_shown_as_such(self, tmp_path):
        db.save_finding(_device("192.168.1.20"))
        db.save_finding(_device("192.168.1.21"))
        db.save_scan_outcome(SESSION, "192.168.1.20", "tcp_scan", "failed")
        db.save_scan_outcome(SESSION, "192.168.1.21", "tcp_scan", "cancelled")
        content = _render(tmp_path)

        assert "TCP scan Failed" in _machine_card(content, "192.168.1.20")
        assert "TCP scan Cancelled" in _machine_card(content, "192.168.1.21")

    def test_open_tcp_ports_are_listed_apart_from_udp(self, tmp_path):
        db.save_finding(_device("192.168.1.20"))
        db.save_finding(make_finding(target_ip="192.168.1.20", target_port=445, module="tcp_scan"))
        db.save_finding(make_finding(target_ip="192.168.1.20", target_port=161, module="udp_scan",
                                     target_service="snmp"))
        content = _render(tmp_path)

        card = _machine_card(content, "192.168.1.20")
        assert "Open TCP ports 445" in card
        assert "161" not in card.split("Open TCP ports")[1].split("Security findings")[0]


class TestPaletteAndTheme:

    def test_dark_and_light_themes_and_toggle_are_present(self, tmp_path):
        content = _render(tmp_path)
        assert '[data-theme="dark"]' in content
        assert '[data-theme="light"]' in content
        assert '<html lang="en" data-theme="dark">' in content
        assert "function toggleTheme()" in content
        assert "sentinelx-theme" in content

    def test_palette_is_red_black_and_white(self, tmp_path):
        content = _render(tmp_path)
        css = content.split("<style>")[1].split("</style>")[0]
        assert re.search(r"--accent:\s*#e10600", css)
        assert re.search(r"--bg:\s*#0a0a0a", css)
        assert re.search(r"--bg:\s*#f4f4f4", css)
        # Previous teal/blue palette is gone.
        assert "#00d4aa" not in content and "#0088ff" not in content

    def test_textual_logo_enlarges_the_red_x(self, tmp_path):
        content = _render(tmp_path)
        css = content.split("<style>")[1].split("</style>")[0]
        assert 'class="brand-x"' in content
        assert re.search(r"\.brand-x\s*\{[^}]*font-size:\s*1\.[5-9]", css)


class TestInlineScript:

    HARNESS = r"""
const vm = require('vm');
const fs = require('fs');
const [, , scriptPath, savedTheme] = process.argv;
const src = fs.readFileSync(scriptPath, 'utf8');

class ClassList {
  constructor() { this.items = new Set(); }
  toggle(c) { if (this.items.has(c)) { this.items.delete(c); return false; } this.items.add(c); return true; }
  contains(c) { return this.items.has(c); }
}
const fake = (extra) => Object.assign({ textContent: '', classList: new ClassList() }, extra);

const html = {
  attrs: { 'data-theme': 'dark' },
  getAttribute(n) { return this.attrs[n]; },
  setAttribute(n, v) { this.attrs[n] = v; },
};
const ui = {
  'theme-icon': fake({ textContent: '🌙' }),
  'theme-label': fake({ textContent: 'Light mode' }),
};
const details = [fake({ open: false }), fake({ open: true })];
const listeners = {};
const storage = {};
if (savedTheme) { storage['sentinelx-theme'] = savedTheme; }

const context = {
  document: {
    documentElement: html,
    getElementById: (id) => ui[id],
    querySelectorAll: () => details,
  },
  localStorage: {
    getItem: (k) => (k in storage ? storage[k] : null),
    setItem: (k, v) => { storage[k] = String(v); },
  },
  window: { addEventListener: (name, fn) => { listeners[name] = fn; } },
  setTimeout: () => {},
};
vm.createContext(context);
vm.runInContext(src, context);

const themeState = () => ({
  theme: html.getAttribute('data-theme'),
  label: ui['theme-label'].textContent,
  icon: ui['theme-icon'].textContent,
  stored: storage['sentinelx-theme'] === undefined ? null : storage['sentinelx-theme'],
});
const out = { restored: themeState() };
context.toggleTheme();
out.afterFirstToggle = themeState();
context.toggleTheme();
out.afterSecondToggle = themeState();

const list = fake({});
const button = fake({
  dataset: { more: 'Voir plus', less: 'Voir moins', count: '4' },
  textContent: 'Voir plus (4)',
  previousElementSibling: list,
});
context.toggleTop(button);
out.expanded = { cls: list.classList.contains('expanded'), label: button.textContent };
context.toggleTop(button);
out.collapsed = { cls: list.classList.contains('expanded'), label: button.textContent };

listeners['beforeprint']();
out.duringPrint = details.map((d) => d.open);
listeners['afterprint']();
out.afterPrint = details.map((d) => d.open);
console.log(JSON.stringify(out));
"""

    @pytest.fixture
    def script_path(self, tmp_path):
        content = _render(tmp_path)
        script = re.search(r"<script>(.*?)</script>", content, flags=re.S).group(1)
        path = tmp_path / "inline.js"
        path.write_text(script, encoding="utf-8")
        return path

    def _run(self, tmp_path, script_path, saved_theme=""):
        node = shutil.which("node")
        harness = tmp_path / "harness.js"
        harness.write_text(self.HARNESS, encoding="utf-8")
        result = subprocess.run(
            [node, str(harness), str(script_path), saved_theme],
            capture_output=True, text=True, timeout=60,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    @pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
    def test_inline_script_is_valid_javascript(self, tmp_path, script_path):
        result = subprocess.run(
            [shutil.which("node"), "--check", str(script_path)],
            capture_output=True, text=True, timeout=60,
        )
        assert result.returncode == 0, result.stderr

    @pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
    def test_voir_plus_voir_moins_toggles_the_label(self, tmp_path, script_path):
        out = self._run(tmp_path, script_path)
        assert out["expanded"] == {"cls": True, "label": "Voir moins"}
        assert out["collapsed"] == {"cls": False, "label": "Voir plus (4)"}

    @pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
    def test_theme_toggle_keeps_icon_label_and_storage_coherent(self, tmp_path, script_path):
        out = self._run(tmp_path, script_path)
        assert out["restored"] == {"theme": "dark", "label": "Light mode", "icon": "🌙", "stored": None}
        assert out["afterFirstToggle"] == {"theme": "light", "label": "Dark mode", "icon": "☀️", "stored": "light"}
        assert out["afterSecondToggle"] == {"theme": "dark", "label": "Light mode", "icon": "🌙", "stored": "dark"}

    @pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
    def test_saved_light_theme_is_restored_at_load(self, tmp_path, script_path):
        out = self._run(tmp_path, script_path, saved_theme="light")
        assert out["restored"] == {"theme": "light", "label": "Dark mode", "icon": "☀️", "stored": "light"}

    @pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
    def test_print_opens_every_detail_and_restores_the_previous_state(self, tmp_path, script_path):
        out = self._run(tmp_path, script_path)
        assert out["duringPrint"] == [True, True]
        assert out["afterPrint"] == [False, True]


class TestJsonContractT20:

    def test_json_public_keys_are_exactly_the_documented_ones(self, tmp_path):
        db.save_finding(make_finding(risk_score=80.0))
        db.save_scan_outcome(SESSION, "192.168.1.26", "tcp_scan", "completed", open_ports=1)
        output = tmp_path / "report.json"
        assert generate_report(SESSION, "json", str(output)) is True

        data = json.loads(output.read_text(encoding="utf-8"))
        assert set(data) == {
            "report_generated_at", "session", "scoring_formula",
            "findings_count", "summary", "findings",
        }
        assert set(data["summary"]) == {
            "total_findings", "open_findings", "verified_findings",
            "inventory_observations", "worst_current_threat",
        }
