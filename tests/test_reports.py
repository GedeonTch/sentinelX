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

import json
import pytest
from pathlib import Path
from unittest.mock import patch

import core.database as db
from core.finding import (
    Finding, Evidence, Explanation,
    Severity, Category, Confidence, Exposure, FindingStatus,
)
from core.risk_scorer import FORMULA_DESCRIPTION
from reports.generator import generate_report, _count_by_severity, _compute_global_score


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

    def test_json_contains_session_info(self, tmp_path):
        output = tmp_path / "report.json"
        generate_report(SESSION, "json", str(output))
        data = json.loads(output.read_text())
        assert "session" in data
        assert data["session"]["target"] == "192.168.1.0/24"

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
        assert "sentinelXlogo.png" in content

    def test_logo_copied_to_output_dir(self, tmp_path):
        output = tmp_path / "report.html"
        generate_report(SESSION, "html", str(output))
        logo = tmp_path / "sentinelXlogo.png"
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
        assert "87" in content  # score displayed

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

    def test_compute_global_score_returns_highest(self):
        f1 = make_finding(risk_score=45.0)
        f2 = make_finding(risk_score=87.5)
        f3 = make_finding(risk_score=30.0)
        score = _compute_global_score([f1, f2, f3])
        assert score == 87.5

    def test_compute_global_score_excludes_possible_confidence(self):
        f = make_finding(risk_score=90.0)
        f.confidence = Confidence.POSSIBLE
        score = _compute_global_score([f])
        assert score is None

    def test_compute_global_score_excludes_non_open(self):
        f = make_finding(risk_score=90.0)
        f.status = FindingStatus.REMEDIATED
        score = _compute_global_score([f])
        assert score is None

    def test_compute_global_score_none_when_no_scored_findings(self):
        f = make_finding(risk_score=None)
        score = _compute_global_score([f])
        assert score is None

    def test_compute_global_score_empty_list(self):
        assert _compute_global_score([]) is None
