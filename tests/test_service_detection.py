"""
tests/test_service_detection.py — Unit tests for detect/service_detection.py

Strategy:
- All tests use injected KB entries — never depend on cve_db.json on disk
- Tests cover: version matching, product matching, service matching,
  range bounds, version extraction, Finding enrichment, no-match cases,
  confidence upgrade, invariants (risk_score=None never touched)
"""

import dataclasses
import pytest
from typing import List, Dict, Any

from core.finding import (
    Finding,
    Evidence,
    Category,
    Severity,
    Confidence,
    Exposure,
    FindingStatus,
)
from detect.service_detection import (
    enrich_findings,
    _lookup_cve,
    _service_matches,
    _product_matches,
    _version_in_range,
    _extract_version,
    _apply_cve,
)


# ---------------------------------------------------------------------------
# Fixtures — injectable KB entries
# ---------------------------------------------------------------------------

KB_SSH = {
    "service": "ssh",
    "product": "OpenSSH",
    "version_gte": "5.0",
    "version_lte": "7.4",
    "cve_refs": ["CVE-2016-6515"],
    "cvss_score": 7.8,
    "severity": "high",
    "description": "OpenSSH <= 7.4 privilege escalation",
}

KB_SMB = {
    "service": "microsoft-ds",
    "product": "Microsoft Windows",
    "version_gte": None,
    "version_lte": None,
    "requires_version_confirmation": True,
    "cve_refs": ["CVE-2017-0144", "CVE-2017-0145"],
    "cvss_score": 9.3,
    "severity": "critical",
    "description": "EternalBlue SMBv1",
}

KB_APACHE_CRITICAL = {
    "service": "http",
    "product": "Apache httpd",
    "version_gte": "2.4.49",
    "version_lte": "2.4.49",
    "cve_refs": ["CVE-2021-41773"],
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "Apache 2.4.49 path traversal",
}

KB_NGINX = {
    "service": "http",
    "product": "nginx",
    "version_gte": "1.0.0",
    "version_lte": "1.14.0",
    "cve_refs": ["CVE-2018-16843"],
    "cvss_score": 7.5,
    "severity": "high",
    "description": "nginx HTTP/2 memory exhaustion",
}

KB_SNMP_NO_VERSION = {
    "service": "snmp",
    "product": "",
    "version_gte": None,
    "version_lte": None,
    "requires_version_confirmation": True,
    "cve_refs": [],
    "cvss_score": 5.0,
    "severity": "medium",
    "description": "SNMP exposed",
}

FULL_KB = [KB_SSH, KB_SMB, KB_APACHE_CRITICAL, KB_NGINX, KB_SNMP_NO_VERSION]


def make_finding(
    service: str = "ssh",
    service_version: str = "OpenSSH 7.4",
    confidence: Confidence = Confidence.CONFIRMED,
) -> Finding:
    return Finding(
        session_id="session-test",
        module="tcp_scan",
        target_ip="192.168.1.1",
        target_port=22,
        target_service=service,
        service_version=service_version,
        category=Category.SERVICE,
        severity=Severity.INFO,
        confidence=confidence,
        evidence=Evidence(raw="<port/>", command="nmap -sV"),
    )


# ---------------------------------------------------------------------------
# _extract_version
# ---------------------------------------------------------------------------

class TestExtractVersion:
    def test_extracts_simple_version(self):
        assert _extract_version("OpenSSH 7.4") == "7.4"

    def test_extracts_dotted_version(self):
        assert _extract_version("Apache httpd 2.4.49") == "2.4.49"

    def test_extracts_first_version_only(self):
        assert _extract_version("nginx 1.18.0 (Ubuntu 20.04)") == "1.18.0"

    def test_no_version_returns_none(self):
        assert _extract_version("Microsoft Windows Server 2019") is None

    def test_empty_string_returns_none(self):
        assert _extract_version("") is None

    def test_version_with_protocol(self):
        assert _extract_version("OpenSSH 7.4 protocol 2.0") == "7.4"

    def test_four_part_version(self):
        assert _extract_version("vsftpd 2.3.4") == "2.3.4"


# ---------------------------------------------------------------------------
# _version_in_range
# ---------------------------------------------------------------------------

class TestVersionInRange:
    def test_version_within_range(self):
        assert _version_in_range("7.4", "5.0", "7.4") is True

    def test_version_at_lower_bound(self):
        assert _version_in_range("5.0", "5.0", "7.4") is True

    def test_version_at_upper_bound(self):
        assert _version_in_range("7.4", "5.0", "7.4") is True

    def test_version_below_range(self):
        assert _version_in_range("4.9", "5.0", "7.4") is False

    def test_version_above_range(self):
        assert _version_in_range("7.5", "5.0", "7.4") is False

    def test_no_bounds_matches_any_version(self):
        assert _version_in_range("99.0", None, None) is True

    def test_no_bounds_matches_none_version(self):
        assert _version_in_range(None, None, None) is True

    def test_version_none_with_bounds_returns_false(self):
        assert _version_in_range(None, "5.0", "7.4") is False

    def test_only_lower_bound(self):
        assert _version_in_range("8.0", "5.0", None) is True
        assert _version_in_range("4.0", "5.0", None) is False

    def test_only_upper_bound(self):
        assert _version_in_range("3.0", None, "5.0") is True
        assert _version_in_range("6.0", None, "5.0") is False

    def test_invalid_version_string_returns_false(self):
        assert _version_in_range("not-a-version", "5.0", "7.4") is False

    def test_exact_version_match(self):
        assert _version_in_range("2.4.49", "2.4.49", "2.4.49") is True
        assert _version_in_range("2.4.48", "2.4.49", "2.4.49") is False
        assert _version_in_range("2.4.50", "2.4.49", "2.4.49") is False


# ---------------------------------------------------------------------------
# _service_matches
# ---------------------------------------------------------------------------

class TestServiceMatches:
    def test_exact_match(self):
        assert _service_matches("ssh", "ssh") is True

    def test_case_insensitive(self):
        assert _service_matches("SSH", "ssh") is True

    def test_partial_match(self):
        assert _service_matches("microsoft-ds", "microsoft-ds") is True

    def test_no_match(self):
        assert _service_matches("http", "ssh") is False

    def test_empty_entry_service_returns_false(self):
        assert _service_matches("ssh", "") is False


# ---------------------------------------------------------------------------
# _product_matches
# ---------------------------------------------------------------------------

class TestProductMatches:
    def test_product_found_in_version_string(self):
        assert _product_matches("OpenSSH 7.4 protocol 2.0", "OpenSSH") is True

    def test_case_insensitive(self):
        assert _product_matches("openssh 7.4", "OpenSSH") is True

    def test_empty_entry_product_matches_anything(self):
        assert _product_matches("anything here", "") is True

    def test_product_not_found(self):
        assert _product_matches("nginx 1.18.0", "Apache") is False


# ---------------------------------------------------------------------------
# _lookup_cve
# ---------------------------------------------------------------------------

class TestLookupCve:
    def test_returns_entry_for_matching_ssh(self):
        result = _lookup_cve("ssh", "OpenSSH 7.4", "7.4", kb_entries=FULL_KB)
        assert result is not None
        assert "CVE-2016-6515" in result["cve_refs"]

    def test_returns_none_for_newer_ssh(self):
        result = _lookup_cve("ssh", "OpenSSH 8.9", "8.9", kb_entries=FULL_KB)
        assert result is None

    def test_returns_smb_entry_without_version(self):
        """SMB entry has no version constraints — matches any version."""
        result = _lookup_cve(
            "microsoft-ds",
            "Microsoft Windows Server 2019",
            None,
            kb_entries=FULL_KB,
        )
        assert result is not None
        assert "CVE-2017-0144" in result["cve_refs"]
        assert result["severity"] == "critical"

    def test_returns_snmp_entry_no_version(self):
        result = _lookup_cve("snmp", "", None, kb_entries=FULL_KB)
        assert result is not None
        assert result["severity"] == "medium"

    def test_returns_highest_cvss_when_multiple_match(self):
        """If two entries match, the one with the highest CVSS wins."""
        result = _lookup_cve(
            "http", "Apache httpd 2.4.49", "2.4.49", kb_entries=FULL_KB
        )
        assert result is not None
        assert result["cvss_score"] == 9.8  # critical, not the nginx entry

    def test_returns_none_for_unknown_service(self):
        result = _lookup_cve("telnet", "telnetd 1.0", "1.0", kb_entries=FULL_KB)
        assert result is None

    def test_returns_none_for_empty_kb(self):
        result = _lookup_cve("ssh", "OpenSSH 7.4", "7.4", kb_entries=[])
        assert result is None


# ---------------------------------------------------------------------------
# _apply_cve
# ---------------------------------------------------------------------------

class TestApplyCve:
    def test_severity_upgraded(self):
        f = make_finding()
        result = _apply_cve(f, KB_SSH)
        assert result.severity == Severity.HIGH

    def test_cvss_score_set(self):
        f = make_finding()
        result = _apply_cve(f, KB_SSH)
        assert result.cvss_score == 7.8

    def test_cve_refs_set(self):
        f = make_finding()
        result = _apply_cve(f, KB_SSH)
        assert "CVE-2016-6515" in result.cve_refs

    def test_risk_score_stays_none(self):
        """_apply_cve must NEVER set risk_score — that is risk_scorer.py only."""
        f = make_finding()
        result = _apply_cve(f, KB_SSH)
        assert result.risk_score is None

    def test_original_finding_not_mutated(self):
        f = make_finding()
        original_severity = f.severity
        _apply_cve(f, KB_SSH)
        assert f.severity == original_severity  # original untouched

    def test_possible_confidence_upgraded_to_probable(self):
        """POSSIBLE → PROBABLE when a CVE is found."""
        f = make_finding(confidence=Confidence.POSSIBLE)
        result = _apply_cve(f, KB_SSH)
        assert result.confidence == Confidence.PROBABLE

    def test_confirmed_confidence_unchanged(self):
        f = make_finding(confidence=Confidence.CONFIRMED)
        result = _apply_cve(f, KB_SSH)
        assert result.confidence == Confidence.CONFIRMED

    def test_probable_confidence_unchanged(self):
        f = make_finding(confidence=Confidence.PROBABLE)
        result = _apply_cve(f, KB_SSH)
        assert result.confidence == Confidence.PROBABLE

    def test_critical_severity_from_smb(self):
        """SMB with version detected → CRITICAL severity, confidence unchanged."""
        f = make_finding(service="microsoft-ds", service_version="Microsoft Windows Server 2019")
        result = _apply_cve(f, KB_SMB)
        assert result.severity == Severity.CRITICAL
        assert "CVE-2017-0144" in result.cve_refs
        # Version present → confidence NOT forced to POSSIBLE
        assert result.confidence != Confidence.POSSIBLE


# ---------------------------------------------------------------------------
# enrich_findings — integration
# ---------------------------------------------------------------------------

class TestEnrichFindings:
    def test_enriches_matching_finding(self):
        f = make_finding(service="ssh", service_version="OpenSSH 7.4")
        from unittest.mock import patch
        import detect.service_detection as sd
        with patch.object(sd, "_KB_ENTRIES", FULL_KB):
            results = enrich_findings([f])
        assert results[0].severity == Severity.HIGH
        assert "CVE-2016-6515" in results[0].cve_refs

    def test_unmatched_finding_stays_info(self):
        f = make_finding(service="ssh", service_version="OpenSSH 9.0")
        from unittest.mock import patch
        import detect.service_detection as sd
        with patch.object(sd, "_KB_ENTRIES", FULL_KB):
            results = enrich_findings([f])
        assert results[0].severity == Severity.INFO
        assert results[0].cve_refs == []

    def test_returns_same_count(self):
        findings = [
            make_finding(service="ssh", service_version="OpenSSH 7.4"),
            make_finding(service="http", service_version="nginx 1.18.0"),
        ]
        from unittest.mock import patch
        import detect.service_detection as sd
        with patch.object(sd, "_KB_ENTRIES", FULL_KB):
            results = enrich_findings(findings)
        assert len(results) == 2

    def test_empty_list_returns_empty(self):
        assert enrich_findings([]) == []

    def test_smb_finding_becomes_critical(self):
        """SMB with version → CRITICAL severity, confidence not forced to POSSIBLE."""
        f = make_finding(
            service="microsoft-ds",
            service_version="Microsoft Windows Server 2019",
        )
        from unittest.mock import patch
        import detect.service_detection as sd
        with patch.object(sd, "_KB_ENTRIES", FULL_KB):
            results = enrich_findings([f])
        assert results[0].severity == Severity.CRITICAL
        assert results[0].cvss_score == 9.3
        assert results[0].confidence != Confidence.POSSIBLE

    def test_all_results_risk_score_none(self):
        """Invariant: enrich_findings never sets risk_score."""
        findings = [
            make_finding(service="ssh", service_version="OpenSSH 7.4"),
            make_finding(service="microsoft-ds"),
        ]
        from unittest.mock import patch
        import detect.service_detection as sd
        with patch.object(sd, "_KB_ENTRIES", FULL_KB):
            results = enrich_findings(findings)
        assert all(r.risk_score is None for r in results)

    def test_originals_not_mutated(self):
        f = make_finding(service="ssh", service_version="OpenSSH 7.4")
        from unittest.mock import patch
        import detect.service_detection as sd
        with patch.object(sd, "_KB_ENTRIES", FULL_KB):
            enrich_findings([f])
        assert f.severity == Severity.INFO  # original untouched


# ---------------------------------------------------------------------------
# A1 — requires_version_confirmation tests
# ---------------------------------------------------------------------------

KB_SMB_NO_VERSION_REQUIRED = {
    "service": "microsoft-ds",
    "product": "",
    "version_gte": None,
    "version_lte": None,
    "requires_version_confirmation": True,
    "cve_refs": ["CVE-2017-0144"],
    "cvss_score": 9.3,
    "severity": "critical",
    "description": "EternalBlue — requires version confirmation",
}

KB_RDP_NO_VERSION_REQUIRED = {
    "service": "ms-wbt-server",
    "product": "",
    "version_gte": None,
    "version_lte": None,
    "requires_version_confirmation": True,
    "cve_refs": ["CVE-2019-0708"],
    "cvss_score": 9.8,
    "severity": "critical",
    "description": "BlueKeep — requires version confirmation",
}


def make_finding_no_version(service: str, port: int) -> Finding:
    """Make a Finding with empty service_version (simulates undetected version)."""
    return Finding(
        session_id="session-test",
        module="tcp_scan",
        target_ip="192.168.1.26",
        target_port=port,
        target_service=service,
        service_version="",          # ← version inconnue
        category=Category.SERVICE,
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        exposure=Exposure.INTERNAL,
        evidence=Evidence(raw=f"PORT {port}/tcp open", command=f"nmap 192.168.1.26"),
    )


class TestRequiresVersionConfirmation:

    def test_smb_no_version_confidence_is_possible(self):
        """Port 445, version inconnue → confidence forcée à POSSIBLE."""
        f = make_finding_no_version("microsoft-ds", 445)
        result = _apply_cve(f, KB_SMB_NO_VERSION_REQUIRED)
        assert result.confidence == Confidence.POSSIBLE

    def test_rdp_no_version_confidence_is_possible(self):
        """Port 3389, version inconnue → confidence forcée à POSSIBLE."""
        f = make_finding_no_version("ms-wbt-server", 3389)
        result = _apply_cve(f, KB_RDP_NO_VERSION_REQUIRED)
        assert result.confidence == Confidence.POSSIBLE

    def test_smb_no_version_severity_stays_critical(self):
        """Severity CRITICAL conservée — pas abaissée à MEDIUM sans version."""
        f = make_finding_no_version("microsoft-ds", 445)
        result = _apply_cve(f, KB_SMB_NO_VERSION_REQUIRED)
        assert result.severity == Severity.CRITICAL

    def test_evidence_contains_version_warning_when_unconfirmed(self):
        """La note d'avertissement doit être dans evidence.raw."""
        f = make_finding_no_version("microsoft-ds", 445)
        result = _apply_cve(f, KB_SMB_NO_VERSION_REQUIRED)
        assert "Version not confirmed" in result.evidence.raw
        assert "POSSIBLE" in result.evidence.raw

    def test_smb_with_version_keeps_original_confidence(self):
        """Avec version détectée → confidence NON forcée à POSSIBLE."""
        f = make_finding(
            service="microsoft-ds",
            service_version="Windows XP SP3",
            confidence=Confidence.CONFIRMED,
        )
        result = _apply_cve(f, KB_SMB_NO_VERSION_REQUIRED)
        assert result.confidence != Confidence.POSSIBLE
        assert result.confidence == Confidence.CONFIRMED
