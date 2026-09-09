"""
tests/test_finding.py — Unit tests for core/finding.py

Covers:
- Nominal case: Finding creation with typed fields
- Serialization: to_dict() + json.dumps() — no custom logic, verified concretely
- Enum serialization: Severity.HIGH → "high", Confidence.PROBABLE → 0.85
- Edge case: confidence=POSSIBLE → risk_score remains None
- Edge case: explanation=None when no knowledge base rule matches
- Edge case: Finding with full Explanation and Evidence
- Invariant: risk_score is never set by Finding itself
"""

import json
import pytest
from core.finding import (
    Finding,
    Severity,
    Category,
    Confidence,
    Exposure,
    FindingStatus,
    Evidence,
    Explanation,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_basic_finding(**kwargs) -> Finding:
    """Return a minimal but valid Finding for testing."""
    defaults = dict(
        module="tcp_scan",
        target_ip="192.168.1.1",
        target_port=445,
        target_service="smb",
        severity=Severity.HIGH,
        confidence=Confidence.PROBABLE,
        evidence=Evidence(raw="PORT 445/tcp open", command="nmap -sV 192.168.1.1"),
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# Nominal case
# ---------------------------------------------------------------------------

class TestFindingCreation:
    def test_finding_has_auto_generated_id(self):
        f = make_basic_finding()
        assert f.id != ""
        assert len(f.id) == 36  # UUID4 format

    def test_two_findings_have_different_ids(self):
        f1 = make_basic_finding()
        f2 = make_basic_finding()
        assert f1.id != f2.id

    def test_finding_has_auto_generated_created_at(self):
        f = make_basic_finding()
        assert f.created_at != ""
        # Must be a valid ISO 8601 datetime string
        from datetime import datetime
        datetime.fromisoformat(f.created_at)  # raises if malformed

    def test_finding_default_status_is_open(self):
        f = make_basic_finding()
        assert f.status == FindingStatus.OPEN

    def test_finding_default_exposure_is_internal(self):
        f = make_basic_finding()
        assert f.exposure == Exposure.INTERNAL

    def test_finding_typed_fields(self):
        f = make_basic_finding(
            severity=Severity.HIGH,
            category=Category.SERVICE,
            confidence=Confidence.PROBABLE,
            exposure=Exposure.EXTERNAL,
            status=FindingStatus.VERIFIED,
        )
        assert f.severity == Severity.HIGH
        assert f.category == Category.SERVICE
        assert f.confidence == Confidence.PROBABLE
        assert f.exposure == Exposure.EXTERNAL
        assert f.status == FindingStatus.VERIFIED


# ---------------------------------------------------------------------------
# Serialization — the core requirement for ticket #001
# ---------------------------------------------------------------------------

class TestFindingSerialization:
    def test_to_dict_returns_a_dict(self):
        f = make_basic_finding()
        result = f.to_dict()
        assert isinstance(result, dict)

    def test_json_dumps_does_not_raise(self):
        """json.dumps(finding.to_dict()) must never raise — this is the contract."""
        f = make_basic_finding(
            severity=Severity.HIGH,
            category=Category.SERVICE,
            confidence=Confidence.PROBABLE,
            exposure=Exposure.EXTERNAL,
            cve_refs=["CVE-2017-0144"],
            cvss_score=9.3,
        )
        # Must not raise TypeError or ValueError
        serialized = json.dumps(f.to_dict())
        assert isinstance(serialized, str)

    def test_severity_serializes_as_string(self):
        """Severity.HIGH must serialize to the plain string "high"."""
        f = make_basic_finding(severity=Severity.HIGH)
        d = f.to_dict()
        assert d["severity"] == "high"
        # Round-trip check via JSON
        assert json.loads(json.dumps(d))["severity"] == "high"

    def test_all_severity_values_serialize_correctly(self):
        expected = [
            (Severity.CRITICAL, "critical"),
            (Severity.HIGH, "high"),
            (Severity.MEDIUM, "medium"),
            (Severity.LOW, "low"),
            (Severity.INFO, "info"),
        ]
        for severity, expected_str in expected:
            f = make_basic_finding(severity=severity)
            assert f.to_dict()["severity"] == expected_str

    def test_confidence_serializes_as_float(self):
        """Confidence.PROBABLE must serialize to the float 0.85."""
        f = make_basic_finding(confidence=Confidence.PROBABLE)
        d = f.to_dict()
        assert d["confidence"] == 0.85
        assert isinstance(d["confidence"], float)

    def test_all_confidence_values_serialize_correctly(self):
        expected = [
            (Confidence.CONFIRMED, 1.00),
            (Confidence.PROBABLE, 0.85),
            (Confidence.POSSIBLE, 0.60),
        ]
        for confidence, expected_float in expected:
            f = make_basic_finding(confidence=confidence)
            assert f.to_dict()["confidence"] == expected_float

    def test_exposure_serializes_as_string(self):
        f = make_basic_finding(exposure=Exposure.EXTERNAL)
        assert f.to_dict()["exposure"] == "external"

    def test_status_serializes_as_string(self):
        f = make_basic_finding(status=FindingStatus.VERIFIED)
        assert f.to_dict()["status"] == "verified"

    def test_evidence_serializes_as_nested_dict(self):
        """Evidence dataclass must become a nested dict, not a string."""
        ev = Evidence(raw="PORT 22/tcp open ssh", command="nmap -sV 192.168.1.1 -p 22")
        f = make_basic_finding(evidence=ev)
        d = f.to_dict()
        assert isinstance(d["evidence"], dict)
        assert d["evidence"]["raw"] == "PORT 22/tcp open ssh"
        assert d["evidence"]["command"] == "nmap -sV 192.168.1.1 -p 22"

    def test_explanation_serializes_as_nested_dict_when_present(self):
        """Explanation dataclass must become a nested dict when not None."""
        exp = Explanation(
            what="SMBv1 is enabled — an outdated protocol with known critical vulnerabilities.",
            attack="EternalBlue (MS17-010) exploits SMBv1 to achieve remote code execution.",
            defense="Disable SMBv1 via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
        )
        f = make_basic_finding(explanation=exp)
        d = f.to_dict()
        assert isinstance(d["explanation"], dict)
        assert d["explanation"]["what"].startswith("SMBv1")
        assert "EternalBlue" in d["explanation"]["attack"]

    def test_explanation_none_serializes_as_null(self):
        """explanation=None must serialize to JSON null — not an empty dict."""
        f = make_basic_finding(explanation=None)
        d = f.to_dict()
        assert d["explanation"] is None
        # Verify JSON round-trip
        assert json.loads(json.dumps(d))["explanation"] is None

    def test_cve_refs_serializes_as_list(self):
        f = make_basic_finding(cve_refs=["CVE-2017-0144", "CVE-2017-0145"])
        d = f.to_dict()
        assert d["cve_refs"] == ["CVE-2017-0144", "CVE-2017-0145"]

    def test_empty_cve_refs_serializes_as_empty_list(self):
        f = make_basic_finding()
        assert f.to_dict()["cve_refs"] == []


# ---------------------------------------------------------------------------
# Edge cases — invariants that must hold
# ---------------------------------------------------------------------------

class TestFindingInvariants:
    def test_risk_score_is_none_on_creation(self):
        """risk_score must ALWAYS be None when a Finding is created.
        It is set exclusively by core/risk_scorer.py — never here.
        """
        f = make_basic_finding(
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
        )
        assert f.risk_score is None

    def test_risk_score_stays_none_with_possible_confidence(self):
        """Confidence.POSSIBLE (0.60) does not trigger any score calculation."""
        f = make_basic_finding(confidence=Confidence.POSSIBLE)
        assert f.risk_score is None

    def test_explanation_none_when_no_rule_matches(self):
        """When no knowledge base rule matches, explanation is None.
        Never a placeholder or empty Explanation().
        """
        f = make_basic_finding(explanation=None)
        assert f.explanation is None

    def test_explanation_is_not_empty_dataclass_by_default(self):
        """Default explanation must be None, not Explanation() with empty strings."""
        f = make_basic_finding()
        # explanation field default is None — not an empty Explanation dataclass
        assert f.explanation is None

    def test_optional_port_can_be_none(self):
        f = Finding(module="passive_recon", target_ip="192.168.1.1")
        assert f.target_port is None

    def test_optional_cvss_score_can_be_none(self):
        f = make_basic_finding()
        assert f.cvss_score is None

    def test_confidence_is_a_float_enum(self):
        """Confidence must be usable as a plain float multiplier."""
        f = make_basic_finding(confidence=Confidence.PROBABLE)
        # This is how risk_scorer.py will use it — no conversion needed
        result = f.confidence * 100
        assert result == 85.0

    def test_finding_with_all_fields_serializes_cleanly(self):
        """Full Finding with every field populated must serialize without error."""
        f = Finding(
            session_id="session-001",
            module="smb_enum",
            target_ip="192.168.1.10",
            target_port=445,
            target_service="smb",
            service_version="Windows Server 2008 R2",
            category=Category.SERVICE,
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            exposure=Exposure.INTERNAL,
            evidence=Evidence(
                raw="Host script results: smb-security-mode: account_used: guest",
                command="nmap --script smb-security-mode 192.168.1.10",
            ),
            explanation=Explanation(
                what="SMBv1 is enabled.",
                attack="EternalBlue exploitation.",
                defense="Disable SMBv1.",
            ),
            cve_refs=["CVE-2017-0144"],
            cvss_score=9.3,
            risk_score=None,  # set by risk_scorer only
            status=FindingStatus.OPEN,
            remediation_cmd="",
        )
        serialized = json.dumps(f.to_dict())
        reloaded = json.loads(serialized)
        assert reloaded["severity"] == "critical"
        assert reloaded["confidence"] == 1.0
        assert reloaded["risk_score"] is None
        assert reloaded["explanation"]["what"] == "SMBv1 is enabled."
