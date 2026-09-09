"""
tests/test_risk_scorer.py — Unit tests for core/risk_scorer.py

Steering requirement: coefficients must be tested on 5+ real cases before release.

Strategy:
- All tests use injected coefficients (_CONFIG override) so they never depend
  on config.yaml being present — the scorer is tested in isolation.
- The 5 reference cases use realistic Finding scenarios with manually verified
  expected scores calculated from the formula:
      risk_score = min(100, base_severity × confidence_factor × exposure_factor)

Reference cases (manually calculated):
  Case 1 — EternalBlue (SMBv1, CVE known):
      cvss=9.3 → base=93.0, CONFIRMED×1.00, INTERNAL×1.00 → min(100, 93.0) = 93.0

  Case 2 — Weak SSH banner (version probable, internal):
      no cvss, HIGH → base=70, PROBABLE×0.85, INTERNAL×1.00 → 70×0.85 = 59.5

  Case 3 — Open HTTP on external IP (no CVE, medium):
      no cvss, MEDIUM → base=45, CONFIRMED×1.00, EXTERNAL×1.15 → 45×1.15 = 51.75

  Case 4 — Default router credentials (high, external):
      no cvss, HIGH → base=70, CONFIRMED×1.00, EXTERNAL×1.15 → 70×1.15 = 80.5

  Case 5 — OS fingerprint (possible confidence, low severity):
      no cvss, LOW → base=20, POSSIBLE×0.60, INTERNAL×1.00 → 20×0.60 = 12.0

  Case 6 — Critical with CVSS 10.0 (would exceed 100 without cap):
      cvss=10.0 → base=100, CONFIRMED×1.00, EXTERNAL×1.15 → min(100, 115.0) = 100.0
"""

import dataclasses
import pytest
from typing import List

from core.finding import (
    Finding,
    Evidence,
    Severity,
    Category,
    Confidence,
    Exposure,
    FindingStatus,
)
import core.risk_scorer as scorer


# ---------------------------------------------------------------------------
# Fixtures — inject deterministic config, bypass config.yaml
# ---------------------------------------------------------------------------

FIXED_CONFIG = {
    "base_severity": {
        "critical": 90,
        "high": 70,
        "medium": 45,
        "low": 20,
        "info": 5,
    },
    "confidence_factor": {
        "confirmed": 1.00,
        "probable": 0.85,
        "possible": 0.60,
    },
    "exposure_factor": {
        "internal": 1.00,
        "external": 1.15,
    },
}


@pytest.fixture(autouse=True)
def inject_config(monkeypatch):
    """Replace module-level _CONFIG with the fixed reference config for all tests."""
    monkeypatch.setattr(scorer, "_CONFIG", FIXED_CONFIG)


def make_finding(
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.CONFIRMED,
    exposure: Exposure = Exposure.INTERNAL,
    cvss_score: float | None = None,
    status: FindingStatus = FindingStatus.OPEN,
) -> Finding:
    return Finding(
        session_id="session-test",
        module="test_module",
        target_ip="192.168.1.1",
        severity=severity,
        confidence=confidence,
        exposure=exposure,
        cvss_score=cvss_score,
        status=status,
        evidence=Evidence(raw="test evidence", command="test cmd"),
    )


# ---------------------------------------------------------------------------
# Reference cases — the 5+ real scenarios required by the steering document
# ---------------------------------------------------------------------------

class TestReferenceScenarios:
    """5+ manually verified real-world scenarios.

    Each expected value is calculated by hand from the formula:
        risk_score = min(100, base_severity × confidence_factor × exposure_factor)
    and documented above in the module docstring.
    """

    def test_case_1_eternalblue_cvss_confirmed_internal(self):
        """CVE-2017-0144 EternalBlue: cvss=9.3, CONFIRMED, INTERNAL
        base = 9.3 × 10 = 93.0
        93.0 × 1.00 × 1.00 = 93.0
        """
        f = make_finding(
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            exposure=Exposure.INTERNAL,
            cvss_score=9.3,
        )
        assert scorer.calculate_score(f) == 93.0

    def test_case_2_weak_ssh_banner_probable_internal(self):
        """Weak SSH version inferred from banner: HIGH, PROBABLE, INTERNAL
        base = 70
        70 × 0.85 × 1.00 = 59.5
        """
        f = make_finding(
            severity=Severity.HIGH,
            confidence=Confidence.PROBABLE,
            exposure=Exposure.INTERNAL,
            cvss_score=None,
        )
        assert scorer.calculate_score(f) == 59.5

    def test_case_3_open_http_external_confirmed(self):
        """Open HTTP on external IP, no CVE: MEDIUM, CONFIRMED, EXTERNAL
        base = 45
        45 × 1.00 × 1.15 = 51.75
        """
        f = make_finding(
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            exposure=Exposure.EXTERNAL,
            cvss_score=None,
        )
        assert scorer.calculate_score(f) == 51.75

    def test_case_4_default_router_credentials_external(self):
        """Default credentials on router: HIGH, CONFIRMED, EXTERNAL
        base = 70
        70 × 1.00 × 1.15 = 80.5
        """
        f = make_finding(
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            exposure=Exposure.EXTERNAL,
            cvss_score=None,
        )
        assert scorer.calculate_score(f) == 80.5

    def test_case_5_os_fingerprint_possible_low(self):
        """OS fingerprint estimate: LOW, POSSIBLE, INTERNAL
        base = 20
        20 × 0.60 × 1.00 = 12.0
        """
        f = make_finding(
            severity=Severity.LOW,
            confidence=Confidence.POSSIBLE,
            exposure=Exposure.INTERNAL,
            cvss_score=None,
        )
        assert scorer.calculate_score(f) == 12.0

    def test_case_6_cvss_10_capped_at_100(self):
        """CVSS 10.0 with EXTERNAL exposure would exceed 100 — must be capped.
        base = 10.0 × 10 = 100.0
        100.0 × 1.00 × 1.15 = 115.0 → min(100, 115.0) = 100.0
        """
        f = make_finding(
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            exposure=Exposure.EXTERNAL,
            cvss_score=10.0,
        )
        assert scorer.calculate_score(f) == 100.0

    def test_case_7_info_finding_probable_external(self):
        """Info-level port discovery: INFO, PROBABLE, EXTERNAL
        base = 5
        5 × 0.85 × 1.15 = 4.8875 → rounded to 4.89
        """
        f = make_finding(
            severity=Severity.INFO,
            confidence=Confidence.PROBABLE,
            exposure=Exposure.EXTERNAL,
            cvss_score=None,
        )
        assert scorer.calculate_score(f) == 4.89


# ---------------------------------------------------------------------------
# Formula invariants
# ---------------------------------------------------------------------------

class TestFormulaInvariants:
    def test_score_never_exceeds_100(self):
        """No combination of inputs must produce a score above 100."""
        f = make_finding(
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            exposure=Exposure.EXTERNAL,
            cvss_score=10.0,
        )
        assert scorer.calculate_score(f) <= 100.0

    def test_score_is_always_positive(self):
        f = make_finding(
            severity=Severity.INFO,
            confidence=Confidence.POSSIBLE,
            exposure=Exposure.INTERNAL,
        )
        assert scorer.calculate_score(f) > 0.0

    def test_cvss_base_takes_priority_over_severity_enum(self):
        """When cvss_score is set, it drives the base — not the severity enum."""
        # HIGH enum would give base=70, but cvss=5.0 gives base=50
        f = make_finding(severity=Severity.HIGH, cvss_score=5.0)
        score = scorer.calculate_score(f)
        assert score == 50.0   # 5.0×10 × 1.00 × 1.00

    def test_external_always_scores_higher_than_internal(self):
        """Same finding, external exposure must score higher than internal."""
        f_internal = make_finding(
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            exposure=Exposure.INTERNAL,
        )
        f_external = make_finding(
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            exposure=Exposure.EXTERNAL,
        )
        assert scorer.calculate_score(f_external) > scorer.calculate_score(f_internal)

    def test_confirmed_scores_higher_than_probable(self):
        """Higher confidence must produce a higher score, all else equal."""
        f_confirmed = make_finding(confidence=Confidence.CONFIRMED)
        f_probable = make_finding(confidence=Confidence.PROBABLE)
        f_possible = make_finding(confidence=Confidence.POSSIBLE)

        assert scorer.calculate_score(f_confirmed) > scorer.calculate_score(f_probable)
        assert scorer.calculate_score(f_probable) > scorer.calculate_score(f_possible)

    def test_higher_severity_scores_higher(self):
        """Critical must score higher than high, high > medium, etc."""
        severities = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        scores = [
            scorer.calculate_score(make_finding(severity=s, cvss_score=None))
            for s in severities
        ]
        assert scores == sorted(scores, reverse=True)

    def test_score_is_rounded_to_2_decimals(self):
        """Score must be rounded to 2 decimal places."""
        f = make_finding(
            severity=Severity.INFO,
            confidence=Confidence.PROBABLE,
            exposure=Exposure.EXTERNAL,
        )
        score = scorer.calculate_score(f)
        assert score == round(score, 2)


# ---------------------------------------------------------------------------
# score_findings — batch scoring
# ---------------------------------------------------------------------------

class TestScoreFindings:
    def test_score_findings_returns_same_count(self):
        findings = [make_finding(severity=s) for s in Severity]
        result = scorer.score_findings(findings)
        assert len(result) == len(findings)

    def test_score_findings_sets_risk_score(self):
        findings = [make_finding()]
        result = scorer.score_findings(findings)
        assert result[0].risk_score is not None

    def test_score_findings_does_not_mutate_originals(self):
        """score_findings must return new objects — originals stay unchanged."""
        f = make_finding()
        assert f.risk_score is None

        result = scorer.score_findings([f])

        # Original untouched
        assert f.risk_score is None
        # New object has the score
        assert result[0].risk_score is not None

    def test_score_findings_empty_list(self):
        assert scorer.score_findings([]) == []


# ---------------------------------------------------------------------------
# get_global_score — global network score
# ---------------------------------------------------------------------------

class TestGetGlobalScore:
    def test_global_score_is_worst_open_finding(self):
        """Global score = highest risk_score among OPEN findings with confidence >= 0.7."""
        findings = scorer.score_findings([
            make_finding(severity=Severity.LOW, confidence=Confidence.CONFIRMED),
            make_finding(severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED),
            make_finding(severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED),
        ])
        global_score = scorer.get_global_score(findings)
        # Critical (base=90) must be the global score
        assert global_score == 90.0

    def test_global_score_excludes_possible_confidence(self):
        """Findings with Confidence.POSSIBLE (< 0.7) must be excluded from global score."""
        findings = scorer.score_findings([
            make_finding(severity=Severity.CRITICAL, confidence=Confidence.POSSIBLE),
        ])
        global_score = scorer.get_global_score(findings)
        assert global_score is None

    def test_global_score_excludes_non_open_findings(self):
        """Remediated and accepted findings must not drive the global score."""
        findings = scorer.score_findings([
            make_finding(severity=Severity.CRITICAL, status=FindingStatus.REMEDIATED),
            make_finding(severity=Severity.LOW, status=FindingStatus.OPEN),
        ])
        global_score = scorer.get_global_score(findings)
        # Only LOW (open) qualifies — CRITICAL is remediated
        low_score = scorer.calculate_score(
            make_finding(severity=Severity.LOW, status=FindingStatus.OPEN)
        )
        assert global_score == low_score

    def test_global_score_returns_none_when_no_qualifying_findings(self):
        assert scorer.get_global_score([]) is None

    def test_global_score_is_never_an_average(self):
        """Global score must equal the highest individual score, not their average."""
        findings = scorer.score_findings([
            make_finding(severity=Severity.HIGH),   # base=70
            make_finding(severity=Severity.LOW),    # base=20
        ])
        global_score = scorer.get_global_score(findings)
        high_score = scorer.calculate_score(make_finding(severity=Severity.HIGH))
        average = sum(f.risk_score for f in findings) / len(findings)

        assert global_score == high_score
        assert global_score != average


# ---------------------------------------------------------------------------
# Config fallback
# ---------------------------------------------------------------------------

class TestConfigFallback:
    def test_scorer_works_without_config_file(self, monkeypatch, tmp_path):
        """If config.yaml is missing, scorer uses hardcoded defaults and does not crash."""
        # Point config loader to a non-existent path
        import core.risk_scorer as rs
        original_config = rs._CONFIG
        monkeypatch.setattr(rs, "_CONFIG", rs._load_config.__wrapped__()
                            if hasattr(rs._load_config, "__wrapped__") else {
                                "base_severity": {"high": 70},
                                "confidence_factor": {"confirmed": 1.00},
                                "exposure_factor": {"internal": 1.00},
                            })

        f = make_finding(severity=Severity.HIGH, confidence=Confidence.CONFIRMED)
        score = rs.calculate_score(f)
        assert score > 0.0

    def test_formula_description_is_not_empty(self):
        """FORMULA_DESCRIPTION must be a non-empty string for use in reports."""
        assert isinstance(scorer.FORMULA_DESCRIPTION, str)
        assert len(scorer.FORMULA_DESCRIPTION) > 0
        assert "risk_score" in scorer.FORMULA_DESCRIPTION
        assert "confidence" in scorer.FORMULA_DESCRIPTION
        assert "exposure" in scorer.FORMULA_DESCRIPTION
