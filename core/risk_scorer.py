"""
core/risk_scorer.py — Risk score calculation for SentinelX NetLab V1

This is the ONLY file that calculates risk_score.
No other module may compute or assign risk_score — this rule is enforced by grep at ticket close.

Formula (Section H of the steering document):
    risk_score = min(100, base_severity × confidence_factor × exposure_factor)

Base severity:
    If cvss_score is known  → base = cvss_score × 10
    Otherwise               → Critical=90, High=70, Medium=45, Low=20, Info=5

Confidence factor:
    Confidence.CONFIRMED (1.00) → ×1.00
    Confidence.PROBABLE  (0.85) → ×0.85
    Confidence.POSSIBLE  (0.60) → ×0.60

Exposure factor:
    Exposure.INTERNAL → ×1.00
    Exposure.EXTERNAL → ×1.15

Global network score = worst (highest) open Finding score — never an average.

Coefficients are loaded from config.yaml (project root).
This formula always appears in every generated report.

Rules enforced here:
- ZERO import sqlite3
- ZERO print()
- ONLY file that calculates risk_score
"""

import os
from pathlib import Path
from typing import List, Optional

from core.finding import Finding, Severity, Confidence, Exposure, FindingStatus

# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    """Load scoring coefficients from config.yaml at the project root.

    Falls back to hardcoded defaults if the file is missing or unreadable,
    so the scorer never crashes due to a missing config file.

    Returns:
        dict: Scoring coefficients with keys base_severity, confidence_factor,
              exposure_factor.
    """
    _DEFAULTS = {
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

    config_path = Path(__file__).parent.parent / "config.yaml"
    if not config_path.exists():
        return _DEFAULTS

    try:
        import yaml  # type: ignore
        with open(config_path, "r") as f:
            data = yaml.safe_load(f)
        return data.get("scoring", _DEFAULTS)
    except Exception:
        return _DEFAULTS


# Module-level config — loaded once at import time.
# Tests can override _CONFIG to inject custom coefficients without touching disk.
_CONFIG = _load_config()


# ---------------------------------------------------------------------------
# Core scoring function
# ---------------------------------------------------------------------------

def calculate_score(finding: Finding) -> float:
    """Calculate the risk score for a single Finding.

    Formula:
        risk_score = min(100, base_severity × confidence_factor × exposure_factor)

    The result is rounded to 2 decimal places for readability in reports.
    Findings with confidence < 0.7 (Confidence.POSSIBLE) still receive a score —
    it is the caller's responsibility to exclude them from the global score
    if needed (get_global_score does this automatically).

    Args:
        finding: Finding object. risk_score field is ignored — recalculated here.

    Returns:
        float: Calculated risk score, between 0.0 and 100.0 inclusive.
    """
    # Step 1 — Base severity
    if finding.cvss_score is not None:
        base = finding.cvss_score * 10.0
    else:
        base = float(
            _CONFIG["base_severity"].get(finding.severity.value, 5)
        )

    # Step 2 — Confidence factor
    # Confidence inherits from float, so it is already the numeric value (1.00, 0.85, 0.60).
    # We look it up from config by name to stay consistent with the config file.
    confidence_name = _confidence_name(finding.confidence)
    confidence_factor = float(
        _CONFIG["confidence_factor"].get(confidence_name, float(finding.confidence))
    )

    # Step 3 — Exposure factor
    exposure_factor = float(
        _CONFIG["exposure_factor"].get(finding.exposure.value, 1.00)
    )

    # Step 4 — Apply formula
    raw_score = base * confidence_factor * exposure_factor
    return round(min(100.0, raw_score), 2)


def _confidence_name(confidence: Confidence) -> str:
    """Return the config key name for a Confidence value.

    Args:
        confidence: Confidence enum value.

    Returns:
        str: "confirmed", "probable", or "possible".
    """
    return confidence.name.lower()


# ---------------------------------------------------------------------------
# Batch scoring
# ---------------------------------------------------------------------------

def score_findings(findings: List[Finding]) -> List[Finding]:
    """Calculate and assign risk_score to a list of Findings.

    Returns new Finding objects with risk_score set — does not mutate the
    originals. The caller is responsible for persisting the scores via
    core/database.update_finding_risk_score().

    Args:
        findings: List of Finding objects to score.

    Returns:
        List[Finding]: Same findings with risk_score populated.
    """
    import dataclasses

    scored = []
    for f in findings:
        score = calculate_score(f)
        scored.append(dataclasses.replace(f, risk_score=score))
    return scored


# ---------------------------------------------------------------------------
# Global network score
# ---------------------------------------------------------------------------

def get_global_score(findings: List[Finding]) -> Optional[float]:
    """Return the global network risk score for a session.

    Global score = highest risk_score among all OPEN findings
    with confidence >= 0.7 (i.e. CONFIRMED or PROBABLE).

    Findings with confidence < 0.7 (POSSIBLE) are excluded.
    Findings that are not OPEN (verified, remediated, accepted) are excluded.
    Never an average — the worst case drives the global score.

    Args:
        findings: List of Finding objects (risk_score must be set).

    Returns:
        Optional[float]: Highest score, or None if no qualifying findings exist.
    """
    qualifying = [
        f.risk_score
        for f in findings
        if f.status == FindingStatus.OPEN
        and f.risk_score is not None
        and float(f.confidence) >= 0.7
    ]

    return max(qualifying) if qualifying else None


# ---------------------------------------------------------------------------
# Formula string — always included in reports
# ---------------------------------------------------------------------------

FORMULA_DESCRIPTION = (
    "risk_score = min(100, base_severity × confidence_factor × exposure_factor)\n"
    "  base_severity : CVSS×10 if known — else Critical=90, High=70, Medium=45, Low=20, Info=5\n"
    "  confidence    : Confirmed×1.00 · Probable×0.85 · Possible×0.60\n"
    "  exposure      : External×1.15 · Internal×1.00\n"
    "  global score  : worst open Finding — never an average"
)
