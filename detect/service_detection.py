"""
detect/service_detection.py — CVE lookup and Finding enrichment

Pipeline step: DETECT (post-scan enrichment)
Role: Match detected service versions against the local CVE knowledge base
      and upgrade Finding severity + CVE refs accordingly.

This module takes Findings produced by tcp_scan/udp_scan (all at INFO severity)
and enriches them with:
  - CVE references (cve_refs)
  - CVSS score (cvss_score)
  - Upgraded severity (INFO → LOW/MEDIUM/HIGH/CRITICAL)

It reads from knowledge/cve_db.json — no internet, fully offline.

Rules enforced here:
- ZERO import sqlite3
- ZERO print() — display via core/logger.py
- ZERO risk_score calculation — that stays in core/risk_scorer.py
- ALWAYS return List[Finding] — enriched copies, originals untouched
- No network calls — local knowledge base only
- No Finding without evidence — if no CVE matches, Finding stays INFO

Version matching logic:
    An entry matches if:
      1. service name matches (case-insensitive)
      2. product name matches if specified (substring, case-insensitive)
      3. detected version is within [version_gte, version_lte] range
         (null bounds = match any version)

Confidence rules:
    - If CVE found AND version confirmed → keep existing confidence
    - If CVE found BUT version was POSSIBLE → upgrade to PROBABLE
      (we found a CVE match, so the service guess was meaningful)
    - If no CVE found → Finding stays as-is (INFO, same confidence)
"""

import json
import dataclasses
from pathlib import Path
from typing import List, Optional, Dict, Any
from packaging.version import Version, InvalidVersion

from core.finding import Finding, Severity, Confidence, Evidence
from core.logger import display


# ---------------------------------------------------------------------------
# Knowledge base loading
# ---------------------------------------------------------------------------

_KB_PATH = Path(__file__).parent.parent / "knowledge" / "cve_db.json"


def _load_kb(path: Path = _KB_PATH) -> List[Dict[str, Any]]:
    """Load the local CVE knowledge base from JSON.

    Falls back to empty list if file is missing or malformed.

    Args:
        path: Path to cve_db.json (injectable for tests).

    Returns:
        List[dict]: CVE entries from the knowledge base.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("entries", [])
    except Exception:
        return []


# Module-level cache — loaded once at import time.
# Tests can override _KB_ENTRIES to inject custom data.
_KB_ENTRIES: List[Dict[str, Any]] = _load_kb()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def enrich_findings(
    findings: List[Finding],
    asset_context: Optional[Dict[str, str]] = None,
) -> List[Finding]:
    """Enrich a list of Findings with CVE data from the local knowledge base.

    For each Finding, looks up matching CVE entries based on service name,
    product, and version. If a match is found, returns a new Finding with
    upgraded severity, CVE refs, and CVSS score.

    Does NOT mutate the original Finding objects — returns new copies.
    Does NOT calculate risk_score — that is core/risk_scorer.py's job.

    Args:
        findings:      List of Finding objects from tcp_scan or udp_scan.
        asset_context: Optional mapping of {target_ip: os_string} built from
                       device_fingerprint findings. When provided, used to
                       qualify CVE applicability for entries that require
                       version confirmation (e.g. EternalBlue). The OS string
                       is checked against not_affected_versions /
                       affected_versions in the KB entry. Never increases
                       confidence — can only exclude a CVE or confirm it.

    Returns:
        List[Finding]: Enriched copies. Unmatched Findings returned as-is.
    """
    enriched = []
    matched = 0

    for finding in findings:
        # Pass both service_version and target_service as product context
        # so entries with product="" still match service-level entries (e.g. SMB, RDP)
        product_context = finding.service_version or finding.target_service
        cve_entry = _lookup_cve(
            service=finding.target_service,
            product=product_context,
            version=_extract_version(finding.service_version),
            raw_version=finding.service_version,
        )

        if cve_entry:
            matched += 1
            enriched.append(_apply_cve(finding, cve_entry, asset_context=asset_context))
        else:
            enriched.append(finding)

    if matched:
        display(f"[green]Service detection: {matched}/{len(findings)} finding(s) matched CVE entries.[/green]")
    else:
        display(f"[dim]Service detection: no CVE matches found for {len(findings)} finding(s).[/dim]")

    return enriched


# ---------------------------------------------------------------------------
# CVE lookup
# ---------------------------------------------------------------------------

def _lookup_cve(
    service: str,
    product: str,
    version: Optional[str],
    kb_entries: Optional[List[Dict]] = None,
    raw_version: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Find the best matching CVE entry for a service/product/version.

    Returns the entry with the highest CVSS score if multiple entries match.
    Returns None if no entry matches.

    Matching rules:
      1. service name match (case-insensitive, partial OK)
      2. product match if entry.product is non-empty (substring, case-insensitive)
      3. version in range [version_gte, version_lte] — null bounds = any version

    Args:
        service:    Service name from Finding (e.g. "ssh", "http").
        product:    Product/version string from Finding.service_version.
        version:    Parsed version string (e.g. "7.4"), may be None.
        kb_entries: Override knowledge base (for testing).

    Returns:
        dict: Best matching CVE entry, or None.
    """
    entries = kb_entries if kb_entries is not None else _KB_ENTRIES
    candidates = []
    detected_version = raw_version if raw_version is not None else product
    qualification = _qualify_version(detected_version, version)

    for entry in entries:
        if not _service_matches(service, entry.get("service", "")):
            continue
        if not _product_matches(product, entry.get("product", "")):
            continue

        requires_confirmation = entry.get("requires_version_confirmation", False)
        if requires_confirmation:
            if qualification == "exact":
                if _matches_version_labels(
                    detected_version,
                    entry.get("not_affected_versions", []),
                ):
                    continue
                affected = entry.get("affected_versions")
                if affected and not _matches_version_labels(detected_version, affected):
                    continue
                if not _version_in_range(
                    version,
                    entry.get("version_gte"),
                    entry.get("version_lte"),
                ):
                    continue
            # Missing, ambiguous, or incomplete versions remain candidates:
            # _apply_cve() will mark them POSSIBLE rather than CONFIRMED.
        elif not _version_in_range(
            version,
            entry.get("version_gte"),
            entry.get("version_lte"),
        ):
            continue
        candidates.append(entry)

    if not candidates:
        return None

    # Return the highest CVSS score match
    return max(candidates, key=lambda e: e.get("cvss_score", 0.0))


def _service_matches(detected: str, entry_service: str) -> bool:
    """Check if detected service name matches an entry's service field.

    Case-insensitive. The detected name must contain or equal the entry service.

    Args:
        detected:      Service name from Finding (e.g. "microsoft-ds").
        entry_service: Service in the CVE entry (e.g. "microsoft-ds").

    Returns:
        bool
    """
    if not entry_service:
        return False
    return entry_service.lower() in detected.lower() or detected.lower() in entry_service.lower()


def _product_matches(detected_version_str: str, entry_product: str) -> bool:
    """Check if the detected product/version string contains the entry's product name.

    If entry product is empty → matches anything (service-level entry).

    Args:
        detected_version_str: service_version from Finding (e.g. "OpenSSH 7.4").
        entry_product:        Product name in CVE entry (e.g. "OpenSSH").

    Returns:
        bool
    """
    if not entry_product:
        return True  # no product constraint — match any
    return entry_product.lower() in detected_version_str.lower()


def _qualify_version(raw_version: str, parsed_version: Optional[str]) -> str:
    """Classify a banner as exact, ambiguous, or incomplete.

    This deliberately does not decide CVE applicability. It only determines
    whether the banner is precise enough for a KB entry requiring confirmation.
    """
    import re

    text = (raw_version or "").strip()
    if not text:
        return "missing"
    if re.search(r"\s(?:-|–|—|to)\s|\d\s*/\s*\d|\b(?:or|and)\b|[0-9][+*]", text, re.IGNORECASE):
        return "ambiguous"
    if parsed_version:
        if re.search(r"\b\d+(?:\.\d+)*\.(?:x|X|\*)\b|\b\d+(?:\.x|\.X|\.\*)", text):
            return "incomplete"
        return "exact"
    # Windows banners often identify an exact release without semver syntax.
    if re.search(
        r"\b(?:windows\s+(?:server\s+)?(?:xp|vista|7|8(?:\.1)?|10|11)|"
        r"windows\s+server\s+\d{4}(?:\s+r\d)?)\b",
        text,
        re.IGNORECASE,
    ):
        return "exact"
    return "incomplete"


def _matches_version_labels(raw_version: str, labels: List[str]) -> bool:
    """Return whether one exact banner contains one KB OS/version label."""
    normalized = " ".join((raw_version or "").lower().split())
    return any(" ".join(str(label).lower().split()) in normalized for label in labels)


def _version_in_range(
    version: Optional[str],
    gte: Optional[str],
    lte: Optional[str],
) -> bool:
    """Check if a version string falls within [gte, lte] range.

    If version is None or unparseable → matches only if both bounds are None.
    If a bound is None → that bound is unconstrained.

    Args:
        version: Detected version string (e.g. "7.4").
        gte:     Minimum version (inclusive), or None.
        lte:     Maximum version (inclusive), or None.

    Returns:
        bool
    """
    if gte is None and lte is None:
        return True  # no version constraint — matches any

    if version is None:
        return False  # version required but not detected

    try:
        v = Version(version)
        if gte is not None and v < Version(gte):
            return False
        if lte is not None and v > Version(lte):
            return False
        return True
    except InvalidVersion:
        return False


def _extract_version(service_version: str) -> Optional[str]:
    """Extract the first version-like token from a service_version string.

    Examples:
        "OpenSSH 7.4 protocol 2.0" → "7.4"
        "Apache httpd 2.4.49"      → "2.4.49"
        "nginx 1.18.0"             → "1.18.0"
        "Microsoft Windows Server 2019" → None (no semver-like token)
        ""                          → None

    Args:
        service_version: service_version field from Finding.

    Returns:
        str: First version-like token, or None.
    """
    import re
    if not service_version:
        return None
    # Match tokens like 1.2, 1.2.3, 1.2.3.4 — must start with a digit
    matches = re.findall(r"\b\d+\.\d+(?:\.\d+)*\b", service_version)
    return matches[0] if matches else None


# ---------------------------------------------------------------------------
# Finding enrichment
# ---------------------------------------------------------------------------

def _apply_cve(
    finding: Finding,
    cve_entry: Dict[str, Any],
    asset_context: Optional[Dict[str, str]] = None,
) -> Finding:
    """Return a new Finding enriched with CVE data.

    Never mutates the original Finding.
    Never sets risk_score — that is risk_scorer.py's responsibility.

    Confidence rules:
        1. If entry has requires_version_confirmation=True AND service_version
           is empty → confidence forced to POSSIBLE (0.60).
           The CVE severity is preserved — the uncertainty is in the
           applicability, not the potential impact.
           A warning note is appended to evidence.raw.
           risk_scorer will automatically exclude this Finding from the
           global score because confidence < 0.7.

        2. If asset_context provides an OS for this IP and the entry requires
           version confirmation:
           - OS in not_affected_versions → return original Finding unchanged
             (CVE does not apply to this OS; no enrichment).
           - OS in affected_versions → enrich with original confidence
             (confirmed affected; no confidence upgrade beyond what banner allows).
           - OS in neither list → fall through to rule 1 (POSSIBLE).

        3. Otherwise (version confirmed, or no confirmation required):
           POSSIBLE → PROBABLE upgrade if CVE was matched (existing rule).

    Safety constraint: asset_context OS comes from device_fingerprint which has
    confidence=POSSIBLE (nmap estimation). It can only exclude a CVE (not_affected)
    or confirm applicability (affected). It never upgrades confidence above the
    Finding's existing confidence.

    Args:
        finding:       Original Finding from tcp_scan/udp_scan.
        cve_entry:     Matching CVE entry from the knowledge base.
        asset_context: Optional {target_ip: os_string} from device_fingerprint.

    Returns:
        Finding: New enriched copy, or original Finding if CVE not applicable.
    """
    new_severity = Severity(cve_entry.get("severity", "info"))
    new_cvss = cve_entry.get("cvss_score")
    new_cve_refs = cve_entry.get("cve_refs", [])
    requires_version = cve_entry.get("requires_version_confirmation", False)

    version_qualification = _qualify_version(
        finding.service_version,
        _extract_version(finding.service_version),
    )

    # ── Asset context qualification ──────────────────────────────────────────
    # Only applies when the KB entry requires version confirmation AND the
    # banner alone is not exact enough.
    if requires_version and version_qualification != "exact" and asset_context:
        os_name = asset_context.get(finding.target_ip, "")
        if os_name:
            not_affected = cve_entry.get("not_affected_versions", [])
            affected = cve_entry.get("affected_versions", [])

            if _matches_version_labels(os_name, not_affected):
                # OS is confirmed not affected — skip CVE enrichment entirely.
                # Return the original Finding without any CVE data.
                return finding

            if affected and _matches_version_labels(os_name, affected):
                # OS is confirmed affected — enrich with original confidence.
                # Do NOT upgrade confidence: the OS came from device_fingerprint
                # which is itself a POSSIBLE-confidence estimation.
                return dataclasses.replace(
                    finding,
                    severity=new_severity,
                    cvss_score=new_cvss,
                    cve_refs=new_cve_refs,
                    # confidence unchanged — never upgrade via OS context
                    evidence=Evidence(
                        raw=finding.evidence.raw + (
                            "\n[service_detection] OS confirmed in affected versions "
                            f"({os_name}) via device_fingerprint context."
                        ),
                        command=finding.evidence.command,
                    ),
                )
            # OS present but not in either list → fall through to banner-only logic

    # ── Banner-only qualification (original logic) ───────────────────────────
    if requires_version and version_qualification != "exact":
        # Version required but missing, ambiguous, or incomplete — preserve
        # severity but lower confidence because applicability is unconfirmed.
        new_confidence = Confidence.POSSIBLE
        version_note = (
            "\n[service_detection] Version not confirmed. "
            "CVE refs are potentially applicable but exploitability cannot "
            "be assessed without version confirmation. "
            "Confidence set to POSSIBLE — excluded from global risk score."
        )
        enriched_evidence = Evidence(
            raw=finding.evidence.raw + version_note,
            command=finding.evidence.command,
        )
    else:
        # Version confirmed or no confirmation required
        # Existing rule: POSSIBLE → PROBABLE when CVE matched
        new_confidence = (
            Confidence.PROBABLE
            if finding.confidence == Confidence.POSSIBLE
            else finding.confidence
        )
        enriched_evidence = finding.evidence

    return dataclasses.replace(
        finding,
        severity=new_severity,
        cvss_score=new_cvss,
        cve_refs=new_cve_refs,
        confidence=new_confidence,
        evidence=enriched_evidence,
        # risk_score stays None — set by risk_scorer only
    )
