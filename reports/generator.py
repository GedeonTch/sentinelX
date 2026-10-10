"""
reports/generator.py — Report generation for SentinelX NetLab V1

Formats supported:
    html — Full report with SentinelX design, CSS embedded, logo in top-left
    json — Raw export of all Findings for a session

PDF is explicitly out of scope for V1. The HTML report can be printed to PDF
from any browser (File → Print → Save as PDF).

Rules enforced here:
- ZERO import sqlite3
- ZERO print() — display via core/logger.py
- ZERO risk_score calculation
- Reads Findings and scan outcomes from DB via core/database.py
- Scoring formula ALWAYS appears in every generated report
- Logo (SentinelleX.png) copied alongside the HTML output file

HTML sections (T20): machines, security findings (Top 5 first), inventory
observations and recommendations are separate. Completeness and discovery
states come from core/assessment.py. The JSON export keeps its public keys.

Usage:
    from reports.generator import generate_report
    generate_report(session_id="session-001", format="html",
                    output_path="/tmp/report.html")
"""

import ipaddress
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import jinja2

from core.assessment import (
    compute_assessment_completeness,
    compute_discovery_state,
)
from core.database import get_findings, get_scan_outcomes, get_session
from core.finding import Finding, Severity
from core.logger import display
from core.risk_scorer import FORMULA_DESCRIPTION


# ---------------------------------------------------------------------------
# Paths and constants
# ---------------------------------------------------------------------------

_REPORTS_DIR = Path(__file__).parent
_TEMPLATE_DIR = _REPORTS_DIR / "templates"
_ASSETS_DIR = _REPORTS_DIR / "assets"
_LOGO_FILENAME = "SentinelleX.png"

# Number of security findings shown before "Voir plus" in the HTML report.
_TOP_FINDINGS_LIMIT = 5

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate_report(
    session_id: str,
    format: str,
    output_path: str,
) -> bool:
    """Generate a report for a session in the requested format.

    Args:
        session_id:  Session identifier.
        format:      "html" or "json".
        output_path: Absolute or relative path to write the output file.

    Returns:
        bool: True if report was generated successfully, False otherwise.
    """
    format = format.lower().strip()
    if format not in ("html", "json"):
        display(f"[red]Unsupported format: '{format}'. Use 'html' or 'json'.[/red]")
        return False

    try:
        findings = get_findings(session_id)
        session = get_session(session_id)
        # Scan outcomes only feed the HTML completeness indicators (T20).
        scan_outcomes = get_scan_outcomes(session_id) if format == "html" else None
    except Exception:
        display(f"[red]Session '{session_id}' not found or DB error.[/red]")
        return False

    if session is None:
        display(f"[red]Session '{session_id}' not found.[/red]")
        return False

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    if format == "json":
        return _generate_json(findings, session, output)
    return _generate_html(findings, session, output, scan_outcomes=scan_outcomes)


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------

def _generate_json(
    findings: List[Finding],
    session: dict,
    output: Path,
) -> bool:
    """Export all Findings as a JSON file.

    Args:
        findings: List of Finding objects.
        session:  Session dict from DB.
        output:   Output file path.

    Returns:
        bool: True on success.
    """
    try:
        payload = {
            "report_generated_at": datetime.now(timezone.utc).isoformat(),
            "session": session,
            "scoring_formula": _report_formula_description(),
            "findings_count": len(findings),
            "summary": _build_summary(findings),
            "findings": [_finding_payload(f) for f in findings],
        }
        output.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        display(f"[green]JSON report written to {output}[/green]")
        return True
    except Exception as exc:
        display(f"[red]JSON report error: {exc}[/red]")
        return False


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

def _generate_html(
    findings: List[Finding],
    session: dict,
    output: Path,
    scan_outcomes: Optional[List[dict]] = None,
) -> bool:
    """Generate a full HTML report with SentinelX design.

    Copies the logo to the same directory as the output file so the <img>
    reference resolves correctly when opened in a browser.

    Args:
        findings:      List of Finding objects.
        session:       Session dict from DB.
        output:        Output file path.
        scan_outcomes: Rows from get_scan_outcomes(), or None when the session
                       has no reliable scan data (legacy session).

    Returns:
        bool: True on success.
    """
    try:
        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=jinja2.select_autoescape(["html"]),
        )
        template = env.get_template("report.html")

        # Compute summary stats from persisted current Finding state.
        severity_counts = _count_by_severity(findings)
        summary = _build_summary(findings)
        worst_current_threat = summary["worst_current_threat"]
        open_findings = [
            f for f in findings
            if f.status.value == "open" and not _is_inventory_observation(f)
        ]
        critical_high = [
            f for f in open_findings
            if f.severity.value in ("critical", "high")
        ]
        host_map = _build_host_map(findings)

        security_findings = _sort_security_findings(
            [f for f in findings if not _is_inventory_observation(f)]
        )
        recommendations = [
            f for f in security_findings
            if f.explanation and f.explanation.defense
        ]
        inventory_findings = sorted(
            (f for f in findings if _is_inventory_observation(f)),
            key=lambda f: (_ip_sort_key(f.target_ip), f.created_at or ""),
        )

        observed_ips = _observed_ips(findings)
        discovery = compute_discovery_state(session.get("discover_status"))
        completeness = compute_assessment_completeness(
            observed_ips, _tcp_completed_ips(scan_outcomes),
        )
        machines = _build_machines(findings, observed_ips, host_map, scan_outcomes)

        rendered = template.render(
            session=session,
            findings=findings,
            open_findings=open_findings,
            critical_high=critical_high,
            severity_counts=severity_counts,
            summary=summary,
            worst_current_threat=worst_current_threat,
            gauge_level=_gauge_level(worst_current_threat),
            formula=_report_formula_description(),
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            logo_filename=_LOGO_FILENAME,
            host_map=host_map,
            has_recommendations=bool(recommendations),
            security_findings=security_findings,
            recommendations=recommendations,
            inventory_findings=inventory_findings,
            top_limit=_TOP_FINDINGS_LIMIT,
            discovery=discovery,
            completeness=completeness,
            machines=machines,
        )

        output.write_text(rendered, encoding="utf-8")

        # Copy logo alongside the report
        logo_src = _ASSETS_DIR / _LOGO_FILENAME
        logo_dst = output.parent / _LOGO_FILENAME
        if logo_src.exists() and not logo_dst.exists():
            shutil.copy2(logo_src, logo_dst)

        display(f"[green]HTML report written to {output}[/green]")
        return True
    except Exception as exc:
        display(f"[red]HTML report error: {exc}[/red]")
        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _count_by_severity(findings: List[Finding]) -> dict:
    """Return a count dict by severity for open findings."""
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        if f.status.value == "open" and not _is_inventory_observation(f):
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts


def _compute_worst_current_threat(findings: List[Finding]) -> Optional[float]:
    """Return the highest current risk among persisted OPEN Findings."""
    scores = [
        f.risk_score
        for f in findings
        if f.status.value == "open"
        and not _is_inventory_observation(f)
        and f.risk_score is not None
    ]
    return max(scores) if scores else None


def _gauge_level(worst_current_threat: Optional[float]) -> str:
    """Map the worst current threat to the gauge colour level (display only)."""
    if worst_current_threat is None:
        return "none"
    if worst_current_threat >= 70:
        return "critical"
    if worst_current_threat >= 45:
        return "high"
    if worst_current_threat >= 20:
        return "medium"
    return "low"


def _report_formula_description() -> str:
    """Describe scoring without reviving the retired network-score label."""
    lines = [
        line for line in FORMULA_DESCRIPTION.splitlines()
        if not line.strip().lower().startswith("global")
    ]
    lines.append("  Worst Current Threat : highest current risk_score among OPEN Findings")
    return "\n".join(lines)


def _is_inventory_observation(finding: Finding) -> bool:
    """Return whether a persisted record is inventory, not a vulnerability."""
    return finding.module == "device_fingerprint"


def _finding_payload(finding: Finding) -> dict:
    """Serialize a Finding with explicit current-versus-historical semantics."""
    payload = finding.to_dict()
    is_open = finding.status.value == "open"
    payload["current_risk_score"] = finding.risk_score if is_open else None
    payload["risk_scope"] = "current" if is_open else "historical_only"
    payload["kind"] = (
        "observation" if finding.module == "device_fingerprint" else "finding"
    )
    return payload


def _build_summary(findings: List[Finding]) -> dict:
    """Build report counters from the persisted Finding collection."""
    open_findings = [
        f for f in findings
        if f.status.value == "open" and not _is_inventory_observation(f)
    ]
    verified_findings = [
        f for f in findings
        if f.status.value == "verified" and not _is_inventory_observation(f)
    ]
    observations = [f for f in findings if _is_inventory_observation(f)]
    return {
        "total_findings": len(findings),
        "open_findings": len(open_findings),
        "verified_findings": len(verified_findings),
        "inventory_observations": len(observations),
        "worst_current_threat": _compute_worst_current_threat(findings),
    }


def _build_host_map(findings: List[Finding]) -> dict:
    """Build a {ip: {os, ports}} map from Findings for the Network Overview.

    Only uses data actually present in Findings — never invents hosts or ports.

    Args:
        findings: List of Finding objects.

    Returns:
        dict: {ip: {"os": str, "ports": List[int]}}
    """
    hosts: dict = {}
    for f in findings:
        ip = f.target_ip
        if not ip:
            continue
        if ip not in hosts:
            hosts[ip] = {"os": "", "ports": []}
        # OS from device_fingerprint findings
        if f.module == "device_fingerprint" and f.service_version:
            hosts[ip]["os"] = f.service_version
        # Ports from tcp_scan findings
        if f.target_port is not None and f.target_port not in hosts[ip]["ports"]:
            hosts[ip]["ports"].append(f.target_port)
    # Sort ports per host
    for ip in hosts:
        hosts[ip]["ports"].sort()
    return hosts


# ---------------------------------------------------------------------------
# HTML helpers (T20): machines, completeness inputs, ordering
# ---------------------------------------------------------------------------

def _ip_sort_key(ip: Optional[str]) -> tuple:
    """Sort IP addresses numerically; anything else sorts after them as text."""
    try:
        return (0, int(ipaddress.ip_address(ip or "")), "")
    except ValueError:
        return (1, 0, ip or "")


def _observed_ips(findings: List[Finding]) -> List[str]:
    """Machines observed by discovery: IPs with a device_fingerprint Finding."""
    return sorted(
        {f.target_ip for f in findings if _is_inventory_observation(f) and f.target_ip},
        key=_ip_sort_key,
    )


def _tcp_completed_ips(scan_outcomes: Optional[List[dict]]) -> Optional[set]:
    """IPs whose TCP scan completed, or None when no reliable data exists."""
    if scan_outcomes is None:
        return None
    return {
        row["target_ip"]
        for row in scan_outcomes
        if row["module"] == "tcp_scan" and row["outcome"] == "completed"
    }


def _host_outcomes(scan_outcomes: Optional[List[dict]]) -> dict:
    """Return {ip: {module: {"outcome": str, "open_ports": int}}}."""
    result: dict = {}
    for row in scan_outcomes or []:
        result.setdefault(row["target_ip"], {})[row["module"]] = {
            "outcome": row["outcome"],
            "open_ports": row["open_ports"],
        }
    return result


def _module_status(host_outcomes: dict, module: str, legacy: bool) -> dict:
    """Describe how one scan module ended for one machine, without guessing.

    A machine with no recorded row is shown as "not recorded": it is never
    presented as a completed scan.
    """
    if legacy:
        return {
            "state": "unknown",
            "label": "Unknown: legacy session without scan data",
            "open_ports": None,
        }
    row = host_outcomes.get(module)
    if row is None:
        return {"state": "not_recorded", "label": "Not recorded in this session", "open_ports": None}
    outcome = row["outcome"]
    if outcome == "completed":
        return {"state": "completed", "label": "Completed", "open_ports": row["open_ports"]}
    return {"state": outcome, "label": outcome.capitalize(), "open_ports": None}


def _build_machines(
    findings: List[Finding],
    observed_ips: List[str],
    host_map: dict,
    scan_outcomes: Optional[List[dict]],
) -> List[dict]:
    """One entry per observed machine, for the per-machine section."""
    legacy = scan_outcomes is None
    outcomes = _host_outcomes(scan_outcomes)

    security_count: dict = {}
    inventory_count: dict = {}
    open_tcp: dict = {}
    open_udp: dict = {}
    for f in findings:
        if _is_inventory_observation(f):
            inventory_count[f.target_ip] = inventory_count.get(f.target_ip, 0) + 1
            continue
        security_count[f.target_ip] = security_count.get(f.target_ip, 0) + 1
        if f.target_port is None:
            continue
        if f.module == "tcp_scan":
            open_tcp.setdefault(f.target_ip, set()).add(f.target_port)
        elif f.module == "udp_scan":
            open_udp.setdefault(f.target_ip, set()).add(f.target_port)

    machines = []
    for ip in observed_ips:
        host = host_map.get(ip, {"os": "", "ports": []})
        machines.append({
            "ip": ip,
            "os": host["os"],
            "tcp": _module_status(outcomes.get(ip, {}), "tcp_scan", legacy),
            "udp": _module_status(outcomes.get(ip, {}), "udp_scan", legacy),
            "tcp_ports": sorted(open_tcp.get(ip, set())),
            "udp_ports": sorted(open_udp.get(ip, set())),
            "security_count": security_count.get(ip, 0),
            "inventory_count": inventory_count.get(ip, 0),
        })
    return machines


def _sort_security_findings(findings: List[Finding]) -> List[Finding]:
    """Order security findings: current open risk first (Top 5 of the report).

    Open findings come first, by descending current risk_score (unscored last),
    then by severity, then by machine and port. Other statuses follow, so a
    verified or remediated finding never outranks a current one.
    """
    def key(f: Finding):
        is_open = f.status.value == "open"
        current_score = f.risk_score if (is_open and f.risk_score is not None) else -1.0
        return (
            0 if is_open else 1,
            -current_score,
            -_SEVERITY_RANK.get(f.severity.value, 0),
            _ip_sort_key(f.target_ip),
            f.target_port or 0,
        )

    return sorted(findings, key=key)
