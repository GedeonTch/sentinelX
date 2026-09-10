"""
detect/smb_enum.py — SMB share / user / domain enumeration via enum4linux

Pipeline step: DETECT
Role: Enumerate SMB shares, users, and domain information on a Windows host.
      One Finding per detected share, plus one Finding for domain info
      when a domain or workgroup name is present in the output.

Does not calculate risk_score. Does not write to SQLite. Does not print().

Rules enforced here:
- ZERO import sqlite3
- ZERO print() — display via core/logger.py
- ZERO risk_score calculation
- ALWAYS return List[Finding]
- ALWAYS ask (y/n) confirmation before sending traffic
- explanation stays None (no knowledge-base rule wired here)
- evidence.raw is the raw enum4linux stdout
"""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import List, Optional, Tuple

import typer

from core.finding import (
    Category,
    Confidence,
    Evidence,
    Exposure,
    Finding,
    Severity,
)
from core.logger import display

MODULE_NAME = "smb_enum"
SMB_PORT = 445
ENUM4LINUX_TIMEOUT_SECONDS = 120

_SHARE_ROW = re.compile(
    r"^\s*([A-Za-z0-9._$-]+)\s+(Disk|IPC|Printer)\b",
    re.IGNORECASE,
)
_SHARE_HEADER_NAMES = frozenset({"sharename", "---------"})
_DOMAIN_PATTERNS = (
    re.compile(r"Domain Name:\s*(\S+)", re.IGNORECASE),
    re.compile(r"Got domain/workgroup name:\s*(\S+)", re.IGNORECASE),
    re.compile(r"\[.\]\s+Got domain name:\s*(\S+)", re.IGNORECASE),
    re.compile(r"Workgroup:\s*(\S+)", re.IGNORECASE),
)


def smb_enum(target_ip: str, session_id: str) -> List[Finding]:
    """Enumerate SMB shares and domain info on a Windows host.

    Asks for (y/n) confirmation before running enum4linux. Returns an
    empty list when the tool is missing, the user cancels, or output is
    empty — never raises for those cases.

    Args:
        target_ip: IPv4 address of the Windows host.
        session_id: Current audit session ID.

    Returns:
        List[Finding]: One Finding per detected share, plus one domain
        Finding when domain information is available.
    """
    if shutil.which("enum4linux") is None:
        display("[red]enum4linux not found. Run 'netlab doctor'.[/red]")
        return []

    confirmed = typer.confirm(
        f"[smb_enum] Enumerate SMB shares, users and domain on {target_ip}?"
    )
    if not confirmed:
        display("[yellow]SMB enumeration cancelled.[/yellow]")
        return []

    display(f"[cyan]Starting enum4linux on {target_ip}...[/cyan]")
    raw_output = _run_enum4linux(target_ip)
    if not raw_output:
        display(f"[yellow]No output from enum4linux on {target_ip}.[/yellow]")
        return []

    findings = _parse_enum4linux_output(raw_output, target_ip, session_id)
    if findings:
        display(
            f"[green]SMB enumeration complete — {len(findings)} finding(s).[/green]"
        )
    else:
        display(
            f"[yellow]SMB enumeration complete — no shares or domain info on {target_ip}.[/yellow]"
        )
    return findings


def _run_enum4linux(target_ip: str) -> Optional[str]:
    """Run enum4linux and return stdout, or None on error / empty output.

    Args:
        target_ip: IPv4 address of the Windows host.

    Returns:
        Optional[str]: Raw stdout, or None.
    """
    command = ["enum4linux", "-a", target_ip]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=ENUM4LINUX_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        display("[red]enum4linux not found. Run 'netlab doctor'.[/red]")
        return None
    except subprocess.TimeoutExpired:
        display("[yellow]enum4linux timed out.[/yellow]")
        return None
    except OSError as exc:
        display(f"[red]enum4linux error: {exc}[/red]")
        return None

    combined = f"{result.stdout or ''}{result.stderr or ''}"
    stripped = combined.strip()
    if not stripped:
        return None
    return combined


def _parse_enum4linux_output(
    raw_output: str,
    target_ip: str,
    session_id: str,
) -> List[Finding]:
    """Build Findings from raw enum4linux output.

    Args:
        raw_output: Full stdout/stderr from enum4linux.
        target_ip: Host that was enumerated.
        session_id: Current audit session ID.

    Returns:
        List[Finding]: Share findings, then an optional domain finding.
    """
    command = f"enum4linux -a {target_ip}"
    findings: List[Finding] = []
    seen_shares: set[str] = set()

    for share_name in _extract_share_names(raw_output):
        key = share_name.upper()
        if key in seen_shares:
            continue
        seen_shares.add(key)
        category, severity = _classify_share(share_name)
        findings.append(
            _make_finding(
                session_id=session_id,
                target_ip=target_ip,
                target_service=share_name,
                category=category,
                severity=severity,
                raw_output=raw_output,
                command=command,
            )
        )

    domain_name = _extract_domain_name(raw_output)
    if domain_name is not None:
        findings.append(
            _make_finding(
                session_id=session_id,
                target_ip=target_ip,
                target_service=domain_name,
                category=Category.NETWORK,
                severity=Severity.INFO,
                raw_output=raw_output,
                command=command,
            )
        )

    return findings


def _extract_share_names(raw_output: str) -> List[str]:
    """Return share names parsed from an enum4linux share table.

    Args:
        raw_output: Full enum4linux output.

    Returns:
        List[str]: Share names in the order they appeared.
    """
    names: List[str] = []
    for line in raw_output.splitlines():
        match = _SHARE_ROW.match(line)
        if match is None:
            continue
        name = match.group(1)
        if name.lower() in _SHARE_HEADER_NAMES or set(name) <= {"-"}:
            continue
        names.append(name)
    return names


def _extract_domain_name(raw_output: str) -> Optional[str]:
    """Return a domain or workgroup name if enum4linux reported one.

    Args:
        raw_output: Full enum4linux output.

    Returns:
        Optional[str]: Domain/workgroup name, or None if not available.
    """
    for pattern in _DOMAIN_PATTERNS:
        match = pattern.search(raw_output)
        if match is None:
            continue
        name = match.group(1).strip().strip("'\"")
        if name and name.upper() not in {"(NULL)", "NULL", "UNKNOWN", "N/A"}:
            return name
    return None


def _classify_share(share_name: str) -> Tuple[Category, Severity]:
    """Return category and severity for a detected share.

    ADMIN$ is specified by the ticket: CREDENTIAL / MEDIUM.
    Other shares are reported as SERVICE / INFO (confirmed observation).

    Args:
        share_name: Share name as printed by enum4linux.

    Returns:
        Tuple[Category, Severity]: Classification for this share.
    """
    if share_name.upper() == "ADMIN$":
        return Category.CREDENTIAL, Severity.MEDIUM
    return Category.SERVICE, Severity.INFO


def _make_finding(
    session_id: str,
    target_ip: str,
    target_service: str,
    category: Category,
    severity: Severity,
    raw_output: str,
    command: str,
) -> Finding:
    """Construct a Finding for this module. risk_score and explanation stay None.

    Args:
        session_id: Current audit session ID.
        target_ip: Host that was enumerated.
        target_service: Share name or domain name.
        category: Finding category.
        severity: Finding severity.
        raw_output: Full enum4linux stdout (evidence.raw).
        command: Exact command that produced the output.

    Returns:
        Finding: Populated Finding with confidence CONFIRMED.
    """
    return Finding(
        session_id=session_id,
        module=MODULE_NAME,
        target_ip=target_ip,
        target_port=SMB_PORT,
        target_service=target_service,
        category=category,
        severity=severity,
        confidence=Confidence.CONFIRMED,
        exposure=Exposure.INTERNAL,
        evidence=Evidence(raw=raw_output, command=command),
        explanation=None,
        risk_score=None,
    )
