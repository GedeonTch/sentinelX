"""
detect/udp_scan.py — UDP port scanner

Pipeline step: DETECT
Role: Identify open UDP ports on a target host.
      One Finding per open port — never for closed or open|filtered ports.

UDP scanning is fundamentally different from TCP:
  - No handshake — nmap sends a UDP packet and waits
  - "open" means a response was received (rare — most services don't reply)
  - "open|filtered" means no response — could be open or firewalled
  - "closed" means an ICMP port unreachable was received

Only "open" ports produce Findings. "open|filtered" are excluded —
they cannot be confirmed without a service-specific probe.

nmap command used:
    nmap -sU --version-intensity 5 -oX - -p <ports> <target>

    -sU : UDP scan (requires root on Linux)

Confidence rules:
    CONFIRMED — port responded (rare for UDP)
    PROBABLE  — service version detected from response
    POSSIBLE  — open|filtered → excluded from Findings (not reported)

Rules enforced here:
- ZERO import sqlite3
- ZERO print() — display via core/logger.py
- ZERO risk_score calculation
- ALWAYS return List[Finding] — one per confirmed open UDP port
- ALWAYS ask (y/n) confirmation before scan
- NEVER report closed or open|filtered ports
"""

import subprocess
import xml.etree.ElementTree as ET
from typing import List, Optional

import typer

from core.finding import (
    Finding,
    Evidence,
    Category,
    Severity,
    Confidence,
    Exposure,
)
from core.logger import display
from rich.progress import Progress, SpinnerColumn, TextColumn


# Top UDP ports — scanning all 65535 UDP ports takes hours
DEFAULT_UDP_PORTS = "53,67,68,69,123,137,138,139,161,162,500,514,520,1194,1900,4500,5353"

PROFILE_FLAGS = {
    "normal":     ["-sU", "--version-intensity", "5", "-T3"],
    "stealth":    ["-sU", "--version-intensity", "3", "-T2"],
    "aggressive": ["-sU", "--version-intensity", "7", "-T4"],
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def udp_scan(
    target: str,
    session_id: str,
    profile: str = "normal",
    ports: str = DEFAULT_UDP_PORTS,
    auto_confirm: bool = False,
) -> List[Finding]:
    """Scan UDP ports on a target and return one Finding per confirmed open port.

    Requires root/sudo on Linux for raw socket access.
    Asks for (y/n) confirmation before sending any traffic,
    unless auto_confirm=True (used by netlab scan --yes pipeline).

    Args:
        target:       IP address or hostname to scan.
        session_id:   Current audit session ID.
        profile:      Scan profile — normal, stealth, aggressive.
        ports:        Port list/range (nmap format).
        auto_confirm: If True, skip the (y/n) prompt. Default False.

    Returns:
        List[Finding]: One Finding per confirmed open UDP port.
    """
    if profile not in PROFILE_FLAGS:
        display(f"[red]Unknown profile '{profile}'. Using 'normal'.[/red]")
        profile = "normal"

    if not auto_confirm:
        confirmed = typer.confirm(
            f"[udp_scan] Scan UDP ports on {target} (profile: {profile})? "
            f"[requires root, may be slow]"
        )
        if not confirmed:
            display("[yellow]UDP scan cancelled.[/yellow]")
            return []

    display(f"[cyan]Starting UDP scan on {target} (profile: {profile})...[/cyan]")
    display("[dim]UDP scanning is slow — only common ports are scanned by default.[/dim]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}[/cyan]"),
        transient=True,
    ) as progress:
        progress.add_task(f"nmap UDP scan → {target}", total=None)
        xml_output = _run_nmap_udp(target, profile, ports)

    if not xml_output:
        display(f"[yellow]No response from nmap UDP scan on {target}.[/yellow]")
        return []

    findings = _parse_udp_xml(xml_output, target, session_id)

    if findings:
        display(f"[green]UDP scan complete — {len(findings)} open port(s) found.[/green]")
    else:
        display(f"[yellow]UDP scan complete — no confirmed open UDP ports on {target}.[/yellow]")

    return findings


# ---------------------------------------------------------------------------
# nmap subprocess
# ---------------------------------------------------------------------------

def _run_nmap_udp(target: str, profile: str, ports: str) -> Optional[str]:
    """Run nmap UDP scan and return raw XML output.

    Args:
        target:  IP or hostname.
        profile: Scan profile key.
        ports:   Port list/range string.

    Returns:
        str: Raw XML from nmap, or None on error.
    """
    flags = PROFILE_FLAGS.get(profile, PROFILE_FLAGS["normal"])
    cmd = ["nmap"] + flags + ["-oX", "-", "-p", ports, target]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # UDP scans are slower
        )
        if result.returncode not in (0, 1):
            display(f"[yellow]nmap warning (exit {result.returncode}): "
                    f"{result.stderr.strip()[:200]}[/yellow]")
        return result.stdout if result.stdout.strip() else None
    except FileNotFoundError:
        display("[red]nmap not found. Run 'netlab doctor'.[/red]")
        return None
    except subprocess.TimeoutExpired:
        display("[yellow]nmap UDP scan timed out after 600s.[/yellow]")
        return None
    except Exception as exc:
        display(f"[red]nmap error: {exc}[/red]")
        return None


# ---------------------------------------------------------------------------
# XML parser
# ---------------------------------------------------------------------------

def _parse_udp_xml(
    xml_output: str,
    target: str,
    session_id: str,
) -> List[Finding]:
    """Parse nmap XML output and build one Finding per confirmed open UDP port.

    Only ports with state="open" produce a Finding.
    "open|filtered" and "closed" are explicitly excluded.

    Args:
        xml_output: Raw XML string from nmap.
        target:     IP or hostname scanned.
        session_id: Current audit session ID.

    Returns:
        List[Finding]: One per confirmed open UDP port.
    """
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        display("[red]Failed to parse nmap UDP XML output.[/red]")
        return []

    findings = []

    for host in root.findall("host"):
        addr_elem = host.find("address[@addrtype='ipv4']")
        host_ip = addr_elem.get("addr", target) if addr_elem is not None else target

        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            if port_elem.get("protocol") != "udp":
                continue

            state_elem = port_elem.find("state")
            if state_elem is None:
                continue

            state = state_elem.get("state", "")
            # Strict: only "open" — never "open|filtered"
            if state != "open":
                continue

            port_num = int(port_elem.get("portid", 0))
            service_elem = port_elem.find("service")
            service_name, service_version, confidence = _extract_udp_service(service_elem)

            findings.append(Finding(
                session_id=session_id,
                module="udp_scan",
                target_ip=host_ip,
                target_port=port_num,
                target_service=service_name,
                service_version=service_version,
                category=Category.SERVICE,
                severity=Severity.INFO,
                confidence=confidence,
                exposure=Exposure.INTERNAL,
                evidence=Evidence(
                    raw=ET.tostring(port_elem, encoding="unicode"),
                    command=f"nmap -sU -oX - -p {port_num} {host_ip}",
                ),
                explanation=None,
                cve_refs=[],
                risk_score=None,
            ))

    return findings


def _extract_udp_service(
    service_elem: Optional[ET.Element],
) -> tuple[str, str, Confidence]:
    """Extract service info from a nmap UDP <service> element.

    UDP services that respond are rare — when they do, it's CONFIRMED.

    Args:
        service_elem: The <service> XML element, may be None.

    Returns:
        Tuple[str, str, Confidence]: (service_name, version_string, confidence)
    """
    if service_elem is None:
        return "", "", Confidence.CONFIRMED

    name = service_elem.get("name", "")
    product = service_elem.get("product", "")
    version = service_elem.get("version", "")
    extrainfo = service_elem.get("extrainfo", "")
    method = service_elem.get("method", "table")

    parts = [p for p in [product, version, extrainfo] if p]
    version_str = " ".join(parts)

    if method == "probed":
        confidence = Confidence.CONFIRMED
    elif version_str:
        confidence = Confidence.PROBABLE
    else:
        confidence = Confidence.POSSIBLE

    return name, version_str, confidence
