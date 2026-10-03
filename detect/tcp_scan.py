"""
detect/tcp_scan.py — TCP port scanner

Pipeline step: DETECT
Role: Identify open TCP ports on a target host.
      One Finding per open port — never for closed or filtered ports.

nmap command used:
    nmap -sV --version-intensity 5 -oX - -p <ports> <target>

    -sV               : service/version detection
    --version-intensity 5 : balanced intensity (0=light, 9=aggressive)
    -oX -             : XML output to stdout

Profile mapping:
    normal    → -T3 (default timing)
    stealth   → -sS -T2 (SYN scan, slower — requires root)
    aggressive → -T4 --version-intensity 7 (faster, more intrusive)

Confidence rules:
    CONFIRMED — port is open (TCP handshake or SYN-ACK confirmed)
    PROBABLE  — service version inferred from banner
    POSSIBLE  — service guessed by nmap without banner

Rules enforced here:
- ZERO import sqlite3
- ZERO print() — display via core/logger.py
- ZERO risk_score calculation
- ALWAYS return List[Finding] — one per open port
- ALWAYS ask (y/n) confirmation before scan
- NEVER report closed or filtered ports as Findings
"""

import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, List, Optional

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


# Default port range — covers the most common services
DEFAULT_PORTS = "1-1024,8080,8443,8888,3389,5432,3306,1433,27017,6379,9200"

# Profile → nmap timing/technique flags
PROFILE_FLAGS = {
    "normal":     ["-sV", "--version-intensity", "5", "-T3"],
    "stealth":    ["-sS", "-sV", "--version-intensity", "3", "-T2"],
    "aggressive": ["-sV", "--version-intensity", "7", "-T4"],
}


# ---------------------------------------------------------------------------
# Public scan outcomes
# ---------------------------------------------------------------------------

class TcpScanFailed(Exception):
    """Raised when a TCP scan cannot produce a valid result."""


class TcpScanCancelled(Exception):
    """Raised when the user cancels a TCP scan."""


class TcpScanFindings(list):
    """List-compatible TCP findings carrying the Nmap port states."""

    def __init__(self, findings: List[Finding], states: Dict[int, str]):
        super().__init__(findings)
        self.states = states


@dataclass(frozen=True)
class TcpPortScanResult:
    """Open findings and Nmap states returned by one TCP scan."""

    findings: List[Finding]
    states: Dict[int, str]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def tcp_scan(
    target: str,
    session_id: str,
    profile: str = "normal",
    ports: str = DEFAULT_PORTS,
    auto_confirm: bool = False,
) -> List[Finding]:
    """Scan TCP ports on a target and return one Finding per open port.

    Asks for (y/n) confirmation before sending any traffic,
    unless auto_confirm=True (used by netlab scan --yes pipeline).

    Args:
        target:       IP address or hostname to scan.
        session_id:   Current audit session ID.
        profile:      Scan profile — normal, stealth, aggressive.
        ports:        Port range string (nmap format, e.g. "1-1024,8080").
        auto_confirm: If True, skip the (y/n) prompt. Default False.

    Returns:
        List[Finding]: One Finding per open TCP port. Empty only when the
                       scan succeeds and no open ports are found.

    Raises:
        TcpScanFailed: If Nmap fails or returns invalid XML.
        TcpScanCancelled: If the user cancels this host scan.
    """
    if profile not in PROFILE_FLAGS:
        display(f"[red]Unknown profile '{profile}'. Using 'normal'.[/red]")
        profile = "normal"

    if not auto_confirm:
        confirmed = typer.confirm(
            f"[tcp_scan] Scan TCP ports {ports} on {target} (profile: {profile})?"
        )
        if not confirmed:
            display("[yellow]TCP scan cancelled.[/yellow]")
            raise TcpScanCancelled(f"User cancelled TCP scan for {target}")

    display(f"[cyan]Starting TCP scan on {target} (profile: {profile})...[/cyan]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}[/cyan]"),
        transient=True,
    ) as progress:
        progress.add_task(f"nmap TCP scan → {target}", total=None)
        xml_output = _run_nmap_tcp(target, profile, ports)

    if not xml_output:
        display(f"[yellow]No response from nmap TCP scan on {target}.[/yellow]")
        raise TcpScanFailed(f"Nmap TCP scan returned no result for {target}")

    try:
        ET.fromstring(xml_output)
    except ET.ParseError as exc:
        display("[red]Failed to parse nmap TCP XML output.[/red]")
        raise TcpScanFailed(f"Invalid nmap TCP XML output for {target}") from exc

    findings, states = _parse_tcp_xml_with_states(xml_output, target, session_id)
    findings = TcpScanFindings(findings, states)

    if findings:
        display(f"[green]TCP scan complete — {len(findings)} open port(s) found.[/green]")
    else:
        display(f"[yellow]TCP scan complete — no open ports found on {target}.[/yellow]")

    return findings


def tcp_scan_port_state(
    target: str,
    session_id: str,
    profile: str = "normal",
    ports: str = DEFAULT_PORTS,
    auto_confirm: bool = False,
) -> TcpPortScanResult:
    """Run one TCP scan and retain Nmap's state for every scanned port.

    This is used by VERIFY, where an absent open Finding is not enough to
    distinguish a closed port from a filtered port.
    """
    findings = tcp_scan(
        target, session_id, profile=profile,
        ports=ports, auto_confirm=auto_confirm,
    )
    if isinstance(findings, TcpScanFindings):
        states = findings.states
    else:
        # Compatibility for callers/tests replacing tcp_scan with the historic
        # plain List[Finding] contract. Real scans always carry Nmap states.
        states = {
            item.target_port: "open"
            for item in findings
            if item.target_port is not None
        }
        if not states:
            try:
                target_port = int(ports)
            except (TypeError, ValueError):
                target_port = None
            if target_port is not None:
                states[target_port] = "closed"
    return TcpPortScanResult(findings=list(findings), states=states)


# ---------------------------------------------------------------------------
# nmap subprocess
# ---------------------------------------------------------------------------

def _run_nmap_tcp(target: str, profile: str, ports: str) -> Optional[str]:
    """Run nmap TCP scan and return raw XML output.

    Args:
        target:  IP or hostname.
        profile: Scan profile key.
        ports:   Port range string.

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
            timeout=300,
        )
        if result.returncode not in (0, 1):  # nmap exits 1 if no hosts up
            display(f"[yellow]nmap warning (exit {result.returncode}): "
                    f"{result.stderr.strip()[:200]}[/yellow]")
        return result.stdout if result.stdout.strip() else None
    except FileNotFoundError:
        display("[red]nmap not found. Run 'netlab doctor'.[/red]")
        return None
    except subprocess.TimeoutExpired:
        display("[yellow]nmap TCP scan timed out after 300s.[/yellow]")
        return None
    except Exception as exc:
        display(f"[red]nmap error: {exc}[/red]")
        return None


# ---------------------------------------------------------------------------
# XML parser
# ---------------------------------------------------------------------------

def _parse_tcp_xml_with_states(
    xml_output: str,
    target: str,
    session_id: str,
) -> tuple[List[Finding], Dict[int, str]]:
    """Parse nmap XML output and build one Finding per open TCP port.

    Only ports with state="open" produce a Finding.
    Closed, filtered, and open|filtered ports are ignored.

    Confidence:
        CONFIRMED — port is open (TCP handshake confirmed)
        PROBABLE  — service version detected from banner
        POSSIBLE  — service name guessed by nmap without banner

    Args:
        xml_output: Raw XML string from nmap.
        target:     IP or hostname scanned.
        session_id: Current audit session ID.

    Returns:
        Tuple[List[Finding], Dict[int, str]]: Open findings and the Nmap state
        for every scanned TCP port.
    """
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        display("[red]Failed to parse nmap TCP XML output.[/red]")
        return [], {}

    findings = []
    states: Dict[int, str] = {}

    for host in root.findall("host"):
        # Use the actual IP from the XML (may differ from target if hostname given)
        addr_elem = host.find("address[@addrtype='ipv4']")
        host_ip = addr_elem.get("addr", target) if addr_elem is not None else target

        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            if port_elem.get("protocol") != "tcp":
                continue

            state_elem = port_elem.find("state")
            port_num = int(port_elem.get("portid", 0))
            state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
            states[port_num] = state
            if state != "open":
                continue  # NEVER report closed or filtered ports

            service_elem = port_elem.find("service")
            service_name, service_version, confidence = _extract_service(service_elem)

            findings.append(Finding(
                session_id=session_id,
                module="tcp_scan",
                target_ip=host_ip,
                target_port=port_num,
                target_service=service_name,
                service_version=service_version,
                category=Category.SERVICE,
                severity=Severity.INFO,  # scored after CVE lookup in service_detection
                confidence=confidence,
                exposure=Exposure.INTERNAL,
                evidence=Evidence(
                    raw=ET.tostring(port_elem, encoding="unicode"),
                    command=f"nmap -sV -oX - -p {port_num} {host_ip}",
                ),
                explanation=None,
                cve_refs=[],
                risk_score=None,
            ))

    return findings, states


def _parse_tcp_xml(
    xml_output: str,
    target: str,
    session_id: str,
) -> List[Finding]:
    """Parse Nmap XML while preserving the existing open-finding contract."""
    findings, _ = _parse_tcp_xml_with_states(xml_output, target, session_id)
    return findings


def _extract_service(
    service_elem: Optional[ET.Element],
) -> tuple[str, str, Confidence]:
    """Extract service name, version and confidence from a nmap <service> element.

    Confidence mapping:
        CONFIRMED — method="probed" (nmap sent a probe and got a response)
        PROBABLE  — method="table" + version info present (banner matched)
        POSSIBLE  — method="table" without version (name guessed from port number)

    Args:
        service_elem: The <service> XML element, may be None.

    Returns:
        Tuple[str, str, Confidence]: (service_name, version_string, confidence)
    """
    if service_elem is None:
        return "", "", Confidence.CONFIRMED  # port is open — that's certain

    name = service_elem.get("name", "")
    product = service_elem.get("product", "")
    version = service_elem.get("version", "")
    extrainfo = service_elem.get("extrainfo", "")
    method = service_elem.get("method", "table")

    # Build a readable version string
    parts = [p for p in [product, version, extrainfo] if p]
    version_str = " ".join(parts)

    if method == "probed":
        confidence = Confidence.CONFIRMED
    elif version_str:
        confidence = Confidence.PROBABLE
    else:
        confidence = Confidence.POSSIBLE

    return name, version_str, confidence
