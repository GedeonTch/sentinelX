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

import re
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
                       scan succeeds (host up, every planned port recorded)
                       and no open ports are found.

    Raises:
        TcpScanFailed: If Nmap fails, the host is DOWN or not reported, or the
                       XML does not prove a completed scan of an up host.
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
        xml_output = _run_nmap_tcp(target, profile, ports, strict=True)

    if not xml_output:
        display(f"[yellow]No response from nmap TCP scan on {target}.[/yellow]")
        raise TcpScanFailed(f"Nmap TCP scan returned no result for {target}")

    _check_tcp_xml(xml_output, target)

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
    return TcpPortScanResult(findings=list(findings), states=states)


# ---------------------------------------------------------------------------
# nmap subprocess
# ---------------------------------------------------------------------------

def _run_nmap_tcp(
    target: str,
    profile: str,
    ports: str,
    strict: bool = False,
) -> Optional[str]:
    """Run nmap TCP scan and return raw XML output, or None on error.

    Args:
        target:  IP or hostname.
        profile: Scan profile key.
        ports:   Port range string.
        strict:  False (default) keeps the historical contract shared with
                 Sentinel and the baseline: exit codes 0 and 1 are tolerated
                 and any unexpected error becomes None.
                 True is used by the pipeline (tcp_scan): see
                 _run_nmap_tcp_strict.

    Returns:
        str: Raw XML from nmap, or None on error.
    """
    flags = PROFILE_FLAGS.get(profile, PROFILE_FLAGS["normal"])
    cmd = ["nmap"] + flags + ["-oX", "-", "-p", ports, target]
    if strict:
        return _run_nmap_tcp_strict(cmd)
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


def _run_nmap_tcp_strict(cmd: List[str]) -> Optional[str]:
    """Run the pipeline's TCP command with the T20 success criterion.

    Failure by default: any non-zero exit code is a failure, because no real
    lab run has yet confirmed which codes are benign. Known environment errors
    (nmap missing, timeout, launch error, unreadable output) return None with a
    message. Any other exception is a programming error and propagates.

    Args:
        cmd: Full nmap command line.

    Returns:
        str: Raw XML when nmap exited with 0 and produced output, else None.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        display("[red]nmap not found. Run 'netlab doctor'.[/red]")
        return None
    except subprocess.TimeoutExpired:
        display("[yellow]nmap TCP scan timed out after 300s.[/yellow]")
        return None
    except (OSError, UnicodeDecodeError) as exc:
        display(f"[red]nmap TCP scan could not run or its output was unreadable: {exc}[/red]")
        return None

    if result.returncode != 0:
        display(f"[yellow]nmap TCP scan failed (exit {result.returncode}): "
                f"{result.stderr.strip()[:200]}[/yellow]")
        return None
    return result.stdout if result.stdout.strip() else None


# A TCP scan covers at most the 65535 port numbers, so no port count nmap writes
# can exceed it. nmap writes counts as canonical decimal integers.
MAX_TCP_PORT_COUNT = 65535
_COUNT_RE = re.compile(r"0|[1-9][0-9]*")
_MAX_COUNT_DIGITS = len(str(MAX_TCP_PORT_COUNT))


def _parse_port_count(raw: Optional[str], minimum: int) -> Optional[int]:
    """Return an nmap port count as an int, or None when it is not a valid count.

    A valid count is a canonical decimal (no sign, no spaces, no leading zero)
    lying in [minimum, MAX_TCP_PORT_COUNT]. Its length is checked before the
    conversion, so an oversized value is refused without being converted.
    """
    if raw is None or not _COUNT_RE.fullmatch(raw) or len(raw) > _MAX_COUNT_DIGITS:
        return None
    value = int(raw)
    return value if minimum <= value <= MAX_TCP_PORT_COUNT else None


def _planned_port_count(root: ET.Element, target: str) -> int:
    """Return how many ports nmap planned for the TCP scan of target.

    nmap prints one <scaninfo protocol="tcp"> for a TCP connect scan. Its
    numservices is the number of distinct ports in the request: duplicates and
    overlapping ranges are counted once (checked on nmap 7.95). Every TCP
    scaninfo must carry the same count, and the count must lie from 1 to
    MAX_TCP_PORT_COUNT.

    Raises:
        TcpScanFailed: If there is no TCP scaninfo, if the TCP scaninfo elements
                       disagree, or if the count is absent or out of range.
    """
    counts = {
        info.get("numservices")
        for info in root.findall("scaninfo")
        if info.get("protocol") == "tcp"
    }
    if not counts:
        raise TcpScanFailed(f"nmap XML for {target} has no TCP scaninfo: planned ports unknown")
    if len(counts) > 1:
        raise TcpScanFailed(f"nmap XML for {target} has conflicting TCP scaninfo port counts")
    (raw,) = counts
    planned = _parse_port_count(raw, minimum=1)
    if planned is None:
        shown = "absent" if raw is None else repr(raw[:20])
        raise TcpScanFailed(
            f"nmap XML for {target} has an invalid planned port count: {shown} "
            f"(expected 1 to {MAX_TCP_PORT_COUNT})"
        )
    return planned


def _recorded_port_states(ports: ET.Element) -> Optional[int]:
    """Count the port states nmap recorded in one host's <ports> table.

    nmap writes a port either as an explicit <port> (open, closed or filtered)
    or inside an <extraports state="..." count="N"> group that summarises N
    ports of one state. Returns None when a group's count is not a valid count
    (from 0 to MAX_TCP_PORT_COUNT), because the table then cannot be counted.
    """
    total = len(ports.findall("port"))
    for group in ports.findall("extraports"):
        count = _parse_port_count(group.get("count"), minimum=0)
        if count is None:
            return None
        total += count
    return total


def _check_tcp_xml(xml_output: str, target: str) -> None:
    """Refuse nmap XML that does not prove a completed scan of an up host.

    A TCP scan is a success only when the XML shows, for the target:
      - a well-formed nmaprun document,
      - a finished run (runstats/finished, with exit="success" when present),
      - a host whose status is "up" and that nmap did not flag as timedout,
      - a port table for that host,
      - a planned port count (TCP scaninfo numservices): an integer from 1 to
        MAX_TCP_PORT_COUNT on which every TCP scaninfo agrees,
      - exactly that many port states recorded: explicit <port> entries plus the
        counts of <extraports> groups (each from 0 to MAX_TCP_PORT_COUNT). Fewer
        states means a partial table; more means the counts disagree.
    Zero open ports is still a success when all of the above hold.

    Args:
        xml_output: Raw XML string from nmap.
        target:     IP or hostname that was scanned.

    Raises:
        TcpScanFailed: If the XML is invalid or incomplete, the host is DOWN or
                       not reported by nmap, or the port states recorded do not
                       match the planned ports.
    """
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        display("[red]Failed to parse nmap TCP XML output.[/red]")
        raise TcpScanFailed(f"Invalid nmap TCP XML output for {target}") from exc

    if root.tag != "nmaprun":
        raise TcpScanFailed(f"Unexpected nmap XML root for {target}: {root.tag}")

    finished = root.find("runstats/finished")
    if finished is None or finished.get("exit", "success") != "success":
        raise TcpScanFailed(f"nmap TCP run for {target} is not proven finished")

    up_hosts = [
        host for host in root.findall("host")
        if host.find("status") is not None
        and host.find("status").get("state") == "up"
    ]
    if not up_hosts:
        display(f"[yellow]Host {target} is DOWN or was not reported by nmap.[/yellow]")
        raise TcpScanFailed(f"Host {target} is DOWN or not reported by nmap")

    if up_hosts[0].get("timedout") == "true":
        raise TcpScanFailed(f"nmap stopped the scan of {target} on its host timeout")

    ports = up_hosts[0].find("ports")
    if ports is None:
        raise TcpScanFailed(f"nmap XML for {target} has no port table")

    planned = _planned_port_count(root, target)
    recorded = _recorded_port_states(ports)
    if recorded is None:
        raise TcpScanFailed(
            f"nmap XML for {target} has an invalid <extraports> count "
            f"(expected 0 to {MAX_TCP_PORT_COUNT})"
        )
    if recorded < planned:
        raise TcpScanFailed(
            f"nmap XML for {target} records {recorded} of {planned} planned port state(s): "
            "partial port table"
        )
    if recorded > planned:
        raise TcpScanFailed(
            f"nmap XML for {target} records {recorded} port state(s) "
            f"for {planned} planned port(s)"
        )


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
