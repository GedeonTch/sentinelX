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
from core.process_control import run_process
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

# ---------------------------------------------------------------------------
# TCP-01 — Port state model (A1 / SENTINEL-TCP-STATES.md)
# ---------------------------------------------------------------------------
from enum import Enum, auto


class PortState(Enum):
    """State of one TCP port as reported by a complete nmap scan."""
    OPEN = auto()       # explicit state="open"
    CLOSED = auto()     # explicit state="closed"
    FILTERED = auto()   # explicit state="filtered"
    UNCERTAIN = auto()  # absent, invalid, state="open|filtered", or unresolvable


@dataclass(frozen=True)
class HostTcpObservation:
    """Result of one Sentinel TCP scan for a single host.

    status == COMPLETE means every expected port was accounted for without
    contradiction.  status == INCOMPLETE means the XML is malformed, ambiguous,
    or the port coverage could not be established.

    ``ports`` is the backward-compatibility property used by existing callers:
      - None   if INCOMPLETE
      - []     if COMPLETE and no port is OPEN
      - sorted list of OPEN ports otherwise
    """
    status: str                       # "COMPLETE" or "INCOMPLETE"
    states: Dict[int, PortState]      # port → PortState (populated when COMPLETE)

    @property
    def open_ports(self) -> List[int]:
        """Sorted list of ports with PortState.OPEN."""
        return sorted(p for p, s in self.states.items() if s is PortState.OPEN)

    @property
    def ports(self) -> Optional[List[int]]:
        """Backward-compatible view: None / [] / [ports...] (Sentinel contract)."""
        if self.status == "INCOMPLETE":
            return None
        return self.open_ports

    @classmethod
    def incomplete(cls) -> "HostTcpObservation":
        return cls(status="INCOMPLETE", states={})

    @classmethod
    def complete(cls, states: Dict[int, PortState]) -> "HostTcpObservation":
        return cls(status="COMPLETE", states=states)


def _parse_extrareasons_ports(extrareasons_elem: ET.Element) -> Optional[frozenset]:
    """Extract the set of ports from an <extrareasons ports="..."> element.

    Returns None if the attribute is absent or unparseable.
    """
    raw = extrareasons_elem.get("ports")
    return _expand_port_spec(raw) if raw else None


def _parse_host_tcp_states(
    host_elem: ET.Element,
    expected: frozenset,
) -> HostTcpObservation:
    """Parse one host's <ports> section into a HostTcpObservation.

    Implements rules P1-P7, P11-P12 from SENTINEL-TCP-STATES.md §3.

    Args:
        host_elem: The <host> element from nmap XML.
        expected:  Frozenset of port numbers that must all be accounted for.

    Returns:
        HostTcpObservation — COMPLETE with per-port states, or INCOMPLETE.
    """
    ports_elem = host_elem.find("ports")
    if ports_elem is None:
        return HostTcpObservation.incomplete()

    states: Dict[int, PortState] = {}

    # P1 / P2 — explicit <port> elements
    for port_elem in ports_elem.findall("port"):
        if port_elem.get("protocol") != "tcp":
            continue
        portid_raw = port_elem.get("portid", "")
        try:
            portid = int(portid_raw)
        except ValueError:
            return HostTcpObservation.incomplete()
        if portid not in expected:
            return HostTcpObservation.incomplete()          # P11: out of scope
        if portid in states:
            return HostTcpObservation.incomplete()          # P7: duplicate
        state_elem = port_elem.find("state")
        raw_state = state_elem.get("state", "") if state_elem is not None else ""
        if raw_state == "open":
            states[portid] = PortState.OPEN
        elif raw_state == "closed":
            states[portid] = PortState.CLOSED
        elif raw_state == "filtered":
            states[portid] = PortState.FILTERED
        else:
            # P2 / P4-style: open|filtered, unfiltered, unknown, etc. → UNCERTAIN
            states[portid] = PortState.UNCERTAIN

    # Ports not yet assigned come from <extraports> groups
    unassigned = expected - frozenset(states.keys())

    for group in ports_elem.findall("extraports"):
        group_state_raw = group.get("state", "")
        # P4: extraports state="open" → never OPEN
        if group_state_raw == "open":
            group_port_state = PortState.UNCERTAIN
        elif group_state_raw == "closed":
            group_port_state = PortState.CLOSED
        elif group_state_raw == "filtered":
            group_port_state = PortState.FILTERED
        else:
            group_port_state = PortState.UNCERTAIN

        # Gather ports explicitly listed in <extrareasons ports="...">
        explicit_ports: set = set()
        for er in group.findall("extrareasons"):
            port_set = _parse_extrareasons_ports(er)
            if port_set is not None:
                # P7: overlap with already-attributed ports → INCOMPLETE
                overlap = port_set & frozenset(states.keys())
                if overlap:
                    return HostTcpObservation.incomplete()
                # P7 intra-group: overlap between multiple <extrareasons> in same group
                overlap_intra = port_set & explicit_ports
                if overlap_intra:
                    return HostTcpObservation.incomplete()
                explicit_ports |= port_set

        if explicit_ports:
            # P11: validate that the group count matches the explicit port set size
            count_raw = group.get("count")
            try:
                group_count = int(count_raw) if count_raw is not None else None
            except ValueError:
                return HostTcpObservation.incomplete()
            if group_count is not None and group_count != len(explicit_ports):
                return HostTcpObservation.incomplete()
            # P3: attribute the state from the parent group
            for p in explicit_ports:
                if p not in expected:
                    return HostTcpObservation.incomplete()  # P11
                if p in states:
                    return HostTcpObservation.incomplete()  # P7
                states[p] = group_port_state
            unassigned -= explicit_ports
        else:
            # P5 / P6: no explicit port list in this group
            count_raw = group.get("count")
            try:
                count = int(count_raw) if count_raw is not None else None
            except ValueError:
                return HostTcpObservation.incomplete()

            if count is None:
                return HostTcpObservation.incomplete()

            # Count how many groups have no explicit ports (for P6)
            groups_without_explicit = sum(
                1 for g in ports_elem.findall("extraports")
                if not any(g.findall("extrareasons"))
                   or all(_parse_extrareasons_ports(er) is None
                          for er in g.findall("extrareasons"))
            )

            if groups_without_explicit > 1:
                # P6: multiple groups without explicit attribution → UNCERTAIN
                if count > len(unassigned):
                    return HostTcpObservation.incomplete()
                # Cannot determine which ports belong to which group → UNCERTAIN
                # We will assign UNCERTAIN to all remaining unassigned after the loop
                for p in sorted(unassigned)[:count]:
                    states[p] = PortState.UNCERTAIN
                unassigned -= frozenset(sorted(unassigned)[:count])
            else:
                # P5: exactly one group without explicit ports — count must match residual
                if count != len(unassigned):
                    return HostTcpObservation.incomplete()
                for p in unassigned:
                    states[p] = group_port_state
                unassigned = frozenset()

    # P12: all expected ports must be attributed
    if unassigned:
        return HostTcpObservation.incomplete()

    return HostTcpObservation.complete(states)


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
    skip_host_discovery: bool = False,
    should_stop=None,
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
        skip_host_discovery: False (default) leaves nmap host discovery
                 unchanged. True adds ``-Pn`` so that a host already known
                 to be present (e.g. answering ARP but not ICMP) is scanned
                 without a prior discovery step.
        should_stop: None (default) runs nmap to completion. A callable
                 returning True interrupts nmap and raises ScanInterrupted
                 (see core.process_control). Only the Sentinel monitor passes it.

    Returns:
        str: Raw XML from nmap, or None on error.
    """
    flags = PROFILE_FLAGS.get(profile, PROFILE_FLAGS["normal"])
    host_discovery = ["-Pn"] if skip_host_discovery else []
    cmd = ["nmap"] + flags + host_discovery + ["-oX", "-", "-p", ports, target]
    if strict:
        return _run_nmap_tcp_strict(cmd, should_stop=should_stop)
    try:
        result = run_process(cmd, 300, should_stop)
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


def _run_nmap_tcp_strict(cmd: List[str], should_stop=None) -> Optional[str]:
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
        result = run_process(cmd, 300, should_stop)
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

    # Each TCP port is recorded once. A repeated <port> would be counted twice
    # by the planned-count check and then reported as two open ports for one
    # port number: the table is not trusted, so the scan is not a success.
    seen_tcp_ports = set()
    for port_elem in ports.findall("port"):
        if port_elem.get("protocol") != "tcp":
            continue
        port_id = port_elem.get("portid")
        if port_id in seen_tcp_ports:
            raise TcpScanFailed(
                f"nmap XML for {target} records TCP port {port_id} more than once"
            )
        seen_tcp_ports.add(port_id)

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


_PORT_SPEC_TOKEN_RE = re.compile(r"([0-9]+)(?:-([0-9]+))?")
_MAX_PORT_NUMBER = 65535


def _expand_port_spec(spec: Optional[str]) -> Optional[frozenset]:
    """Expand an nmap port list such as ``1-1024,3389`` into its set of ports.

    Returns None when the list is absent or malformed, or when a port is out of
    1-65535. Order and overlapping ranges do not matter.
    """
    if not spec:
        return None
    ports: set = set()
    for token in spec.split(","):
        match = _PORT_SPEC_TOKEN_RE.fullmatch(token.strip())
        if match is None:
            return None
        low = int(match.group(1))
        high = int(match.group(2)) if match.group(2) is not None else low
        if not 1 <= low <= high <= _MAX_PORT_NUMBER:
            return None
        ports.update(range(low, high + 1))
    return frozenset(ports)


def parse_sentinel_open_ports(
    xml_output: Optional[str],
    target: str,
    expected_ports: str,
) -> Optional[List[int]]:
    """Return the open TCP ports of a proven complete scan of ``target``, else None.

    Sentinel contract. ``[]`` means the scan is proven complete and no port is
    open. ``None`` means the port state is unknown: no output, invalid or
    incomplete XML, several hosts, another address, a scan of a port set other
    than ``expected_ports``, or any failed validation of _check_tcp_xml. ``None``
    is never read as zero open ports. The shared parser _parse_tcp_xml is not
    changed for other callers.

    Args:
        xml_output:     Raw nmap XML, or None.
        target:         IP that was scanned.
        expected_ports: The nmap port list that was requested, e.g.
                        ``"1-1024,3389,5432"``. The XML must have scanned exactly
                        this set: scaninfo services and numservices must agree.
    """
    expected = _expand_port_spec(expected_ports)
    if expected is None:
        raise ValueError(f"invalid expected port list: {expected_ports!r}")
    if not xml_output:
        return None
    try:
        root = ET.fromstring(xml_output)
        hosts = root.findall("host")
        if len(hosts) != 1:
            return None
        _check_tcp_xml(xml_output, target)
        if _planned_port_count(root, target) != len(expected):
            return None
        tcp_scaninfo = [info for info in root.findall("scaninfo") if info.get("protocol") == "tcp"]
        if not tcp_scaninfo or any(
            _expand_port_spec(info.get("services")) != expected for info in tcp_scaninfo
        ):
            return None
        # Verify the host address matches the requested target
        addr_elem = hosts[0].find("address[@addrtype='ipv4']")
        host_ip = addr_elem.get("addr") if addr_elem is not None else None
        if host_ip != target:
            return None
        obs = _parse_host_tcp_states(hosts[0], expected)
    except (TcpScanFailed, ET.ParseError, ValueError):
        return None
    return obs.ports


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
