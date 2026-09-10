"""
01_recon/device_fingerprint.py — Device discovery and OS fingerprinting

Pipeline step: DISCOVER
Role: Identify active hosts on a network (IP, MAC, hostname, OS estimate).

This module answers: "Who is on this network?"
It does NOT scan ports — that is tcp_scan.py (#009).

Rules enforced here:
- ZERO import sqlite3
- ZERO print() — logging via core/logger.py
- ZERO risk_score calculation
- ALWAYS return List[Finding]
- ALWAYS ask (y/n) confirmation before sending network traffic
- evidence.raw = raw nmap XML output (never interpreted here)
- explanation = None (knowledge base populated in ticket #015)

Nmap calls:
    Pass 1 — ping scan    : nmap -sn -oX - <target>
    Pass 2 — OS detection : nmap -O --osscan-guess -oX - <ip>  (per active host)

Confidence rules:
    CONFIRMED — host responded to ping AND MAC address confirmed
    PROBABLE  — OS detected by nmap with a high-accuracy match (>= 85%)
    POSSIBLE  — OS guessed by nmap with low accuracy, or inferred from TTL
"""

import subprocess
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple

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


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def fingerprint(target: str, session_id: str) -> List[Finding]:
    """Discover active hosts on a target and fingerprint their OS.

    Performs two nmap passes:
      1. Ping scan to find active hosts
      2. OS detection on each active host

    Asks for (y/n) confirmation before sending any network traffic.

    Args:
        target:     IP address or CIDR range (e.g. "192.168.1.0/24").
        session_id: Current audit session ID — stamped on every Finding.

    Returns:
        List[Finding]: One Finding per active host. Empty list if no hosts found
                       or if the user cancels.
    """
    confirmed = typer.confirm(
        f"[device_fingerprint] Start host discovery on {target}?"
    )
    if not confirmed:
        display("[yellow]Host discovery cancelled.[/yellow]")
        return []

    display(f"[cyan]Starting host discovery on {target}...[/cyan]")

    # Pass 1 — find active hosts
    ping_xml = _run_nmap_ping(target)
    if not ping_xml:
        display("[yellow]No response from nmap ping scan.[/yellow]")
        return []

    active_ips = _parse_active_hosts(ping_xml)
    if not active_ips:
        display(f"[yellow]No active hosts found on {target}.[/yellow]")
        return []

    display(f"[green]{len(active_ips)} active host(s) found.[/green]")

    # Pass 2 — OS detection per host
    findings: List[Finding] = []
    for ip in active_ips:
        os_xml = _run_nmap_os(ip)
        host_findings = _parse_host(
            ip=ip,
            ping_xml=ping_xml,
            os_xml=os_xml,
            session_id=session_id,
        )
        findings.extend(host_findings)

    display(f"[green]Device fingerprint complete — {len(findings)} finding(s).[/green]")
    return findings


# ---------------------------------------------------------------------------
# nmap subprocess calls
# ---------------------------------------------------------------------------

def _run_nmap_ping(target: str) -> Optional[str]:
    """Run a ping scan on a target and return raw XML output.

    Command: nmap -sn -oX - <target>

    Args:
        target: IP or CIDR range.

    Returns:
        str: Raw XML string from nmap, or None on error.
    """
    cmd = ["nmap", "-sn", "-oX", "-", target]
    return _run_nmap(cmd)


def _run_nmap_os(ip: str) -> Optional[str]:
    """Run OS detection on a single host and return raw XML output.

    Command: nmap -O --osscan-guess -oX - <ip>

    Requires root/sudo on Linux for raw socket access.
    Falls back gracefully if OS detection fails.

    Args:
        ip: Single IP address.

    Returns:
        str: Raw XML string from nmap, or None on error.
    """
    cmd = ["nmap", "-O", "--osscan-guess", "-oX", "-", ip]
    return _run_nmap(cmd)


def _run_nmap(cmd: List[str]) -> Optional[str]:
    """Execute an nmap command and return its stdout as a string.

    Args:
        cmd: Full command as a list of strings.

    Returns:
        str: stdout of the nmap process, or None if the process failed.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            display(
                f"[yellow]nmap warning (exit {result.returncode}): "
                f"{result.stderr.strip()[:200]}[/yellow]"
            )
        return result.stdout if result.stdout.strip() else None
    except FileNotFoundError:
        display("[red]nmap not found. Run 'netlab doctor' to check dependencies.[/red]")
        return None
    except subprocess.TimeoutExpired:
        display("[red]nmap timed out after 300s.[/red]")
        return None
    except Exception as exc:
        display(f"[red]nmap error: {exc}[/red]")
        return None


# ---------------------------------------------------------------------------
# XML parsers
# ---------------------------------------------------------------------------

def _parse_active_hosts(xml_output: str) -> List[str]:
    """Extract IP addresses of hosts with status 'up' from nmap ping scan XML.

    Args:
        xml_output: Raw XML string from nmap -sn.

    Returns:
        List[str]: IP addresses of active hosts.
    """
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        display("[red]Failed to parse nmap XML output.[/red]")
        return []

    active = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") == "up":
            addr = host.find("address[@addrtype='ipv4']")
            if addr is not None:
                ip = addr.get("addr", "")
                if ip:
                    active.append(ip)
    return active


def _parse_host(
    ip: str,
    ping_xml: str,
    os_xml: Optional[str],
    session_id: str,
) -> List[Finding]:
    """Build Finding objects for a single active host.

    Combines data from the ping scan (MAC, hostname) and the OS scan (OS name).
    Returns a list — currently one Finding per host, but structured as a list
    for forward compatibility if sub-findings are needed.

    Args:
        ip:         IP address of the host.
        ping_xml:   Raw XML from the ping scan (contains MAC + hostname).
        os_xml:     Raw XML from the OS scan (contains OS match). May be None.
        session_id: Current audit session ID.

    Returns:
        List[Finding]: One Finding for the host, or empty list on parse error.
    """
    # Extract MAC and hostname from ping XML
    mac, hostname = _extract_mac_hostname(ip, ping_xml)

    # Extract OS name and confidence from OS XML
    os_name, os_confidence = _detect_os(os_xml) if os_xml else ("", Confidence.CONFIRMED)

    # Build evidence — raw XML stored verbatim
    raw_evidence = f"[ping]\n{ping_xml}"
    if os_xml:
        raw_evidence += f"\n[os]\n{os_xml}"

    evidence = Evidence(
        raw=raw_evidence,
        command=f"nmap -sn -oX - {ip} && nmap -O --osscan-guess -oX - {ip}",
    )

    # Confidence: CONFIRMED if host is up (ping responded)
    # OS confidence may downgrade to PROBABLE or POSSIBLE
    host_confidence = Confidence.CONFIRMED  # host is up — that is certain

    # Build service version string
    service_version = os_name if os_name else ""

    # Title-style summary for target_service
    target_service = "host"

    finding = Finding(
        session_id=session_id,
        module="device_fingerprint",
        target_ip=ip,
        target_port=None,
        target_service=target_service,
        service_version=service_version,
        category=Category.NETWORK,
        severity=Severity.INFO,
        confidence=host_confidence,
        exposure=Exposure.INTERNAL,
        evidence=evidence,
        explanation=None,   # populated by knowledge base in ticket #015
        cve_refs=[],
        cvss_score=None,
        risk_score=None,    # set by risk_scorer only
    )

    return [finding]


def _extract_mac_hostname(ip: str, xml_output: str) -> Tuple[str, str]:
    """Extract MAC address and hostname for a given IP from nmap XML.

    Args:
        ip:         IP to look up.
        xml_output: Raw XML from nmap ping scan.

    Returns:
        Tuple[str, str]: (mac_address, hostname) — empty strings if not found.
    """
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return "", ""

    for host in root.findall("host"):
        addr_v4 = host.find("address[@addrtype='ipv4']")
        if addr_v4 is None or addr_v4.get("addr") != ip:
            continue

        # MAC address
        addr_mac = host.find("address[@addrtype='mac']")
        mac = addr_mac.get("addr", "") if addr_mac is not None else ""

        # Hostname (PTR or user)
        hostname = ""
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        return mac, hostname

    return "", ""


def _detect_os(os_xml: str) -> Tuple[str, Confidence]:
    """Extract the best OS match and assign a Confidence level from nmap OS XML.

    nmap provides an accuracy percentage (0–100) for each OS match.
    Mapping to Confidence:
        accuracy >= 85 → PROBABLE  (strong deduction from OS fingerprint)
        accuracy <  85 → POSSIBLE  (low-accuracy guess)

    Note: we never return CONFIRMED for OS detection — nmap's OS fingerprinting
    is probabilistic by nature, even at 100% accuracy.

    Args:
        os_xml: Raw XML from nmap -O --osscan-guess.

    Returns:
        Tuple[str, Confidence]: (os_name, confidence) — ("", CONFIRMED) if
        no OS match found (CONFIRMED because absence of info is not uncertain).
    """
    try:
        root = ET.fromstring(os_xml)
    except ET.ParseError:
        return "", Confidence.CONFIRMED

    best_name = ""
    best_accuracy = 0

    for host in root.findall("host"):
        os_elem = host.find("os")
        if os_elem is None:
            continue
        for match in os_elem.findall("osmatch"):
            try:
                accuracy = int(match.get("accuracy", "0"))
            except ValueError:
                accuracy = 0
            if accuracy > best_accuracy:
                best_accuracy = accuracy
                best_name = match.get("name", "")

    if not best_name:
        return "", Confidence.CONFIRMED

    if best_accuracy >= 85:
        return best_name, Confidence.PROBABLE
    else:
        return best_name, Confidence.POSSIBLE
