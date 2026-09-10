"""
recon/passive_recon.py — Passive reconnaissance

Pipeline step: DISCOVER
Role: Collect host information from local system state — zero traffic sent
      to any target.

Sources used (all passive — read from OS/local cache only):
  1. ARP cache     — MAC-to-IP mappings already learned by the OS kernel
  2. /etc/hosts    — static hostname mappings on the local machine
  3. mDNS cache    — local multicast DNS names (.local domains, read from
                     avahi-browse output if available)

This module answers: "What do we already know without sending a single packet?"

Why passive matters:
  - Leaves zero trace on the network
  - Cannot trigger IDS/IPS alerts
  - Reveals what the machine has seen recently (ARP cache)
  - Useful on stealthy engagements or as a pre-scan step

Rules enforced here:
- ZERO import sqlite3
- ZERO print() — display via core/logger.py
- ZERO risk_score calculation
- ALWAYS return List[Finding]
- No (y/n) confirmation — no traffic is sent to targets
- All data comes from local OS state, not from network probes

Confidence rules:
    CONFIRMED — ARP entry exists (OS has confirmed the MAC-IP binding recently)
    PROBABLE  — hostname from /etc/hosts (manually configured, trustworthy but static)
    POSSIBLE  — mDNS entry (multicast advertisement, not verified)
"""

import subprocess
import re
from pathlib import Path
from typing import List, Optional, Dict

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

def passive_recon(target_network: str, session_id: str) -> List[Finding]:
    """Collect passive reconnaissance data for a target network.

    Reads ARP cache, /etc/hosts, and mDNS cache. Filters results to
    hosts within the target_network if provided, or returns all if empty.

    No network traffic is sent. No confirmation required.

    Args:
        target_network: CIDR or IP prefix to filter results (e.g. "192.168.1").
                        Pass "" to return all discovered hosts.
        session_id:     Current audit session ID.

    Returns:
        List[Finding]: One Finding per discovered host/entry. May be empty.
    """
    display(f"[cyan]Starting passive reconnaissance for {target_network or 'all'}...[/cyan]")

    findings: List[Finding] = []

    # Source 1 — ARP cache
    arp_findings = _arp_findings(target_network, session_id)
    findings.extend(arp_findings)
    display(f"[dim]  ARP cache: {len(arp_findings)} entr(y/ies)[/dim]")

    # Source 2 — /etc/hosts
    hosts_findings = _hosts_file_findings(target_network, session_id)
    findings.extend(hosts_findings)
    display(f"[dim]  /etc/hosts: {len(hosts_findings)} entr(y/ies)[/dim]")

    # Source 3 — mDNS (avahi-browse, best-effort)
    mdns_findings = _mdns_findings(target_network, session_id)
    findings.extend(mdns_findings)
    display(f"[dim]  mDNS: {len(mdns_findings)} entr(y/ies)[/dim]")

    if findings:
        display(f"[green]Passive recon complete — {len(findings)} finding(s).[/green]")
    else:
        display("[yellow]No passive data found.[/yellow]")

    return findings


# ---------------------------------------------------------------------------
# ARP cache
# ---------------------------------------------------------------------------

def _arp_findings(network_prefix: str, session_id: str) -> List[Finding]:
    """Read the OS ARP cache and return one Finding per relevant entry.

    Args:
        network_prefix: IP prefix to filter (e.g. "192.168.1"). "" = all.
        session_id:     Current audit session ID.

    Returns:
        List[Finding]: One per ARP entry matching the prefix.
    """
    entries = _arp_table()
    findings = []

    for ip, mac in entries.items():
        if network_prefix and not ip.startswith(network_prefix):
            continue
        if mac in ("(incomplete)", "ff:ff:ff:ff:ff:ff"):
            continue

        findings.append(Finding(
            session_id=session_id,
            module="passive_recon",
            target_ip=ip,
            target_service="arp",
            service_version=f"MAC={mac}",
            category=Category.NETWORK,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,  # OS has confirmed this MAC-IP binding
            exposure=Exposure.INTERNAL,
            evidence=Evidence(
                raw=f"ARP cache entry: {ip} → {mac}",
                command="arp -n",
            ),
            explanation=None,
            cve_refs=[],
        ))

    return findings


def _arp_table() -> Dict[str, str]:
    """Read the OS ARP cache and return a dict of {ip: mac}.

    Parses the output of `arp -n` on Linux.
    Returns an empty dict on error or if arp is not available.

    Returns:
        Dict[str, str]: IP → MAC address mappings.
    """
    try:
        result = subprocess.run(
            ["arp", "-n"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return _parse_arp_output(result.stdout)
    except Exception:
        return {}


def _parse_arp_output(output: str) -> Dict[str, str]:
    """Parse the output of `arp -n` into a {ip: mac} dict.

    Example arp -n output line:
        192.168.1.1     ether   aa:bb:cc:dd:ee:ff   C   enp0s25

    Args:
        output: Raw stdout from `arp -n`.

    Returns:
        Dict[str, str]: {ip: mac}
    """
    entries = {}
    # Match lines: IP<spaces>HWtype<spaces>MAC<spaces>...
    pattern = re.compile(
        r"^(\d{1,3}(?:\.\d{1,3}){3})\s+\w+\s+([0-9a-fA-F:]{17})",
        re.MULTILINE,
    )
    for match in pattern.finditer(output):
        ip = match.group(1)
        mac = match.group(2).lower()
        entries[ip] = mac
    return entries


# ---------------------------------------------------------------------------
# /etc/hosts
# ---------------------------------------------------------------------------

def _hosts_file_findings(network_prefix: str, session_id: str) -> List[Finding]:
    """Read /etc/hosts and return one Finding per relevant static entry.

    Args:
        network_prefix: IP prefix filter. "" = all.
        session_id:     Current audit session ID.

    Returns:
        List[Finding]: One per matching /etc/hosts entry.
    """
    entries = _read_hosts_file()
    findings = []

    for ip, hostname in entries.items():
        if network_prefix and not ip.startswith(network_prefix):
            continue
        if ip.startswith("127.") or ip == "::1":
            continue  # skip loopback entries

        findings.append(Finding(
            session_id=session_id,
            module="passive_recon",
            target_ip=ip,
            target_service="hosts",
            service_version=f"hostname={hostname}",
            category=Category.NETWORK,
            severity=Severity.INFO,
            confidence=Confidence.PROBABLE,  # manually configured, not verified
            exposure=Exposure.INTERNAL,
            evidence=Evidence(
                raw=f"/etc/hosts entry: {ip}\t{hostname}",
                command="cat /etc/hosts",
            ),
            explanation=None,
            cve_refs=[],
        ))

    return findings


def _read_hosts_file(path: str = "/etc/hosts") -> Dict[str, str]:
    """Parse /etc/hosts and return a dict of {ip: hostname}.

    Ignores comments and blank lines.
    Takes only the first hostname per line (ignores aliases).

    Args:
        path: Path to the hosts file (default /etc/hosts).

    Returns:
        Dict[str, str]: {ip: hostname}
    """
    entries = {}
    try:
        content = Path(path).read_text(encoding="utf-8", errors="ignore")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                hostname = parts[1]
                entries[ip] = hostname
    except Exception:
        pass
    return entries


# ---------------------------------------------------------------------------
# mDNS (avahi-browse)
# ---------------------------------------------------------------------------

def _mdns_findings(network_prefix: str, session_id: str) -> List[Finding]:
    """Query the local mDNS cache via avahi-browse and return Findings.

    Uses avahi-browse --all --terminate --resolve (non-interactive).
    Falls back gracefully if avahi-browse is not installed.

    Args:
        network_prefix: IP prefix filter. "" = all.
        session_id:     Current audit session ID.

    Returns:
        List[Finding]: One per mDNS host found.
    """
    entries = _mdns_lookup()
    findings = []

    for hostname, ip in entries.items():
        if network_prefix and not ip.startswith(network_prefix):
            continue

        findings.append(Finding(
            session_id=session_id,
            module="passive_recon",
            target_ip=ip,
            target_service="mdns",
            service_version=f"hostname={hostname}",
            category=Category.NETWORK,
            severity=Severity.INFO,
            confidence=Confidence.POSSIBLE,  # mDNS is self-advertised, not verified
            exposure=Exposure.INTERNAL,
            evidence=Evidence(
                raw=f"mDNS: {hostname} → {ip}",
                command="avahi-browse --all --terminate --resolve",
            ),
            explanation=None,
            cve_refs=[],
        ))

    return findings


def _mdns_lookup() -> Dict[str, str]:
    """Run avahi-browse and parse mDNS host entries.

    Returns an empty dict if avahi-browse is not available or fails.

    Returns:
        Dict[str, str]: {hostname: ip}
    """
    try:
        result = subprocess.run(
            ["avahi-browse", "--all", "--terminate", "--resolve", "--parsable"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return _parse_avahi_output(result.stdout)
    except FileNotFoundError:
        # avahi-browse not installed — silent fallback
        return {}
    except Exception:
        return {}


def _parse_avahi_output(output: str) -> Dict[str, str]:
    """Parse avahi-browse --parsable output to extract hostname → IP mappings.

    Parsable format lines look like:
        =;eth0;IPv4;hostname;_http._tcp;local;hostname.local;192.168.1.x;80;...

    We extract lines starting with '=' (resolved entries) and pick
    the hostname (field 4) and IP (field 7).

    Args:
        output: Raw stdout from avahi-browse --parsable.

    Returns:
        Dict[str, str]: {hostname: ip}
    """
    entries = {}
    for line in output.splitlines():
        if not line.startswith("="):
            continue
        parts = line.split(";")
        if len(parts) < 8:
            continue
        hostname = parts[3].strip()
        ip = parts[7].strip()
        # Validate IP-like format
        if hostname and ip and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            entries[hostname] = ip
    return entries
