"""
sentinel/monitor.py — Network state comparison against baseline

Role: Compare the current network state to the stored baseline and return
      a list of NetworkChange objects describing what changed.

This module does NOT create Findings, does NOT write to DB, does NOT alert.
It only observes and reports raw changes. alerting.py decides what to do.

Changes detected (V1):
    new_host    — an IP is active but not in the baseline
    new_port    — a port is open on a known host but not in its baseline
    mac_change  — the MAC of a known host differs from the baseline

NOT detected in V1:
    removed_host — a baseline host that no longer responds (out of scope)

Return contract (A3 fix):
    check_network() raises ScanFailedError if the ping scan itself fails.
    Callers (_do_check in sentinel_manager) must catch ScanFailedError and
    NOT update last_check_time — a failed scan is not a successful check.

    _get_open_ports() returns:
        None      → port scan failed for this host (skip, do not report)
        []        → scan succeeded, no open ports found
        [n, ...]  → scan succeeded, ports found

Rules enforced here:
- ZERO import sqlite3
- ZERO print() — display via core/logger.py
- ZERO risk_score calculation
"""

from __future__ import annotations

import subprocess
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from core.logger import display
from sentinel.baseline import BaselineEntry, NetworkIdentity


# ---------------------------------------------------------------------------
# ScanFailedError — raised when the ping scan itself fails
# ---------------------------------------------------------------------------

class ScanFailedError(Exception):
    """Raised by check_network() when the ping scan could not be completed.

    Callers must catch this and NOT update last_check_time.
    A failed scan is not a successful check — the network state is unknown.
    """
    pass


# ---------------------------------------------------------------------------
# NetworkChange dataclass
# ---------------------------------------------------------------------------

@dataclass
class NetworkChange:
    """A detected deviation from the stored baseline.

    Attributes:
        change_type: "new_host" | "new_port" | "mac_change"
        asset_ip:    IP address of the affected host.
        detail:      Human-readable description of the change.
                     Format conventions:
                       new_host  → "new host detected"
                       new_port  → "port <n> opened"
                       mac_change → "mac changed from <old> to <new>"
        evidence:    Raw output that produced the observation (for Finding.evidence.raw).
    """
    change_type: str
    asset_ip: str
    detail: str
    evidence: str


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def check_network(
    target_network: str,
    session_id: str,
    identity: NetworkIdentity,
    baseline: Dict[str, BaselineEntry],
) -> List[NetworkChange]:
    """Compare current network state to baseline and return detected changes.

    Performs a lightweight ping scan to find active hosts, then a TCP port
    scan on known hosts to detect new ports, and reads the ARP cache for
    MAC changes.

    A host that disappears (in baseline but not responding) is NOT reported
    in V1 — removed_host is out of scope.

    Args:
        target_network: CIDR to monitor.
        session_id:     Current session ID (for TCP scan results context).
        identity:       NetworkIdentity being monitored.
        baseline:       {ip: BaselineEntry} dict from sentinel/baseline.py.

    Returns:
        List[NetworkChange]: Detected changes. Empty if network matches baseline.
    """
    display(f"[dim]Checking network {target_network}...[/dim]")

    changes: List[NetworkChange] = []

    # Step 1 — discover currently active hosts
    current_hosts = _get_active_hosts(target_network)
    if current_hosts is None:
        # Ping scan failed entirely — raise so caller knows not to update last_check_time
        raise ScanFailedError(
            f"Ping scan failed for {target_network} — network state unknown."
        )

    # Step 2 — detect new hosts
    for ip in current_hosts:
        if ip not in baseline:
            changes.append(NetworkChange(
                change_type="new_host",
                asset_ip=ip,
                detail="new host detected",
                evidence=f"Host {ip} responded to ping but is not in the baseline.",
            ))

    # Step 3 — check known hosts for new ports and MAC changes
    for ip, entry in baseline.items():
        if ip not in current_hosts:
            continue  # host not responding — not reported in V1

        # MAC change check (via ARP cache)
        current_mac = _get_arp_mac(ip)
        if current_mac and entry.mac and current_mac != entry.mac.lower():
            changes.append(NetworkChange(
                change_type="mac_change",
                asset_ip=ip,
                detail=f"mac changed from {entry.mac} to {current_mac}",
                evidence=(
                    f"ARP cache shows {ip} → {current_mac}. "
                    f"Baseline MAC was {entry.mac}."
                ),
            ))

        # New port check — scan known hosts only
        current_ports = _get_open_ports(ip)
        if current_ports is None:
            continue  # scan failed — skip this host silently

        for port in current_ports:
            if port not in entry.ports:
                changes.append(NetworkChange(
                    change_type="new_port",
                    asset_ip=ip,
                    detail=f"port {port} opened",
                    evidence=(
                        f"Port {port}/tcp open on {ip}. "
                        f"Baseline ports: {entry.ports}."
                    ),
                ))

    if changes:
        display(f"[yellow]Monitor: {len(changes)} change(s) detected.[/yellow]")
    else:
        display("[dim]Monitor: no changes detected.[/dim]")

    return changes


# ---------------------------------------------------------------------------
# Internal scan helpers
# ---------------------------------------------------------------------------

def _get_active_hosts(target_network: str) -> Optional[List[str]]:
    """Run a lightweight ping scan and return list of active IPs.

    Args:
        target_network: CIDR or single IP.

    Returns:
        List[str]: Active IPs, or None if the scan failed entirely.
    """
    try:
        from recon.device_fingerprint import _run_nmap_ping, _parse_active_hosts
        xml = _run_nmap_ping(target_network)
        if xml is None:
            return None
        return _parse_active_hosts(xml)
    except Exception:
        return None


def _get_open_ports(ip: str) -> Optional[List[int]]:
    """Run a TCP port scan on a single host and return open port numbers.

    Return contract (A3):
        None      → scan failed (nmap error, timeout) — caller must skip this host
        []        → scan succeeded, no open ports found
        [n, ...]  → scan succeeded, these ports are open

    Args:
        ip: Single IP address.

    Returns:
        Optional[List[int]]: Open ports, or None if scan failed.
    """
    try:
        from detect.tcp_scan import _run_nmap_tcp, _parse_tcp_xml
        xml = _run_nmap_tcp(ip, "normal", "1-1024,3389,5432,3306,1433,8080,8443")
        if xml is None:
            # nmap returned nothing — scan failed, state unknown
            return None
        findings = _parse_tcp_xml(xml, ip, "sentinel-monitor")
        return [f.target_port for f in findings if f.target_port is not None]
    except Exception:
        return None


def _get_arp_mac(ip: str) -> str:
    """Read the MAC address for an IP from the OS ARP cache.

    Args:
        ip: IP address to look up.

    Returns:
        str: MAC address (lowercase), or "" if not found.
    """
    try:
        result = subprocess.run(
            ["arp", "-n", ip],
            capture_output=True, text=True, timeout=10,
        )
        match = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", result.stdout)
        if match:
            return match.group(1).lower()
    except Exception:
        pass
    return ""
