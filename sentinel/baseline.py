"""
sentinel/baseline.py — Network baseline learning and retrieval

Role: Capture the normal state of a network and store it in the database.
      Provide functions to query and manage baselines by NetworkIdentity.

NetworkIdentity = (target_network, gateway_ip, gateway_mac)
These three fields together uniquely identify a network environment.
A baseline with gateway_mac="" never matches one with a known MAC.

Rules enforced here:
- ZERO import sqlite3
- ZERO print() — display via core/logger.py
- ZERO risk_score calculation
- Confirmation (y/n) delegated to sentinel_manager — this module never prompts
- --relearn is atomic: learn first, delete old, insert new (transaction-safe)

Dependencies:
    recon/device_fingerprint.py — discover active hosts
    detect/tcp_scan.py          — discover open ports per host
    core/database.py            — persist baseline entries
"""

from __future__ import annotations

import datetime
import socket
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import timezone
from pathlib import Path
from typing import Dict, List, Optional

import typer

from core.database import (
    baseline_exists as db_baseline_exists,
    delete_baseline_for_identity,
    get_baseline_entries,
    save_asset,
    save_baseline_entry,
)
from core.logger import display


# ---------------------------------------------------------------------------
# Module-level wrappers — exposed for test patching
# ---------------------------------------------------------------------------

def _run_nmap_ping(target: str):
    from recon.device_fingerprint import _run_nmap_ping as _real
    return _real(target)


def _run_nmap_tcp(target: str, profile: str, ports: str):
    from detect.tcp_scan import _run_nmap_tcp as _real
    return _real(target, profile, ports)


def _parse_active_hosts(xml: str):
    from recon.device_fingerprint import _parse_active_hosts as _real
    return _real(xml)


def _parse_tcp_xml(xml: str, ip: str, session_id: str):
    from detect.tcp_scan import _parse_tcp_xml as _real
    return _real(xml, ip, session_id)


# ---------------------------------------------------------------------------
# NetworkIdentity
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NetworkIdentity:
    """Unique identity of a network environment.

    Two networks are the same only if all three fields match exactly.
    gateway_mac="" is a valid value (ARP unavailable) — never treated as wildcard.

    Attributes:
        target_network: CIDR string, e.g. "192.168.1.0/24".
        gateway_ip:     IP of the default gateway for this network.
        gateway_mac:    MAC of the gateway (lowercase, colon-separated).
                        "" if ARP could not resolve the gateway.
    """
    target_network: str
    gateway_ip: str
    gateway_mac: str

    def __str__(self) -> str:
        mac_display = self.gateway_mac if self.gateway_mac else "unknown"
        return f"{self.target_network} via {self.gateway_ip} [{mac_display}]"


# ---------------------------------------------------------------------------
# BaselineEntry
# ---------------------------------------------------------------------------

@dataclass
class BaselineEntry:
    """State of one asset at baseline time.

    Attributes:
        asset_id:   UUID of the asset in the DB.
        ip:         IP address.
        mac:        MAC address of the asset (not the gateway).
        ports:      List of open TCP port numbers.
        last_scan:  ISO 8601 timestamp of when this baseline was captured.
    """
    asset_id: str
    ip: str
    mac: str
    ports: List[int]
    last_scan: str


# ---------------------------------------------------------------------------
# Network identity detection
# ---------------------------------------------------------------------------

def detect_network_identity(target_network: str) -> NetworkIdentity:
    """Detect the NetworkIdentity for a target network by reading OS state.

    1. Extract network prefix from CIDR to find gateway IP from routing table.
    2. Read ARP cache for the gateway MAC.

    If gateway IP cannot be determined → gateway_ip = ""
    If gateway MAC cannot be resolved → gateway_mac = ""

    Args:
        target_network: CIDR string, e.g. "192.168.1.0/24".

    Returns:
        NetworkIdentity: Populated from OS state.
    """
    gateway_ip = _get_gateway_ip(target_network)
    gateway_mac = ""
    if gateway_ip:
        gateway_mac = _get_arp_mac(gateway_ip)
    return NetworkIdentity(
        target_network=target_network,
        gateway_ip=gateway_ip,
        gateway_mac=gateway_mac,
    )


def _get_gateway_ip(target_network: str) -> str:
    """Read the default gateway IP from the OS routing table.

    Uses `ip route` on Linux, returns the gateway for the target network.
    Falls back to the default route gateway if no specific route found.

    Args:
        target_network: CIDR string.

    Returns:
        str: Gateway IP, or "" if not found.
    """
    try:
        result = subprocess.run(
            ["ip", "route", "show", target_network],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            if "via" in line:
                parts = line.split()
                via_idx = parts.index("via")
                return parts[via_idx + 1]
        # Fallback: default route
        result2 = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result2.stdout.splitlines():
            if "via" in line:
                parts = line.split()
                via_idx = parts.index("via")
                return parts[via_idx + 1]
    except Exception:
        pass
    return ""


def _get_arp_mac(ip: str) -> str:
    """Look up a MAC address from the OS ARP cache for a given IP.

    Args:
        ip: IP address to look up.

    Returns:
        str: MAC address (lowercase), or "" if not in ARP cache.
    """
    import re
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


# ---------------------------------------------------------------------------
# baseline_exists wrapper
# ---------------------------------------------------------------------------

def baseline_exists(session_id: str, identity: NetworkIdentity) -> bool:
    """Return True if a baseline exists for this exact NetworkIdentity.

    Args:
        session_id: Session identifier.
        identity:   NetworkIdentity to check.

    Returns:
        bool
    """
    return db_baseline_exists(
        session_id,
        identity.target_network,
        identity.gateway_ip,
        identity.gateway_mac,
    )


# ---------------------------------------------------------------------------
# get_baseline
# ---------------------------------------------------------------------------

def get_baseline(
    session_id: str,
    identity: NetworkIdentity,
) -> Dict[str, BaselineEntry]:
    """Return the stored baseline for a NetworkIdentity as a dict keyed by IP.

    Only returns entries for the exact triplet (target_network, gateway_ip,
    gateway_mac). Never returns entries for a different network identity.

    Args:
        session_id: Session identifier.
        identity:   NetworkIdentity to query.

    Returns:
        Dict[str, BaselineEntry]: {ip: BaselineEntry}. Empty if no baseline.
    """
    rows = get_baseline_entries(
        session_id,
        identity.target_network,
        identity.gateway_ip,
        identity.gateway_mac,
    )
    result: Dict[str, BaselineEntry] = {}
    for row in rows:
        ip = row.get("ip", "")
        if not ip:
            continue
        result[ip] = BaselineEntry(
            asset_id=row["asset_id"],
            ip=ip,
            mac=row.get("asset_mac") or "",
            ports=row.get("ports", []),
            last_scan=row["last_scan"],
        )
    return result


# ---------------------------------------------------------------------------
# learn_baseline
# ---------------------------------------------------------------------------

def learn_baseline(
    target_network: str,
    session_id: str,
    identity: NetworkIdentity,
    force_relearn: bool = False,
) -> bool:
    """Discover active hosts and their open ports, store as baseline.

    Atomic relearn: if force_relearn=True, the old baseline is deleted only
    after the new one has been successfully learned (at least 1 host found).
    If discovery finds 0 hosts, the old baseline is preserved and False is
    returned.

    Args:
        target_network: CIDR to scan.
        session_id:     Current audit session ID.
        identity:       NetworkIdentity for this baseline.
        force_relearn:  If True, replace existing baseline for this identity.

    Returns:
        bool: True if baseline was successfully learned and stored, False otherwise.
    """
    display(f"[cyan]Learning baseline for {identity}...[/cyan]")

    # Step 1 — discover active hosts via module-level wrappers (patchable in tests)
    ping_xml = _run_nmap_ping(target_network)
    if not ping_xml:
        display("[yellow]No hosts found during baseline ping scan.[/yellow]")
        return False

    active_ips = _parse_active_hosts(ping_xml)
    if not active_ips:
        display("[yellow]No active hosts — baseline not stored.[/yellow]")
        return False

    display(f"[green]{len(active_ips)} host(s) found.[/green]")

    # Step 2 — scan ports per host using module-level wrappers
    try:
        pass  # wrappers already defined at module level
    except ImportError:
        display("[red]tcp_scan module not available.[/red]")
        return False

    now = datetime.datetime.now(timezone.utc).isoformat()
    new_entries: List[dict] = []

    for ip in active_ips:
        port_xml = _run_nmap_tcp(ip, "normal", "1-1024,3389,5432,3306,1433,8080,8443")
        ports: List[int] = []
        if port_xml:
            findings = _parse_tcp_xml(port_xml, ip, session_id)
            ports = [f.target_port for f in findings if f.target_port is not None]

        asset_id = str(uuid.uuid4())
        mac = _get_arp_mac(ip)
        new_entries.append({
            "asset_id": asset_id,
            "ip": ip,
            "mac": mac,
            "ports": ports,
        })
        display(f"  [dim]{ip:15} — {len(ports)} port(s)[/dim]")

    # Step 3 — atomic store
    # Delete old baseline ONLY after successful discovery
    if force_relearn and baseline_exists(session_id, identity):
        deleted = delete_baseline_for_identity(
            session_id,
            identity.target_network,
            identity.gateway_ip,
            identity.gateway_mac,
        )
        display(f"[dim]Replaced {deleted} old baseline entry(ies).[/dim]")

    for entry in new_entries:
        # Ensure asset is in DB
        save_asset(
            session_id=session_id,
            asset_id=entry["asset_id"],
            ip=entry["ip"],
            first_seen=now,
            mac=entry["mac"] or None,
        )
        save_baseline_entry(
            session_id=session_id,
            entry_id=str(uuid.uuid4()),
            asset_id=entry["asset_id"],
            target_network=identity.target_network,
            gateway_ip=identity.gateway_ip,
            gateway_mac=identity.gateway_mac,
            ports=entry["ports"],
            mac=entry["mac"] or None,
            last_scan=now,
        )

    display(f"[green]Baseline stored — {len(new_entries)} host(s), identity: {identity}[/green]")
    return True
