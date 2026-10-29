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
import re
import socket
import subprocess
from dataclasses import dataclass, field
from datetime import timezone
from pathlib import Path
from typing import Dict, List, Optional

import typer

from core.database import (
    SentinelStorageError,
    sentinel_baseline_exists as db_baseline_exists,
    sentinel_get_baseline_entries,
    sentinel_replace_baseline,
)
from core.logger import display


# ---------------------------------------------------------------------------
# Network ID — stable identifier derived from NetworkIdentity
# ---------------------------------------------------------------------------

def compute_network_id(identity: "NetworkIdentity") -> str:
    """Derive a stable, filesystem-safe identifier from a NetworkIdentity.

    Uses SHA-256 of "target_network|gateway_ip|gateway_mac" (lowercase).
    Truncated to 12 hex chars — deterministic across restarts.

    Same network = same network_id, always.
    Different gateway MAC = different network_id.

    Args:
        identity: NetworkIdentity triplet.

    Returns:
        str: 12-character lowercase hex string safe for use as a filename.

    Examples:
        NetworkIdentity("192.168.1.0/24", "192.168.1.1", "aa:bb:cc:dd:ee:ff")
        → "a3f9c2b1e047"  (example only — actual value depends on hash)
    """
    import hashlib
    raw = f"{identity.target_network}|{identity.gateway_ip}|{identity.gateway_mac}".lower()
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Module-level wrappers — exposed for test patching
# ---------------------------------------------------------------------------

def _run_nmap_ping(target: str):
    from recon.device_fingerprint import _run_nmap_ping as _real
    return _real(target)


# Ports scanned for every Sentinel host (baseline and monitor share this scope).
SENTINEL_TCP_PORTS = "1-1024,3389,5432,3306,1433,8080,8443"


def _run_nmap_tcp(target: str, profile: str, ports: str):
    # Strict mode: a non-zero nmap exit code yields None, never partial output.
    from detect.tcp_scan import _run_nmap_tcp as _real
    return _real(target, profile, ports, strict=True)


def _parse_active_hosts(xml: str):
    from recon.device_fingerprint import _parse_active_hosts as _real
    return _real(xml)


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
        gateway_display = self.gateway_ip if self.gateway_ip else "unknown"
        return f"{self.target_network} via {gateway_display} [{mac_display}]"


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
        route_lines = [line for line in result.stdout.splitlines() if line.strip()]
        for line in route_lines:
            parts = line.split()
            if "via" in parts:
                via_idx = parts.index("via")
                gateway = parts[via_idx + 1]
                # A route must never identify the local interface as its
                # gateway. The connected-route form (dev ... src ...) has no
                # real gateway and is handled below.
                src = parts[parts.index("src") + 1] if "src" in parts else ""
                if gateway != src:
                    return gateway
                return ""

        # A matching connected route is host-only/local-link evidence: do not
        # fall back to an unrelated default route on another interface.
        if route_lines:
            return ""

        # Fallback: default route only when no route exists for the target.
        result2 = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result2.stdout.splitlines():
            parts = line.split()
            if "via" in parts:
                via_idx = parts.index("via")
                gateway = parts[via_idx + 1]
                src = parts[parts.index("src") + 1] if "src" in parts else ""
                if gateway != src:
                    return gateway
                return ""
    except Exception:
        pass
    return ""


_MAC_TOKEN_RE = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")
_NEIGH_UNUSABLE_STATES = frozenset({"FAILED", "INCOMPLETE"})


def _arp_tool_macs(ip: str) -> Optional[List[str]]:
    """MACs listed for ``ip`` by ``arp -n``, or None when the tool is unusable."""
    try:
        result = subprocess.run(
            ["arp", "-n", ip], capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None  # the tool ran but failed: unusable, so ip neigh is tried
    macs: List[str] = []
    for line in result.stdout.splitlines():
        tokens = line.split()
        if not tokens or not (tokens[0] == ip or f"({ip})" in tokens[:2]):
            continue
        macs.extend(
            token.lower() for token in tokens[1:]
            if _MAC_TOKEN_RE.match(token) and token.lower() != "ff:ff:ff:ff:ff:ff"
        )
    return macs


def _ip_neigh_macs(ip: str) -> Optional[List[str]]:
    """MACs listed for ``ip`` by ``ip -4 neigh``, or None when the tool is unusable."""
    from recon.passive_recon import _parse_ip_neigh_output
    try:
        result = subprocess.run(
            ["ip", "-4", "neigh", "show", "to", ip],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return [
        mac for entry_ip, mac, state in _parse_ip_neigh_output(result.stdout)
        if entry_ip == ip and state not in _NEIGH_UNUSABLE_STATES
    ]


def _get_arp_mac(ip: str) -> str:
    """Return the neighbour-cache MAC of exactly ``ip``, or "" when it is unknown.

    Reads ``arp -n``; ``ip -4 neigh`` is consulted only when the ``arp`` tool is
    missing or unusable. No probe is sent. An empty answer (no usable entry,
    conflicting MACs, no tool) means "MAC unknown": the host is stored without
    a MAC, and that absence is never read as a change.

    Args:
        ip: IP address to look up.

    Returns:
        str: MAC address (lowercase), or "" when it is not reliably known.
    """
    macs = _arp_tool_macs(ip)
    if macs is None:
        macs = _ip_neigh_macs(ip)
    if macs is None:
        display(f"[yellow]No usable ARP tool (arp, ip neigh): MAC of {ip} unknown.[/yellow]")
        return ""
    unique = sorted(set(macs))
    if len(unique) > 1:
        display(f"[yellow]Conflicting ARP entries for {ip}: MAC unknown.[/yellow]")
        return ""
    if not unique:
        display(f"[yellow]No reliable ARP entry for {ip}: MAC unknown.[/yellow]")
        return ""
    return unique[0]


# ---------------------------------------------------------------------------
# baseline_exists wrapper
# ---------------------------------------------------------------------------

def baseline_exists(network_id: str, identity: NetworkIdentity) -> bool:
    """Return True if a baseline exists for this exact NetworkIdentity.

    Args:
        network_id: Stable identifier from compute_network_id().
        identity:   NetworkIdentity to check.

    Returns:
        bool
    """
    return db_baseline_exists(
        network_id,
        identity.target_network,
        identity.gateway_ip,
        identity.gateway_mac,
    )


# ---------------------------------------------------------------------------
# get_baseline
# ---------------------------------------------------------------------------

def get_baseline(
    network_id: str,
    identity: NetworkIdentity,
) -> Dict[str, BaselineEntry]:
    """Return the stored baseline for a NetworkIdentity as a dict keyed by IP.

    Reads from the persistent sentinel DB (not a session DB).

    Args:
        network_id: Stable identifier from compute_network_id().
        identity:   NetworkIdentity to query.

    Returns:
        Dict[str, BaselineEntry]: {ip: BaselineEntry}. Empty if no baseline.
    """
    rows = sentinel_get_baseline_entries(
        network_id,
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
    network_id: str,
    identity: NetworkIdentity,
    force_relearn: bool = False,
) -> bool:
    """Discover active hosts and their open ports, store as baseline.

    Stores in the persistent sentinel DB (~/.netlab/sentinel/<network_id>.db).
    Learning is all-or-nothing: every active host needs a proven complete port
    scan (an unknown host aborts it, with no partial baseline). With
    force_relearn, the old baseline is replaced in the same transaction as the
    new one, so a failure leaves the previous baseline untouched.

    Args:
        target_network: CIDR to scan.
        network_id:     Stable identifier from compute_network_id().
        identity:       NetworkIdentity for this baseline.
        force_relearn:  If True, replace existing baseline for this identity.

    Returns:
        bool: True if baseline was successfully learned and stored.
    """
    from detect.tcp_scan import parse_sentinel_open_ports
    from recon.device_fingerprint import DiscoveryFailed

    display(f"[cyan]Learning baseline for {identity}...[/cyan]")

    # Step 1 — discover active hosts. A failed or unreadable ping scan is an
    # unknown state, never an empty network.
    try:
        ping_xml = _run_nmap_ping(target_network)
        if not ping_xml:
            display("[yellow]No hosts found during baseline ping scan. Baseline not changed.[/yellow]")
            return False
        active_ips = _parse_active_hosts(ping_xml)
    except DiscoveryFailed as exc:
        display(f"[yellow]Baseline ping scan failed ({exc}). Baseline not changed.[/yellow]")
        return False
    if not active_ips:
        display("[yellow]No active hosts. Baseline not changed.[/yellow]")
        return False

    display(f"[green]{len(active_ips)} host(s) found.[/green]")

    # Step 2 — every host needs a proven complete port scan. One unknown host
    # aborts the whole learning: no partial baseline is ever stored.
    now = datetime.datetime.now(timezone.utc).isoformat()
    new_entries: List[dict] = []
    for ip in active_ips:
        ports = parse_sentinel_open_ports(
            _run_nmap_tcp(ip, "normal", SENTINEL_TCP_PORTS), ip, SENTINEL_TCP_PORTS,
        )
        if ports is None:
            display(
                f"[red]Port state of {ip} is unknown (scan failed or incomplete). "
                "Baseline not stored; previous baseline unchanged.[/red]"
            )
            return False
        new_entries.append({"ip": ip, "mac": _get_arp_mac(ip), "ports": ports})
        display(f"  [dim]{ip:15} — {len(ports)} port(s)[/dim]")

    # Step 3 — one transaction: the old baseline goes only if the new one is stored.
    try:
        replaced = sentinel_replace_baseline(
            network_id,
            identity.target_network,
            identity.gateway_ip,
            identity.gateway_mac,
            new_entries,
            now,
            replace=force_relearn,
        )
    except SentinelStorageError as exc:
        display(f"[red]{exc}[/red]")
        return False

    if force_relearn and replaced:
        display(f"[dim]Replaced {replaced} old baseline entry(ies).[/dim]")
    display(f"[green]Baseline stored — {len(new_entries)} host(s), identity: {identity}[/green]")
    return True
