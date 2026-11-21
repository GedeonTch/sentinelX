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
import ipaddress
import re
import socket
import subprocess
import json
import uuid
from dataclasses import dataclass, field
from datetime import timezone
from pathlib import Path
from typing import Dict, List, Optional

import typer

from core.database import (
    SentinelStorageError,
    _open_sentinel_event_connection,  # R3: atomic recovery
    _reuse_or_create_asset,           # R3: atomic recovery
    _sentinel_storage_error,          # R3: atomic recovery
    sentinel_baseline_exists as db_baseline_exists,
    sentinel_get_baseline_entries,
    sentinel_network_snapshot,
    sentinel_replace_baseline,
    sentinel_upsert_baseline_entries,
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

# Internal, persisted outcome of the latest baseline learning. Its
# ``deferred_ips`` list is authoritative for hosts that answered discovery but
# never produced a complete TCP observation: they stay known and UNINITIALIZED
# across restarts until their first complete scan (no schema change).
BASELINE_INITIALIZATION_EVENT = "baseline_initialization"


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
    """Read the gateway IP of ``target_network`` from the OS routing table.

    1. A route for the target that carries ``via`` gives the gateway directly.
    2. A directly connected route (no ``via``) has no gateway of its own. The
       default route then supplies it only if it uses the same interface (``dev``),
       its address lies inside the target network and it is not the local source
       address (see ``_gateway_for_connected_route``). Otherwise the gateway is unknown.
    3. With no route at all for the target, the default route is used.

    Args:
        target_network: CIDR string.

    Returns:
        str: Gateway IP, or "" if not found (gateway unknown).
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

        # Only directly connected routes for the target: their interface decides
        # which default route, if any, can name the gateway.
        if route_lines:
            return _gateway_for_connected_route(target_network, route_lines)

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


def _route_field(parts: List[str], key: str) -> str:
    """Return the token following ``key`` in an ``ip route`` line, or ""."""
    if key in parts and parts.index(key) + 1 < len(parts):
        return parts[parts.index(key) + 1]
    return ""


def _gateway_for_connected_route(target_network: str, connected_lines: List[str]) -> str:
    """Gateway for a directly connected target route, or "" (unknown).

    The connected route fixes the interface (``dev``) and the local source address.
    A default route is accepted only if it uses exactly that interface, its gateway
    lies inside the target network and differs from the local source address. If
    several different gateways qualify, the gateway is ambiguous and stays unknown.
    """
    interfaces = set()
    local_sources = set()
    for line in connected_lines:
        parts = line.split()
        dev = _route_field(parts, "dev")
        if not dev:
            return ""
        interfaces.add(dev)
        local_sources.add(_route_field(parts, "src"))
    if len(interfaces) != 1:
        return ""
    interface = interfaces.pop()

    network = ipaddress.ip_network(target_network, strict=False)
    result = subprocess.run(
        ["ip", "route", "show", "default"],
        capture_output=True, text=True, timeout=10,
    )
    candidates = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if "via" not in parts:
            continue
        if _route_field(parts, "dev") != interface:
            continue
        gateway = _route_field(parts, "via")
        if gateway == _route_field(parts, "src") or gateway in local_sources:
            continue
        try:
            address = ipaddress.ip_address(gateway)
        except ValueError:
            continue
        if address in network:
            candidates.add(gateway)
    if len(candidates) == 1:
        return candidates.pop()
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

def _baseline_initialization_event(
    network_id: str,
    target_network: str,
    deferred_ips: List[str],
    successful_ips: List[str],
    active_ips: List[str],
) -> dict:
    """Build the internal durable record of one baseline learning outcome.

    The event is written in the same transaction as the baseline rows. Its
    ``deferred_ips`` list lets a restart distinguish a host that failed its
    initial scan (known, uninitialized) from a genuinely new host. A later
    learning event supersedes it, including a later complete one (empty list).
    """
    from sentinel.alerting import EventStamp
    from sentinel.notifications import VERSION

    snapshot = sentinel_network_snapshot(network_id)
    stamp = EventStamp.restore(network_id, snapshot["events"])
    timestamp = stamp.next()
    details = {
        # Network scope, like scan_degraded: never a fake host.
        "ip": target_network,
        "detail": "baseline initialization",
        "deferred_ips": sorted(set(deferred_ips)),
        "successful_ips": sorted(set(successful_ips)),
        "active_ips": sorted(set(active_ips)),
        "whitelisted": False,
        # Internal bookkeeping, never a notification nor a quota reservation.
        "notification": {
            "version": VERSION,
            "state": "whitelisted",
            "decided_at": timestamp,
        },
    }
    return {
        "event_id": str(uuid.uuid4()),
        "type": BASELINE_INITIALIZATION_EVENT,
        "timestamp": timestamp,
        "details": details,
        "resolved": True,
    }


def store_recovered_host_baseline(
    network_id: str,
    identity: NetworkIdentity,
    ip: str,
    ports: List[int],
    last_scan: Optional[str] = None,
    initialization_event: Optional[dict] = None,
) -> None:
    """Persist the first complete baseline of a previously deferred host.

    When ``initialization_event`` is provided, the baseline row and the event
    are written in one transaction (R3: atomic recovery). Without the event
    argument, only the baseline row is written (backward-compatible path).

    Storage errors propagate: a host is never reported as initialized before
    its baseline row (and optional event) are durable.
    """
    if ports is None:
        raise ValueError("a deferred host baseline needs a complete port list")
    scan_time = last_scan or datetime.datetime.now(timezone.utc).isoformat()

    if initialization_event is None:
        sentinel_upsert_baseline_entries(
            network_id,
            identity.target_network,
            identity.gateway_ip,
            identity.gateway_mac,
            [{"ip": ip, "mac": _get_arp_mac(ip),
              "ports": list(ports), "last_scan": scan_time}],
            scan_time,
        )
        return

    # R3: atomic path — baseline row + initialization event in one transaction.
    mac = _get_arp_mac(ip)
    subject = "baseline recuperee (hote differe)"
    conn = _open_sentinel_event_connection(network_id, subject)
    try:
        conn.execute("BEGIN IMMEDIATE")
        previous = conn.execute(
            "SELECT b.asset_id FROM baseline b JOIN assets a ON a.id=b.asset_id "
            "WHERE b.target_network=? AND b.gateway_ip=? AND b.gateway_mac=? "
            "AND a.ip=? ORDER BY b.rowid LIMIT 1",
            (identity.target_network, identity.gateway_ip, identity.gateway_mac, ip),
        ).fetchone()
        asset_id = _reuse_or_create_asset(
            conn, ip, previous[0] if previous else None, mac, scan_time,
        )
        conn.execute(
            "DELETE FROM baseline WHERE target_network=? AND gateway_ip=? "
            "AND gateway_mac=? "
            "AND asset_id IN (SELECT id FROM assets WHERE ip=?)",
            (identity.target_network, identity.gateway_ip, identity.gateway_mac, ip),
        )
        conn.execute(
            "INSERT INTO baseline "
            "(id,asset_id,target_network,gateway_ip,gateway_mac,ports,services,mac,last_scan) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), asset_id,
             identity.target_network, identity.gateway_ip, identity.gateway_mac,
             json.dumps(list(ports)), "{}", mac, scan_time),
        )
        ev = initialization_event
        conn.execute(
            "INSERT OR IGNORE INTO events "
            "(id,timestamp,type,asset_id,details,resolved) VALUES (?,?,?,?,?,?)",
            (ev["event_id"], ev["timestamp"], ev["type"],
             None, json.dumps(ev["details"]), int(ev.get("resolved", False))),
        )
        conn.commit()
    except Exception as exc:
        conn.rollback()
        raise _sentinel_storage_error(exc, subject) from exc
    finally:
        conn.close()


def learn_baseline(
    target_network: str,
    network_id: str,
    identity: NetworkIdentity,
    force_relearn: bool = False,
) -> bool:
    """Discover active hosts and their open ports, store the usable baseline.

    Each host is handled on its own outcome:

    - a complete TCP observation stores (or updates) that host's baseline;
    - a failed or incomplete observation never stores ``[]``. If the host had a
      previous baseline, that entry is retained unchanged. Otherwise the host
      is recorded as deferred (known, uninitialized) in an internal event, so a
      restart cannot mistake it for a genuinely new host;
    - when no host produces a complete observation, the baseline is not
      modified and the function returns False (Sentinel must not start healthy).

    With force_relearn, the old identity baseline is replaced in the same
    transaction as the new rows, but retained entries for failed hosts keep
    their previous ports, MAC and last_scan. A storage failure rolls everything
    back. The internal baseline-initialization event is committed with the
    baseline, so partial initialization is never persisted without its durable
    deferred markers.

    Args:
        target_network: CIDR to scan.
        network_id:     Stable identifier from compute_network_id().
        identity:       NetworkIdentity for this baseline.
        force_relearn:  If True, replace existing baseline for this identity.

    Returns:
        bool: True if at least one host was stored and monitoring may start
              (possibly degraded). False when no usable observation exists.
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
    previous = get_baseline(network_id, identity)

    # Step 2 — per-host outcome. A failed host never blocks usable peers and is
    # never stored as an empty port list.
    now = datetime.datetime.now(timezone.utc).isoformat()
    successful_entries: List[dict] = []
    retained_entries: List[dict] = []
    deferred_ips: List[str] = []
    for ip in active_ips:
        ports = parse_sentinel_open_ports(
            _run_nmap_tcp(ip, "normal", SENTINEL_TCP_PORTS), ip, SENTINEL_TCP_PORTS,
        )
        if ports is not None:
            successful_entries.append({
                "ip": ip,
                "mac": _get_arp_mac(ip),
                "ports": ports,
                "last_scan": now,
            })
            display(f"  [dim]{ip:15} — {len(ports)} port(s)[/dim]")
            continue

        old = previous.get(ip)
        if old is not None:
            retained_entries.append({
                "ip": ip,
                "mac": old.mac,
                "ports": list(old.ports or []),
                "last_scan": old.last_scan,
            })
            display(
                f"  [yellow]{ip:15} — port state unknown; previous baseline retained "
                f"({len(old.ports or [])} port(s)).[/yellow]"
            )
        else:
            deferred_ips.append(ip)
            display(
                f"  [yellow]{ip:15} — port state unknown; baseline initialization "
                "deferred (host stays UNKNOWN).[/yellow]"
            )

    if not successful_entries:
        display(
            "[red]No host produced a complete TCP observation. "
            "Baseline not changed; Sentinel will not start as healthy.[/red]"
        )
        return False

    # Step 3 — one transaction for the baseline rows and the durable
    # initialization outcome. The event is required even on full success: an
    # empty deferred list supersedes an older partial outcome after relearn.
    entries = successful_entries + retained_entries
    try:
        internal_event = _baseline_initialization_event(
            network_id,
            identity.target_network,
            deferred_ips=deferred_ips,
            successful_ips=[entry["ip"] for entry in successful_entries],
            active_ips=active_ips,
        )
    except Exception as exc:
        display(
            f"[red]Durable baseline-initialization state could not be prepared "
            f"({type(exc).__name__}). Baseline not changed.[/red]"
        )
        return False

    try:
        replaced = sentinel_replace_baseline(
            network_id,
            identity.target_network,
            identity.gateway_ip,
            identity.gateway_mac,
            entries,
            now,
            replace=force_relearn,
            internal_events=[internal_event],
        )
    except SentinelStorageError as exc:
        display(f"[red]{exc}[/red]")
        return False

    if force_relearn and replaced:
        display(f"[dim]Replaced {replaced} old baseline entry(ies).[/dim]")
    if deferred_ips:
        display(
            f"[yellow]Partial baseline stored — {len(successful_entries)} host(s) usable, "
            f"{len(deferred_ips)} host(s) deferred. Sentinel starts degraded until they "
            "provide a complete scan.[/yellow]"
        )
    display(
        f"[green]Baseline stored — {len(successful_entries)} updated host(s), "
        f"{len(retained_entries)} retained, {len(deferred_ips)} deferred, "
        f"identity: {identity}[/green]"
    )
    return True
