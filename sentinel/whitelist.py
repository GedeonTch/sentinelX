"""
sentinel/whitelist.py — Whitelist management for Sentinel V1

Loads ~/.netlab/baseline_whitelist.yaml and provides functions to test
whether a detected NetworkChange is authorized by the user.

Rules enforced here:
- ZERO import sqlite3
- ZERO print() — display via core/logger.py
- Returns Optional[Whitelist] or bool — never raises on missing file
- Whitelist is the source of truth for "authorized change" decisions
- A whitelisted change still produces an event (resolved=1) — it is never invisible

CLI commands (implemented in cli.py) write to this YAML file:
    netlab sentinel allow port <ip> <port>
    netlab sentinel allow host <ip>
    netlab sentinel allow mac <ip> <mac>
    netlab sentinel unallow port/host/mac ...
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional

import yaml

from core.logger import display


# ---------------------------------------------------------------------------
# Default whitelist file path
# ---------------------------------------------------------------------------

WHITELIST_PATH = Path.home() / ".netlab" / "baseline_whitelist.yaml"

_DEFAULT_MAX_ALERTS = 3


# ---------------------------------------------------------------------------
# Whitelist dataclass
# ---------------------------------------------------------------------------

@dataclass
class Whitelist:
    """Parsed content of baseline_whitelist.yaml.

    Attributes:
        allowed_new_macs:        List of MAC addresses allowed to appear as new.
        allowed_port_changes:    List of {host: ip, ports: [n, ...]} dicts.
        allowed_new_hosts:       List of IP addresses allowed to appear as new hosts.
        sentinel_max_alerts_per_hour: Alert threshold before silent mode.
    """
    allowed_new_macs: List[str] = field(default_factory=list)
    allowed_port_changes: List[Dict] = field(default_factory=list)
    allowed_new_hosts: List[str] = field(default_factory=list)
    sentinel_max_alerts_per_hour: int = _DEFAULT_MAX_ALERTS


# ---------------------------------------------------------------------------
# Load
# ---------------------------------------------------------------------------

def load_whitelist(path: Path = WHITELIST_PATH) -> Whitelist:
    """Load the whitelist from YAML file.

    Falls back to empty Whitelist with defaults if the file is missing
    or malformed — never raises.

    Args:
        path: Path to baseline_whitelist.yaml (injectable for tests).

    Returns:
        Whitelist: Populated from file, or default empty whitelist.
    """
    if not path.exists():
        return Whitelist()

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        return Whitelist(
            allowed_new_macs=_normalize_macs(data.get("allowed_new_macs", [])),
            allowed_port_changes=data.get("allowed_port_changes", []),
            allowed_new_hosts=data.get("allowed_new_hosts", []),
            sentinel_max_alerts_per_hour=int(
                data.get("sentinel_max_alerts_per_hour", _DEFAULT_MAX_ALERTS)
            ),
        )
    except Exception as exc:
        display(f"[yellow]Whitelist load warning: {exc} — using empty whitelist.[/yellow]")
        return Whitelist()


# ---------------------------------------------------------------------------
# Save (used by CLI allow/unallow commands)
# ---------------------------------------------------------------------------

def save_whitelist(whitelist: Whitelist, path: Path = WHITELIST_PATH) -> None:
    """Write the current whitelist back to YAML.

    Creates parent directories if needed.

    Args:
        whitelist: Whitelist object to serialize.
        path:      Destination path.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "allowed_new_macs": whitelist.allowed_new_macs,
        "allowed_port_changes": whitelist.allowed_port_changes,
        "allowed_new_hosts": whitelist.allowed_new_hosts,
        "sentinel_max_alerts_per_hour": whitelist.sentinel_max_alerts_per_hour,
    }
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)


# ---------------------------------------------------------------------------
# Allow / Unallow helpers (called by CLI)
# ---------------------------------------------------------------------------

def allow_port(ip: str, port: int, path: Path = WHITELIST_PATH) -> None:
    """Add a port authorization for a specific host.

    Args:
        ip:   Host IP address.
        port: TCP port number to authorize.
        path: Whitelist file path.
    """
    wl = load_whitelist(path)
    for entry in wl.allowed_port_changes:
        if entry.get("host") == ip:
            if port not in entry.get("ports", []):
                entry["ports"].append(port)
            save_whitelist(wl, path)
            return
    wl.allowed_port_changes.append({"host": ip, "ports": [port]})
    save_whitelist(wl, path)


def unallow_port(ip: str, port: int, path: Path = WHITELIST_PATH) -> None:
    """Remove a port authorization for a specific host.

    Args:
        ip:   Host IP address.
        port: TCP port number to remove.
        path: Whitelist file path.
    """
    wl = load_whitelist(path)
    for entry in wl.allowed_port_changes:
        if entry.get("host") == ip and port in entry.get("ports", []):
            entry["ports"].remove(port)
    wl.allowed_port_changes = [e for e in wl.allowed_port_changes if e.get("ports")]
    save_whitelist(wl, path)


def allow_host(ip: str, path: Path = WHITELIST_PATH) -> None:
    """Add a new host IP to the whitelist.

    Args:
        ip:   Host IP address to authorize.
        path: Whitelist file path.
    """
    wl = load_whitelist(path)
    if ip not in wl.allowed_new_hosts:
        wl.allowed_new_hosts.append(ip)
    save_whitelist(wl, path)


def unallow_host(ip: str, path: Path = WHITELIST_PATH) -> None:
    """Remove a host IP from the whitelist.

    Args:
        ip:   Host IP address to remove.
        path: Whitelist file path.
    """
    wl = load_whitelist(path)
    wl.allowed_new_hosts = [h for h in wl.allowed_new_hosts if h != ip]
    save_whitelist(wl, path)


def allow_mac(ip: str, mac: str, path: Path = WHITELIST_PATH) -> None:
    """Add a MAC address to the allowed new MACs list.

    Args:
        ip:   Host IP (informational only — stored in comment context).
        mac:  MAC address to authorize.
        path: Whitelist file path.
    """
    wl = load_whitelist(path)
    normalized = _normalize_mac(mac)
    if normalized and normalized not in wl.allowed_new_macs:
        wl.allowed_new_macs.append(normalized)
    save_whitelist(wl, path)


def unallow_mac(ip: str, path: Path = WHITELIST_PATH) -> None:
    """Remove MAC authorization for a host IP (removes all MACs for that IP).

    In V1 the whitelist stores MACs without IP binding — this removes all
    matching MACs. Caller should confirm before calling.

    Args:
        ip:   Host IP (used for display context only).
        path: Whitelist file path.
    """
    # V1: MAC whitelist is a flat list — nothing to match by IP
    # This is intentionally a no-op on the MAC list; the caller
    # manages which MACs to remove via allow_mac / direct YAML edit.
    display(
        f"[yellow]unallow mac for {ip}: edit ~/.netlab/baseline_whitelist.yaml "
        f"directly to remove specific MACs.[/yellow]"
    )


# ---------------------------------------------------------------------------
# is_whitelisted
# ---------------------------------------------------------------------------

def is_whitelisted(
    change_type: str,
    asset_ip: str,
    detail: str,
    whitelist: Whitelist,
) -> bool:
    """Return True if this change is explicitly authorized in the whitelist.

    Args:
        change_type: "new_host" | "new_port" | "mac_change"
        asset_ip:    IP address of the asset that changed.
        detail:      Detail string from NetworkChange (e.g. "port 8080" or
                     "mac bb:bb:cc:dd:ee:ff").
        whitelist:   Loaded Whitelist object.

    Returns:
        bool: True if the change is authorized, False otherwise.
    """
    if change_type == "new_host":
        return asset_ip in whitelist.allowed_new_hosts

    if change_type == "new_port":
        port = _extract_port(detail)
        if port is None:
            return False
        for entry in whitelist.allowed_port_changes:
            if entry.get("host") == asset_ip and port in entry.get("ports", []):
                return True
        return False

    if change_type == "mac_change":
        new_mac = _extract_new_mac(detail)
        if not new_mac:
            return False
        return new_mac in whitelist.allowed_new_macs

    return False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalize_mac(mac: str) -> str:
    """Normalize a MAC address to lowercase colon-separated format.

    Returns "" if the input is not a valid MAC address.
    """
    if not mac:
        return ""
    cleaned = mac.lower().replace("-", ":").strip()
    if re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", cleaned):
        return cleaned
    return ""


def _normalize_macs(macs: list) -> List[str]:
    """Normalize a list of MAC addresses, dropping invalid ones."""
    return [m for m in (_normalize_mac(mac) for mac in macs) if m]


def _extract_port(detail: str) -> Optional[int]:
    """Extract a port number from a detail string like 'port 8080 opened'."""
    match = re.search(r"\b(\d{1,5})\b", detail)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return None
    return None


def _extract_mac(detail: str) -> str:
    """Extract the first MAC address from a detail string."""
    match = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", detail)
    if match:
        return match.group(1).lower()
    return ""


def _extract_new_mac(detail: str) -> str:
    """Extract the NEW (second) MAC address from a mac_change detail string.

    Detail format: "mac changed from <old_mac> to <new_mac>"
    Returns the last MAC address found in the string.
    """
    matches = re.findall(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", detail)
    if matches:
        return matches[-1].lower()
    return ""
