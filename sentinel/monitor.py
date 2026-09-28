"""
sentinel/monitor.py — Network state comparison against baseline

Role: Compare the current network state to the stored baseline and return
      a list of NetworkChange objects describing what changed.

This module does NOT create Findings, does NOT write to DB, does NOT alert.
It only observes and reports raw changes. alerting.py decides what to do.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from core.logger import display
from sentinel.arp_probe import ArpProbeStatus, arp_probe
from sentinel.baseline import BaselineEntry, NetworkIdentity


class ScanFailedError(Exception):
    """Raised when ping failed and no known host was recovered by ARP."""


class ScanDegradedError(Exception):
    """Raised when ping failed but targeted ARP recovered known hosts."""

    def __init__(self, message: str, changes: List["NetworkChange"]):
        super().__init__(message)
        self.changes = changes


@dataclass
class NetworkChange:
    """A detected deviation from the stored baseline."""

    change_type: str
    asset_ip: str
    detail: str
    evidence: str


def check_network(
    target_network: str,
    session_id: str,
    identity: NetworkIdentity,
    baseline: Dict[str, BaselineEntry],
) -> List[NetworkChange]:
    """Compare current network state to baseline and return detected changes.

    A failed ping scan may recover baseline IPs with one targeted active ARP
    probe each. Such a partial check raises ScanDegradedError after collecting
    changes, so callers can process them without marking the check successful.
    """
    display(f"[dim]Checking network {target_network}...[/dim]")

    changes: List[NetworkChange] = []
    services_degraded = False

    current_hosts = _get_active_hosts(target_network)
    ping_failed = current_hosts is None
    if current_hosts is None:
        current_hosts = []

    arp_recovered = False
    arp_results = {}
    if ping_failed:
        for ip in baseline:
            result = arp_probe(ip)
            arp_results[ip] = result
            if result.status is ArpProbeStatus.PRESENT:
                current_hosts.append(ip)
                arp_recovered = True

    if ping_failed and not arp_recovered:
        raise ScanFailedError(
            f"Ping scan failed for {target_network}; no known host was recovered by ARP."
        )

    # ARP fallback only probes baseline IPs and therefore never creates
    # new_host changes.
    for ip in current_hosts:
        if ip not in baseline:
            changes.append(NetworkChange(
                change_type="new_host",
                asset_ip=ip,
                detail="new host detected",
                evidence=f"Host {ip} responded to ping but is not in the baseline.",
            ))

    for ip, entry in baseline.items():
        if ip not in current_hosts:
            continue

        arp_result = arp_results.get(ip)
        if arp_result is not None:
            current_mac = (
                arp_result.mac
                if arp_result.status is ArpProbeStatus.PRESENT and arp_result.mac
                else ""
            )
        else:
            current_mac = _get_arp_mac(ip)
        if current_mac and entry.mac and current_mac != entry.mac.lower():
            changes.append(NetworkChange(
                change_type="mac_change",
                asset_ip=ip,
                detail=f"mac changed from {entry.mac} to {current_mac}",
                evidence=(
                    f"Active ARP probe shows {ip} → {current_mac}. "
                    f"Baseline MAC was {entry.mac}."
                ),
            ))

        current_ports = _get_open_ports(ip)
        if current_ports is None:
            services_degraded = True
            continue

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

    if ping_failed or services_degraded:
        if ping_failed:
            message = "Ping scan failed; known hosts were partially checked with targeted ARP."
        else:
            message = "Service scan failed for at least one present host."
        raise ScanDegradedError(message, changes)

    return changes


def _get_active_hosts(target_network: str) -> Optional[List[str]]:
    """Run a lightweight ping scan and return active IPs, or None on failure."""
    try:
        from recon.device_fingerprint import _run_nmap_ping, _parse_active_hosts
        xml = _run_nmap_ping(target_network)
        if xml is None:
            return None
        return _parse_active_hosts(xml)
    except Exception:
        return None


def _get_open_ports(ip: str) -> Optional[List[int]]:
    """Run a TCP port scan; None means the scan failed."""
    try:
        from detect.tcp_scan import _run_nmap_tcp, _parse_tcp_xml
        xml = _run_nmap_tcp(ip, "normal", "1-1024,3389,5432,3306,1433,8080,8443")
        if xml is None:
            return None
        findings = _parse_tcp_xml(xml, ip, "sentinel-monitor")
        return [f.target_port for f in findings if f.target_port is not None]
    except Exception:
        return None


def _get_arp_mac(ip: str) -> str:
    """Return a MAC only when an active targeted ARP probe responds."""
    result = arp_probe(ip)
    if result.status is ArpProbeStatus.PRESENT and result.mac:
        return result.mac
    return ""
