"""
sentinel/monitor.py — Network observation for one Sentinel cycle

Role: Observe the network once per cycle and report what was seen, without
      deciding anything about history. The observations are returned as a
      CycleObservations; sentinel/sentinel_manager.py turns them into events.

What this module does:
    - ping scan (nmap -sn) for the target network;
    - targeted active ARP probe for each known host (baseline or already
      known) that the ping did not return, one probe per IP per cycle;
    - TCP scan of every current host, with -Pn for hosts not seen by ping;
    - candidate new_host (ping-visible, not known) and mac_change
      (baseline MAC differs from the active ARP answer).

What this module does NOT do:
    - no new_port, port_not_open, host_not_observed, host_recovered or
      scan_degraded decision (sentinel/sentinel_manager.py, §9.5);
    - no Finding, no DB write, no alert.

Failure contract (§9.4):
    ping ok + TCP complete            -> CycleObservations
    ping ok + TCP incomplete          -> ScanDegradedError(observations)
    ping failed + >=1 PRESENT or NOT_OBSERVED -> ScanDegradedError(observations)
    ping failed + all ERROR / no probe        -> ScanFailedError
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Set

from sentinel.arp_probe import ArpProbeResult, ArpProbeStatus, arp_probe
from core.process_control import ScanInterrupted
from sentinel.baseline import SENTINEL_TCP_PORTS, BaselineEntry, NetworkIdentity


class ScanFailedError(Exception):
    """No exploitable observation: ping failed and no ARP probe gave PRESENT or NOT_OBSERVED."""


@dataclass
class HostTcpObservation:
    """TCP state of one host for this cycle.

    ports: None = unknown (scan incomplete or not performed),
           []   = complete scan, no open port,
           [..] = complete scan, these ports are open.
    """

    ip: str
    ports: Optional[List[int]]


@dataclass
class NetworkChange:
    """A candidate or recorded change.

    Only new_host and mac_change are produced here. Port and host transitions
    are computed by the manager (§9.5); new_port, port_not_open and
    host_recovered may carry ``port`` or ``initial_ports`` fields in the event.
    """

    change_type: str
    asset_ip: str
    detail: str
    evidence: str
    port: Optional[int] = None
    initial_ports: Optional[List[int]] = None
    initial_ports_known: bool = False


@dataclass
class CycleObservations:
    """Everything observed during one cycle (§9.3)."""

    current_hosts: List[str]                              # ping ∪ ARP recovery
    ping_hosts: List[str]                                 # seen by nmap ping only
    host_arp_status: Dict[str, ArpProbeStatus]            # probed IPs only
    tcp_observations: Dict[str, HostTcpObservation]       # every current host
    candidate_changes: List[NetworkChange]                # [new_host, mac_change]
    ping_failed: bool
    services_degraded: bool


class ScanDegradedError(Exception):
    """Partial cycle: the observations are exploitable but incomplete."""

    def __init__(self, message: str, observations: CycleObservations):
        super().__init__(message)
        self.observations = observations


def check_network(
    target_network: str,
    session_id: str,
    identity: NetworkIdentity,
    baseline: Dict[str, BaselineEntry],
    known_hosts: Set[str],
    should_stop: Optional[Callable[[], bool]] = None,
) -> CycleObservations:
    """Observe the network for one cycle.

    Args:
        target_network: CIDR scanned by ping.
        session_id:     Run session (kept for call-site compatibility).
        identity:       Network identity of the monitored network.
        baseline:       Stored baseline, keyed by IP.
        known_hosts:    IPs known to Sentinel (baseline hosts and hosts already
                        recorded as new_host). A ping-visible IP in this set is
                        not reported as new_host again (§9.5 step 1).
        should_stop:    None runs the cycle to completion. A callable returning
                        True interrupts the running nmap process and raises
                        ScanInterrupted: the cycle is abandoned, nothing is
                        observed or persisted for it.

    Returns:
        CycleObservations when the cycle is complete.

    Raises:
        ScanDegradedError: partial cycle, with the observations attached.
        ScanFailedError:   no exploitable observation at all.
        ScanInterrupted:   a stop was requested during the cycle (BaseException).
    """
    known = set(known_hosts)

    ping_result = _get_active_hosts(target_network, should_stop=should_stop)
    ping_failed = ping_result is None
    ping_hosts = [] if ping_failed else list(dict.fromkeys(ping_result))

    # Targeted ARP: every baseline or known IP that ping did not return.
    # One probe per IP per cycle; results are reused below.
    arp_results: Dict[str, ArpProbeResult] = {}
    for ip in _arp_targets(baseline, known, ping_hosts):
        _checkpoint(should_stop)
        arp_results[ip] = arp_probe(ip)
    host_arp_status = {ip: result.status for ip, result in arp_results.items()}

    if ping_failed and not any(
        status in (ArpProbeStatus.PRESENT, ArpProbeStatus.NOT_OBSERVED)
        for status in host_arp_status.values()
    ):
        raise ScanFailedError(
            f"Ping scan failed for {target_network}; no known host gave a usable ARP answer."
        )

    recovered = [
        ip for ip, result in arp_results.items()
        if result.status is ArpProbeStatus.PRESENT and ip not in ping_hosts
    ]
    current_hosts = ping_hosts + recovered

    tcp_observations: Dict[str, HostTcpObservation] = {}
    for ip in current_hosts:
        _checkpoint(should_stop)
        if ip in ping_hosts:
            # ordinary scan, same call as before T23-B
            ports = _get_open_ports(ip, should_stop=should_stop)
        else:
            # ARP-only host: -Pn
            ports = _get_open_ports(ip, skip_host_discovery=True, should_stop=should_stop)
        tcp_observations[ip] = HostTcpObservation(ip=ip, ports=ports)
    services_degraded = any(obs.ports is None for obs in tcp_observations.values())

    candidates: List[NetworkChange] = []
    for ip in current_hosts:
        if ip in baseline or ip in known:
            continue
        observed = tcp_observations[ip]
        candidates.append(NetworkChange(
            change_type="new_host",
            asset_ip=ip,
            detail="new host detected",
            evidence=f"Host {ip} responded to ping but is not in the baseline or the known hosts.",
            initial_ports=observed.ports,
            initial_ports_known=observed.ports is not None,
        ))

    for ip in current_hosts:
        entry = baseline.get(ip)
        if entry is None:
            continue
        result = arp_results.get(ip)
        if result is not None:
            current_mac = (
                result.mac
                if result.status is ArpProbeStatus.PRESENT and result.mac
                else ""
            )
        else:
            current_mac = _get_arp_mac(ip)
        if current_mac and entry.mac and current_mac != entry.mac.lower():
            candidates.append(NetworkChange(
                change_type="mac_change",
                asset_ip=ip,
                detail=f"mac changed from {entry.mac} to {current_mac}",
                evidence=(
                    f"Active ARP probe shows {ip} → {current_mac}. "
                    f"Baseline MAC was {entry.mac}."
                ),
            ))

    observations = CycleObservations(
        current_hosts=current_hosts,
        ping_hosts=ping_hosts,
        host_arp_status=host_arp_status,
        tcp_observations=tcp_observations,
        candidate_changes=candidates,
        ping_failed=ping_failed,
        services_degraded=services_degraded,
    )

    if ping_failed:
        raise ScanDegradedError(
            "Ping scan failed; known hosts were partially checked with targeted ARP.",
            observations,
        )
    if services_degraded:
        raise ScanDegradedError(
            "Service scan failed for at least one present host.",
            observations,
        )
    return observations


def _checkpoint(should_stop: Optional[Callable[[], bool]]) -> None:
    """Raise ScanInterrupted when a stop was requested (between two probes)."""
    if should_stop is not None and should_stop():
        raise ScanInterrupted("stop requested during the Sentinel cycle")


def _arp_targets(
    baseline: Dict[str, BaselineEntry],
    known: Iterable[str],
    ping_hosts: List[str],
) -> List[str]:
    """Baseline then known IPs not seen by ping, without duplicates."""
    seen: List[str] = []
    for ip in list(baseline) + sorted(known):
        if ip in ping_hosts or ip in seen:
            continue
        seen.append(ip)
    return seen


def _get_active_hosts(
    target_network: str,
    should_stop: Optional[Callable[[], bool]] = None,
) -> Optional[List[str]]:
    """Run a lightweight ping scan and return active IPs, or None on failure.

    ScanInterrupted is a BaseException and is deliberately not caught here.
    """
    try:
        from recon.device_fingerprint import _run_nmap_ping, _parse_active_hosts
        xml = _run_nmap_ping(target_network, should_stop=should_stop)
        if xml is None:
            return None
        return _parse_active_hosts(xml)
    except Exception:
        return None


def _get_open_ports(
    ip: str,
    skip_host_discovery: bool = False,
    should_stop: Optional[Callable[[], bool]] = None,
) -> Optional[List[int]]:
    """Open TCP ports of a proven complete scan; None means the state is unknown.

    skip_host_discovery adds -Pn for hosts that were found by ARP but not by ping.
    ScanInterrupted (BaseException) is not caught: an interruption is not an
    unknown state.
    """
    try:
        from detect.tcp_scan import _run_nmap_tcp, parse_sentinel_open_ports
        xml = _run_nmap_tcp(
            ip, "normal", SENTINEL_TCP_PORTS,
            strict=True, skip_host_discovery=skip_host_discovery,
            should_stop=should_stop,
        )
        return parse_sentinel_open_ports(xml, ip, SENTINEL_TCP_PORTS)
    except Exception:
        return None


def _get_arp_mac(ip: str) -> str:
    """Return a MAC only when an active targeted ARP probe responds."""
    result = arp_probe(ip)
    if result.status is ArpProbeStatus.PRESENT and result.mac:
        return result.mac
    return ""
