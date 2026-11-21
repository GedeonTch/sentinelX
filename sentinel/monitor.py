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

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Set

from sentinel.arp_probe import ArpProbeResult, ArpProbeStatus, arp_probe
from core.process_control import ScanInterrupted
from sentinel.baseline import SENTINEL_TCP_PORTS, BaselineEntry, NetworkIdentity
from detect.tcp_scan import PortState as TcpPortState  # A1 TCP-01
from detect.tcp_scan import (  # A1 TCP-02
    _expand_port_spec,
    _parse_host_tcp_states,
    _run_nmap_tcp as _tcp_run_nmap,
    parse_sentinel_open_ports,
)


class ScanFailedError(Exception):
    """No exploitable observation: ping failed and no ARP probe gave PRESENT or NOT_OBSERVED."""


@dataclass
class HostTcpObservation:
    """TCP state of one host for this cycle.

    ports: None = unknown (scan incomplete or not performed),
           []   = complete scan, no open port,
           [..] = complete scan, these ports are open.

    states: per-port PortState dict from TCP-01 (None when unavailable).
            Present only when the scan is COMPLETE; used by TCP-02 to
            distinguish CLOSED from FILTERED in _compute_port_transitions.
    """

    ip: str
    ports: Optional[List[int]]
    states: Optional[Dict[int, TcpPortState]] = None  # A1 TCP-02


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
    # Recovery metadata is transient: a deferred-host initialization event may
    # already have been committed atomically with its baseline before the
    # normal event pipeline reaches this change.
    event_id: Optional[str] = None
    event_timestamp: Optional[str] = None
    event_pre_persisted: bool = False


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
            tcp_observations[ip] = _get_host_tcp_observation(ip, should_stop=should_stop)
        else:
            # ARP-only host: -Pn
            tcp_observations[ip] = _get_host_tcp_observation(
                ip, skip_host_discovery=True, should_stop=should_stop)
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


def _get_host_tcp_observation(
    ip: str,
    skip_host_discovery: bool = False,
    should_stop: Optional[Callable[[], bool]] = None,
) -> HostTcpObservation:
    """Run exactly ONE TCP scan and return a validated HostTcpObservation.

    This is the primary Sentinel Monitor path (A1/TCP-02). It calls _run_nmap_tcp
    exactly once, then applies ``parse_sentinel_open_ports`` — the same complete
    acceptance gate used by baseline learning. That gate proves the run finished,
    the host is up and not timed out, the XML has one host with the requested
    address, the planned port set and <scaninfo services> match SENTINEL_TCP_PORTS,
    and every planned port is attributed exactly once.

    Only after that acceptance are per-port states parsed with
    ``_parse_host_tcp_states``. Any failure (timeout, missing tool, malformed or
    inconsistent XML, wrong address, etc.) returns HostTcpObservation(ip=ip,
    ports=None) — INCOMPLETE, never an empty observation, no silent fallback.
    """
    try:
        xml = _tcp_run_nmap(
            ip, "normal", SENTINEL_TCP_PORTS,
            strict=True, skip_host_discovery=skip_host_discovery,
            should_stop=should_stop,
        )
        if not xml:
            return HostTcpObservation(ip=ip, ports=None)

        # Authoritative acceptance gate shared with baseline learning: the same
        # validation and the same refusals, including exact scaninfo services.
        ports = parse_sentinel_open_ports(xml, ip, SENTINEL_TCP_PORTS)
        if ports is None:
            return HostTcpObservation(ip=ip, ports=None)

        expected = _expand_port_spec(SENTINEL_TCP_PORTS)
        if expected is None:
            return HostTcpObservation(ip=ip, ports=None)
        root = ET.fromstring(xml)
        hosts = root.findall("host")
        if len(hosts) != 1:
            return HostTcpObservation(ip=ip, ports=None)
        obs = _parse_host_tcp_states(hosts[0], expected)
        if obs.status != "COMPLETE" or obs.ports != ports:
            # The detailed parse must also prove a complete observation.
            return HostTcpObservation(ip=ip, ports=None)
        return HostTcpObservation(ip=ip, ports=obs.ports, states=obs.states)
    except Exception:
        # Any error → INCOMPLETE; never fall back to a previous scan result
        return HostTcpObservation(ip=ip, ports=None)

def _get_open_ports(
    ip: str,
    skip_host_discovery: bool = False,
    should_stop: Optional[Callable[[], bool]] = None,
) -> Optional[List[int]]:
    """Open TCP ports of a proven complete scan; None means the state is unknown.

    Compatibility wrapper: delegates to _get_host_tcp_observation and returns
    only the .ports property. This function is kept for callers that still use
    the binary ports-list contract and for test compatibility.
    """
    obs = _get_host_tcp_observation(
        ip, skip_host_discovery=skip_host_discovery, should_stop=should_stop,
    )
    return obs.ports

def _get_arp_mac(ip: str) -> str:
    """Return a MAC only when an active targeted ARP probe responds."""
    result = arp_probe(ip)
    if result.status is ArpProbeStatus.PRESENT and result.mac:
        return result.mac
    return ""
