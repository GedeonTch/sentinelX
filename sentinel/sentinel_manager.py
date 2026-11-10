"""
sentinel/sentinel_manager.py — Sentinel lifecycle orchestration

Role: Orchestrate start / status / stop for the Sentinel surveillance loop.
      Called by cli.py — this is the only file cli.py should import from sentinel/.

States:
    active   — surveillance loop running, checks within expected interval
    degraded — loop running but no successful check for > 2 × interval_seconds
    inactive — Sentinel stopped or never started

Spec rules enforced:
    - Confirmation (y/n) before initial scan (active network traffic)
    - Baseline reused if identity matches; relearned only if missing or --relearn
    - --relearn is atomic: new baseline learned first, old deleted after success
    - Ctrl+C / stop: sentinel_state = "inactive", baseline preserved
    - last_check_time updated ONLY on successful check
    - Notification quotas are per host/network and recovered from event metadata
    - MAC="" never matches a baseline with known MAC

Rules enforced here:
    - ZERO import sqlite3
    - ZERO print() — display via core/logger.py
    - ZERO risk_score calculation
"""

from __future__ import annotations

import datetime
import ipaddress
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from datetime import timezone
from typing import Dict, List, Optional, Set

import typer

from core import database as _database
from core.database import (
    SentinelStorageError,
    init_db,
    init_sentinel_db,
    save_session,
    list_sentinel_network_ids,
    sentinel_count_unresolved_events,
    sentinel_get_state,
    sentinel_identity_machine_counts,
    sentinel_has_conflicting_baseline,
    sentinel_update_state,
    close_session,
)
from core.logger import display
from sentinel.alerting import AlertCounter, EventStamp, process_changes
from sentinel.arp_probe import ArpProbeStatus
from sentinel.baseline import (
    BaselineEntry,
    NetworkIdentity,
    baseline_exists,
    compute_network_id,
    detect_network_identity,
    get_baseline,
    learn_baseline,
)
from sentinel.monitor import (
    CycleObservations,
    NetworkChange,
    ScanDegradedError,
    ScanFailedError,
    check_network,
)
from sentinel.whitelist import load_whitelist
from sentinel.monitor_view import MonitorView
from core.process_control import ScanInterrupted
from sentinel.lifecycle import Owner, LifecycleError, network_lock, request_stop, DEFAULT_STOP_TIMEOUT


# ---------------------------------------------------------------------------
# Default interval (seconds) — overridable via config.yaml
# ---------------------------------------------------------------------------

_DEFAULT_INTERVAL = 60


def _load_interval() -> int:
    """Read sentinel.interval_seconds from config.yaml, fallback to default."""
    try:
        import yaml
        from pathlib import Path
        cfg_path = Path(__file__).parent.parent / "config.yaml"
        if cfg_path.exists():
            with open(cfg_path) as f:
                data = yaml.safe_load(f) or {}
            return int(data.get("sentinel", {}).get("interval_seconds", _DEFAULT_INTERVAL))
    except Exception:
        pass
    return _DEFAULT_INTERVAL


# ---------------------------------------------------------------------------
# start
# ---------------------------------------------------------------------------

def start(
    target_network: str,
    session_id: Optional[str] = None,
    force_relearn: bool = False,
) -> None:
    """Start Sentinel surveillance on a target network.

    Separates three identities:
      - network_id     : stable hash of NetworkIdentity — used for baseline DB
      - run_session_id : unique per start() call — used for session tracking
      - identity       : NetworkIdentity triplet (CIDR + gateway IP + MAC)

    The baseline persists in ~/.netlab/sentinel/<network_id>.db regardless
    of how many times Sentinel is started or stopped.

    Args:
        target_network: CIDR to monitor (e.g. "192.168.1.0/24").
        session_id:     Optional override for run session ID.
        force_relearn:  Replace baseline for current identity if it exists.
    """
    interval = _load_interval()

    # Step 1 — detect network identity and compute stable network_id
    display(f"[cyan]Detecting network identity for {target_network}...[/cyan]")
    identity = detect_network_identity(target_network)
    network_id = compute_network_id(identity)
    display(f"[dim]Identity: {identity}[/dim]")
    display(f"[dim]Network ID: {network_id}[/dim]")

    if not identity.gateway_ip:
        display(
            "[yellow]Warning: could not determine gateway IP. "
            "Network identity is partial.[/yellow]"
        )

    # Acquire before any network/session data mutation. Held through finalization.
    with network_lock(network_id):
        run_session_id = session_id or f"sentinel-run-{uuid.uuid4().hex}"
        with _database.reserve_sentinel_session_file(run_session_id):
            owner = None
            session_created = False
            outcome = "failed"
            fatal_error = None
            try:
                init_sentinel_db(network_id)
                owner = Owner(network_id, run_session_id)
                init_db(run_session_id)
                save_session(run_session_id, target=target_network, profile="sentinel")
                session_created = True
                outcome = _start_owned(target_network, network_id, run_session_id,
                                       identity, interval, force_relearn, owner)
            except KeyboardInterrupt:
                if not session_created:
                    # No confirmed session: this is an interrupted startup, not
                    # a successful stop. Keep outcome failed for any registered
                    # owner and preserve the interrupt through cleanup failures.
                    fatal_error = "KeyboardInterrupt: preparation interrupted"
                    raise
                outcome = "partial"
            except Exception as exc:
                fatal_error = type(exc).__name__ + ": surveillance failed"
                raise
            finally:
                errors = []
                if session_created:
                    try:
                        close_session(run_session_id, status=outcome)
                    except Exception as exc:
                        errors.append(type(exc).__name__ + ": session finalization failed")
                else:
                    try:
                        # save_session may have committed before its return was
                        # interrupted. Inspect only this attempt's reserved DB;
                        # close a real matching row without inventing a session.
                        _database.sentinel_fail_unconfirmed_session(run_session_id)
                    except Exception as exc:
                        errors.append(type(exc).__name__ + ": unconfirmed session finalization failed")
                try:
                    if owner is None:
                        # We hold the network lock, but have no registered owner
                        # to acknowledge. Reconcile only an existing state row.
                        _database.sentinel_reconcile_failed_start(network_id)
                    else:
                        _graceful_stop(network_id)
                except Exception as exc:
                    errors.append(type(exc).__name__ + ": network finalization failed")
                if owner is not None:
                    try:
                        owner.finish("finalization_failed" if errors else
                                     ("failed" if outcome == "failed" else "completed"),
                                     "; ".join(errors) or fatal_error)
                    except Exception as exc:
                        errors.append(type(exc).__name__ + ": control finalization failed")
                if errors:
                    diagnostic = "Arrêt non finalisé proprement : " + "; ".join(errors)
                    if fatal_error is not None:
                        # Preserve the original exception being propagated. Only
                        # safe operation/type information describes cleanup failure.
                        display(f"[red]{diagnostic}[/red]")
                    else:
                        raise LifecycleError(diagnostic)
            if outcome == "failed":
                raise LifecycleError("Sentinel initialization failed")


def _start_owned(target_network, network_id, run_session_id, identity,
                 interval, force_relearn, owner):
    # Step 4 — check for conflicting baseline (same CIDR, different gateway MAC)
    if not force_relearn and sentinel_has_conflicting_baseline(
        network_id, target_network, identity.gateway_ip, identity.gateway_mac
    ):
        display(
            f"[yellow][!] Identité réseau non reconnue pour {target_network}.\n"
            f"    Une baseline existe pour ce CIDR mais avec une identité différente.\n"
            f"    Aucune baseline ne sera chargée automatiquement.[/yellow]"
        )
        confirmed = typer.confirm(
            "Apprendre une nouvelle baseline pour ce réseau ?",
            default=False,
        )
        if not confirmed:
            display("[yellow]Sentinel annulé.[/yellow]")
            return "partial"
        force_relearn = True

    # Step 5 — learn baseline if missing or force_relearn
    if not baseline_exists(network_id, identity) or force_relearn:
        confirmed = typer.confirm(
            f"[sentinel] Démarrer la surveillance de {target_network} ?\n"
            f"  Un scan initial sera effectué pour établir la baseline.",
            default=False,
        )
        if not confirmed:
            display("[yellow]Sentinel annulé.[/yellow]")
            return "partial"

        ok = learn_baseline(
            target_network=target_network,
            network_id=network_id,
            identity=identity,
            force_relearn=force_relearn,
        )
        if not ok:
            display("[red]Échec de l'apprentissage de la baseline. Sentinel non démarré.[/red]")
            return "failed"
    else:
        display("[green]Baseline existante trouvée — surveillance démarrée.[/green]")

    # Step 6 — rebuild transition state from the stored history (§9.8, B1) before any write
    state = _rebuild_transition_state(network_id, get_baseline(network_id, identity) or {})
    if state is None:
        display("[red]Lecture de l'historique Sentinel impossible. Sentinel non démarré.[/red]")
        return "failed"
    state.target_network = target_network

    # Step 7 — record initial state in sentinel DB
    sentinel_update_state(
        network_id=network_id,
        sentinel_status="active",
        target_network=target_network,
        gateway_ip=identity.gateway_ip,
        gateway_mac=identity.gateway_mac,
    )

    whitelist = load_whitelist()
    counter = AlertCounter()
    counter.bind(network_id)
    with MonitorView(target_network, interval, counter, session_id=run_session_id) as view:
        counter.view = view
        _run_loop(
            target_network=target_network, network_id=network_id,
            run_session_id=run_session_id, identity=identity, interval=interval,
            whitelist=whitelist, counter=counter, owner=owner, state=state,
        )
    return "completed"


@dataclass
class NetworkState:
    """In-memory transition state of one network (§9.15.2). Rebuilt from the stored events."""

    stamp: EventStamp
    known_hosts: Set[str]
    initial_ports: Dict[str, Optional[List[int]]]
    ports_initialized: Dict[str, bool]
    open_ports: Dict[str, Set[int]]
    port_absent_count: Dict[str, Dict[int, int]]
    notified_port_not_open: Dict[str, Set[int]]
    host_absent_count: Dict[str, int]
    host_not_observed: Set[str]
    scan_degraded_active: bool = False    # never restored (§9.8)
    # Monitored CIDR, needed by the L2 classification. Set by _start_owned.
    target_network: str = ""


def _rebuild_transition_state(network_id: str, baseline: Dict[str, BaselineEntry]) -> Optional[NetworkState]:
    """Rebuild the transition state from the stored history (§9.8).

    Baseline hosts start initialized with their baseline ports (option b, decision of
    2026-11-08). Stored events are then replayed chronologically; the stamp is restored
    from the same snapshot (B1). Returns None when the snapshot cannot be read.
    """
    try:
        events = _database.sentinel_network_snapshot(network_id)["events"]
    except Exception:
        return None  # any read failure stops the start explicitly (§9.8)

    state = NetworkState(
        stamp=EventStamp.restore(network_id, events),
        known_hosts=set(baseline),
        initial_ports={},
        ports_initialized={},
        open_ports={},
        port_absent_count={},
        notified_port_not_open={},
        host_absent_count={},
        host_not_observed=set(),
    )
    for ip, entry in baseline.items():
        ports = list(entry.ports or [])
        state.ports_initialized[ip] = True
        state.initial_ports[ip] = ports
        state.open_ports[ip] = set(ports)

    for event in events:
        kind = event.get("type")
        details = event.get("details") or {}
        ip = details.get("ip")
        port = details.get("port")
        if kind == "new_host" and ip:
            state.known_hosts.add(ip)
            if details.get("initial_ports_known"):
                ports = list(details.get("initial_ports") or [])
                state.ports_initialized[ip] = True
                state.initial_ports[ip] = ports
                state.open_ports[ip] = set(ports)
            else:
                state.ports_initialized[ip] = False
                state.initial_ports[ip] = None
                state.open_ports[ip] = set()
        elif kind == "host_ports_initialized" and ip:
            ports = list(details.get("initial_ports") or [])
            state.ports_initialized[ip] = True
            state.initial_ports[ip] = ports
            state.open_ports[ip] = set(ports)
        elif kind == "new_port" and ip and port is not None:
            state.open_ports.setdefault(ip, set()).add(port)
            state.notified_port_not_open.get(ip, set()).discard(port)
        elif kind == "port_not_open" and ip and port is not None:
            state.open_ports.setdefault(ip, set()).discard(port)
            state.notified_port_not_open.setdefault(ip, set()).add(port)
        elif kind == "host_not_observed" and ip:
            state.host_not_observed.add(ip)
        elif kind == "host_recovered" and ip:
            state.host_not_observed.discard(ip)
        # scan_degraded and mac_change are not restored: no transition depends on them.
    return state


def _route_output(ip: str) -> Optional[str]:
    """Output of `ip route get <ip>` (local routing table only, no packet sent)."""
    try:
        result = subprocess.run(["ip", "route", "get", ip], capture_output=True, text=True,
                                timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def _classify_host(ip: str, target_network: str) -> str:
    """l2_direct | routed | unknown | out_of_scope (§9.7)."""
    try:
        address = ipaddress.ip_address(ip)
        network = ipaddress.ip_network(target_network, strict=False)
    except ValueError:
        return "out_of_scope"
    if address not in network:
        return "out_of_scope"
    output = _route_output(ip)
    if not output:
        return "unknown"
    tokens = output.split()
    if "via" in tokens:
        return "routed"
    if "dev" not in tokens or "src" not in tokens:
        return "unknown"
    try:
        source = ipaddress.ip_address(tokens[tokens.index("src") + 1])
    except (ValueError, IndexError):
        return "unknown"
    # Direct on the monitored segment: no gateway and the local source is on the same CIDR.
    return "l2_direct" if source in network else "unknown"


def _is_l2_direct(ip: str, target_network: str) -> bool:
    return _classify_host(ip, target_network) == "l2_direct"


def _normalize_and_filter(observations: CycleObservations, state: NetworkState) -> List[NetworkChange]:
    """Four ordered steps (§9.5). Updates the memory state before anything is persisted."""
    changes: List[NetworkChange] = []

    # Step 1 — candidates from the monitor: new_host (+ host_ports_initialized) and mac_change.
    for change in observations.candidate_changes:
        if change.change_type != "new_host":
            changes.append(change)
            continue
        ip = change.asset_ip
        if ip in state.known_hosts:
            continue  # anti-répétition: already known
        state.known_hosts.add(ip)
        changes.append(change)
        if change.initial_ports_known:
            ports = list(change.initial_ports or [])
            state.ports_initialized[ip] = True
            state.initial_ports[ip] = ports
            state.open_ports[ip] = set(ports)
            changes.append(NetworkChange(
                change_type="host_ports_initialized",
                asset_ip=ip,
                detail="ports initialized",
                evidence=f"First complete TCP scan of {ip}: {len(ports)} open port(s).",
                initial_ports=ports,
                initial_ports_known=True,
            ))
        else:
            state.ports_initialized[ip] = False
            state.initial_ports[ip] = None
            state.open_ports[ip] = set()

    # Step 2 — shared initialization loop: known hosts whose first complete scan is now available.
    for ip in observations.current_hosts:
        observed = observations.tcp_observations.get(ip)
        if ip not in state.known_hosts or state.ports_initialized.get(ip, False):
            continue
        if observed is None or observed.ports is None:
            continue
        ports = list(observed.ports)
        state.ports_initialized[ip] = True
        state.initial_ports[ip] = ports
        state.open_ports[ip] = set(ports)
        changes.append(NetworkChange(
            change_type="host_ports_initialized",
            asset_ip=ip,
            detail="ports initialized",
            evidence=f"First complete TCP scan of {ip}: {len(ports)} open port(s).",
            initial_ports=ports,
            initial_ports_known=True,
        ))

    changes.extend(_compute_port_transitions(observations, state))
    changes.extend(_compute_host_transitions(observations, state))
    return changes


def _compute_port_transitions(observations: CycleObservations, state: NetworkState) -> List[NetworkChange]:
    """Unified new_port / port_not_open (§9.5 step 3, §9.6)."""
    changes: List[NetworkChange] = []
    for ip in observations.current_hosts:
        if not state.ports_initialized.get(ip, False):
            continue
        observed = observations.tcp_observations.get(ip)
        counts = state.port_absent_count.setdefault(ip, {})
        if observed is None or observed.ports is None:
            counts.clear()  # unknown state: no conclusion, no counter kept (§9.6)
            continue
        present = set(observed.ports)
        known_open = state.open_ports.setdefault(ip, set())

        for port in sorted(present):
            counts.pop(port, None)
            if port not in known_open:
                known_open.add(port)  # first opening or reopening
                state.notified_port_not_open.get(ip, set()).discard(port)
                changes.append(NetworkChange(
                    change_type="new_port",
                    asset_ip=ip,
                    detail=f"port {port} opened",
                    evidence=f"Port {port}/tcp open on {ip} in a complete TCP scan.",
                    port=port,
                ))

        for port in sorted(known_open - present):
            count = counts.get(port, 0) + 1
            counts[port] = count
            if count < 2:
                continue
            counts[port] = 0  # always reset after two complete observations
            known_open.discard(port)  # a later reappearance is a new opening
            notified = state.notified_port_not_open.setdefault(ip, set())
            if port not in notified:
                changes.append(NetworkChange(
                    change_type="port_not_open",
                    asset_ip=ip,
                    detail=f"port {port} not open",
                    evidence=f"Port {port}/tcp absent from two complete TCP scans of {ip}.",
                    port=port,
                ))
                notified.add(port)
    return changes


def _compute_host_transitions(observations: CycleObservations, state: NetworkState) -> List[NetworkChange]:
    """host_not_observed (two NOT_OBSERVED ARP answers, L2 direct only) and host_recovered."""
    changes: List[NetworkChange] = []
    current = set(observations.current_hosts)

    for ip in sorted(current):
        state.host_absent_count.pop(ip, None)
        if ip in state.host_not_observed:
            state.host_not_observed.discard(ip)
            changes.append(NetworkChange(
                change_type="host_recovered",
                asset_ip=ip,
                detail="host recovered",
                evidence=f"Host {ip} answered again after an absence (ping or targeted ARP).",
            ))

    for ip in sorted(state.known_hosts - current):
        if observations.host_arp_status.get(ip) is not ArpProbeStatus.NOT_OBSERVED:
            state.host_absent_count.pop(ip, None)  # ERROR or no probe: no conclusion, reset
            continue
        if not _is_l2_direct(ip, state.target_network):
            state.host_absent_count.pop(ip, None)  # routed or unknown: never an absence on ARP alone
            continue
        count = state.host_absent_count.get(ip, 0) + 1
        state.host_absent_count[ip] = count
        if count >= 2 and ip not in state.host_not_observed:
            state.host_not_observed.add(ip)
            changes.append(NetworkChange(
                change_type="host_not_observed",
                asset_ip=ip,
                detail="host not observed",
                evidence=f"Host {ip} not answered to targeted ARP in two reliable cycles.",
            ))
    return changes


def _scan_degraded_change(target_network: str, reason: str) -> NetworkChange:
    """Network-scope observation (B3): asset_ip is the target network, never a host."""
    return NetworkChange(
        change_type="scan_degraded",
        asset_ip=target_network,
        detail="scan degraded",
        evidence=reason,
    )


def _run_loop(
    target_network: str,
    network_id: str,
    run_session_id: str,
    identity: NetworkIdentity,
    interval: int,
    whitelist,
    counter: AlertCounter,
    owner: Owner,
    state: NetworkState,
) -> None:
    """Cooperative stop: bounded polling when idle; a stop during a check interrupts it.

    An interrupted check is abandoned as a whole: no observation, transition,
    counter change, last_check update or scan_degraded event is produced by it.
    The loop then returns normally, so the common finalizer records a completed
    stop.
    """
    while not owner.wait(interval):
        if not owner.admit_cycle():
            return
        try:
            counter.phase('contrôle')
            _do_check(
                target_network=target_network,
                network_id=network_id,
                run_session_id=run_session_id,
                identity=identity,
                interval=interval,
                whitelist=whitelist,
                counter=counter,
                state=state,
                should_stop=owner.requested,
            )
        except ScanInterrupted:
            counter.phase('arrêt')
            return
        finally:
            owner.end_cycle()


def _do_check(
    target_network: str,
    network_id: str,
    run_session_id: str,
    identity: NetworkIdentity,
    interval: int,
    whitelist,
    counter: AlertCounter,
    state: NetworkState,
    should_stop=None,
) -> None:
    """Execute one surveillance check cycle using the sentinel DB.

    should_stop: None runs the check to completion; a callable returning True
    interrupts it (ScanInterrupted propagates to the caller, nothing is written).
    """
    baseline = get_baseline(network_id, identity)
    if not baseline:
        counter.phase('erreur')
        display("[yellow]Baseline vide — impossible de comparer.[/yellow]")
        return

    try:
        try:
            observations = check_network(
                target_network=target_network,
                session_id=run_session_id,
                identity=identity,
                baseline=baseline,
                known_hosts=set(state.known_hosts),
                should_stop=should_stop,
            )
            partial = None
        except ScanDegradedError as exc:
            observations, partial = exc.observations, exc
        except ScanFailedError as exc:
            # No exploitable observation: no host or port conclusion, counters reset (§9.14).
            display(f"[yellow]Monitor: {exc}[/yellow]")
            state.host_absent_count.clear()
            state.port_absent_count.clear()
            changes = []
            if not state.scan_degraded_active:
                changes.append(_scan_degraded_change(target_network, str(exc)))
            if changes:
                process_changes(
                    changes=changes,
                    session_id=run_session_id,
                    network_id=network_id,
                    whitelist=whitelist,
                    counter=counter,
                    stamp=state.stamp,
                )
            state.scan_degraded_active = True
            sentinel_update_state(network_id=network_id, sentinel_status="degraded")
            counter.phase("erreur", finished=True)
            return

        changes = _normalize_and_filter(observations, state)
        if partial is not None and not state.scan_degraded_active:
            # One scan_degraded per episode, after the exploitable transitions of this cycle.
            changes.append(_scan_degraded_change(target_network, str(partial)))
        if changes:
            process_changes(
                changes=changes,
                session_id=run_session_id,
                network_id=network_id,
                whitelist=whitelist,
                counter=counter,
                stamp=state.stamp,
            )
        if partial is not None:
            # Partial check: changes above are persisted, last_check_time is not updated
            # because global discovery was incomplete.
            state.scan_degraded_active = True
            display(f"[yellow]Monitor: {partial}[/yellow]")
            sentinel_update_state(network_id=network_id, sentinel_status="degraded")
            counter.phase("dégradé", finished=True)
            return

        # D1: the check is recorded only after its changes were persisted. A
        # storage failure above raises before this point, so last_check_time
        # is not advanced and the cycle is not reported as successful.
        state.scan_degraded_active = False
        now = datetime.datetime.now(timezone.utc).isoformat()
        sentinel_update_state(
            network_id=network_id,
            sentinel_status="active",
            last_check_time=now,
        )
        counter.phase('attente', finished=True)
    except Exception as exc:
        try:
            counter.phase("erreur")
        except Exception:
            pass  # rendering must not replace the original failure
        # Unexpected failures leave through the common owner finalizer.
        if isinstance(exc, SentinelStorageError):
            # Safe classified message only; the native SQLite error stays chained.
            display(f"[yellow]Monitor: {exc} ; arrêt de la surveillance.[/yellow]")
        else:
            display(f"[yellow]Monitor check failed ({type(exc).__name__}); arrêt de la surveillance.[/yellow]")
        raise


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

def _resolve_status_network_id(network_id: Optional[str] = None) -> str:
    """Resolve the network context for the network-oriented status command."""
    if network_id:
        if network_id not in list_sentinel_network_ids():
            raise ValueError(f"Unknown Sentinel network '{network_id}'.")
        return network_id

    known = list_sentinel_network_ids()
    if not known:
        raise ValueError("No known Sentinel network is available.")
    if len(known) > 1:
        raise ValueError(
            "Multiple Sentinel networks are available; use --network <network_id>."
        )
    return known[0]


def _state_identity(state: dict) -> Optional[tuple]:
    """Return the NetworkIdentity recorded in the sentinel state, or None if incomplete.

    The state row is the only record of the identity this DB serves. gateway_ip
    and gateway_mac may legitimately be "" (route or ARP unavailable), so only
    NULL means "never recorded". target_network must be a non-empty CIDR.
    """
    target = state.get("target_network")
    gateway_ip = state.get("gateway_ip")
    gateway_mac = state.get("gateway_mac")
    if not target or gateway_ip is None or gateway_mac is None:
        return None
    return (target, gateway_ip, gateway_mac)


def status(network_id: Optional[str] = None) -> dict:
    """Return Sentinel status for a network, never for an audit session."""
    network_id = _resolve_status_network_id(network_id)
    interval = _load_interval()
    state = sentinel_get_state(network_id)
    if not state:
        raise ValueError(f"No Sentinel state exists for network '{network_id}'.")

    sentinel_state = state.get("sentinel_status", "inactive")
    last_check = state.get("last_check_time")
    target_network = state.get("target_network", "")
    gateway_ip = state.get("gateway_ip", "")
    gateway_mac = state.get("gateway_mac", "")

    display_state = _compute_display_state(sentinel_state, last_check, interval)
    # Machines are the hosts of this identity's baseline (spec §8: actives/connues).
    # An incomplete identity or an unreadable count is unavailable (None), never 0.
    identity = _state_identity(state)
    known_hosts = active_hosts = None
    if identity is not None:
        try:
            known_hosts, active_hosts = sentinel_identity_machine_counts(network_id, *identity)
        except Exception:
            known_hosts = active_hosts = None

    try:
        unresolved = sentinel_count_unresolved_events(network_id)
    except Exception:
        # D2: an unreadable count is unavailable (None), never a false zero.
        unresolved = None

    seconds_since = None
    seconds_until = None
    if last_check:
        try:
            last_dt = datetime.datetime.fromisoformat(last_check)
            elapsed = (datetime.datetime.now(timezone.utc) - last_dt).total_seconds()
            seconds_since = int(elapsed)
            seconds_until = max(0, interval - seconds_since)
        except Exception:
            pass

    return {
        "network_id": network_id,
        "sentinel_state": sentinel_state,
        "display_state": display_state,
        "target_network": target_network,
        "gateway_ip": gateway_ip,
        "gateway_mac": gateway_mac,
        "last_check_time": last_check,
        "seconds_since_check": seconds_since,
        "seconds_until_check": seconds_until,
        "active_hosts": active_hosts,
        "known_hosts": known_hosts,
        "unresolved_alerts": unresolved,
    }


def display_status(network_id: Optional[str] = None) -> None:
    """Display compact Sentinel status for a resolved network."""
    s = status(network_id)
    state = s["display_state"]

    state_icon = {"ACTIF": "[●]", "DÉGRADÉ": "[!]", "INACTIF": "[○]"}.get(state, "[?]")
    state_color = {"ACTIF": "green", "DÉGRADÉ": "yellow", "INACTIF": "dim"}.get(state, "white")

    network = s.get("target_network") or "—"
    if s.get("known_hosts") is None or s.get("active_hosts") is None:
        machines = "machines indisponibles"
    else:
        machines = f"{s['active_hosts']}/{s['known_hosts']} machines"
    unresolved = s.get("unresolved_alerts")
    alerts = "indisponible" if unresolved is None else unresolved
    changes = "—"  # total changes requires session event count — omitted for compactness

    line1 = (
        f"[{state_color}]{state_icon} SENTINELX: {state} | "
        f"{network} | {machines} | alertes: {alerts}[/{state_color}]"
    )

    last = s.get("seconds_since_check")
    nxt = s.get("seconds_until_check")
    if last is not None and nxt is not None:
        line2 = f"[dim]    dernière vérif. {last}s | prochaine {nxt}s[/dim]"
    else:
        line2 = "[dim]    aucune vérification effectuée[/dim]"

    display(line1)
    display(line2)
    _display_hints(state.lower())


# ---------------------------------------------------------------------------
# stop
# ---------------------------------------------------------------------------

def stop(session_id: Optional[str] = None, *, network_id: Optional[str] = None,
         timeout: float = DEFAULT_STOP_TIMEOUT) -> None:
    """Request one owner's stop; success requires ack, free lock and OS exit."""
    request_stop(network_id=network_id, session_id=session_id, timeout=timeout)
    display("[○] Sentinel arrêté : finalisation et terminaison confirmées.")


def _graceful_stop(network_id: str) -> None:
    """Owner-only persistence; failures must propagate, never signal success."""
    sentinel_update_state(network_id, "inactive")


def _compute_display_state(
    sentinel_state: str,
    last_check: Optional[str],
    interval: int,
) -> str:
    """Compute the display state string from DB state and timing.

    Rules:
        inactive → INACTIF
        active/degraded + no last_check → DÉGRADÉ
        active + last_check within 2×interval → ACTIF
        active + last_check older than 2×interval → DÉGRADÉ

    Args:
        sentinel_state: Raw DB value.
        last_check:     ISO 8601 last successful check time or None.
        interval:       Surveillance interval in seconds.

    Returns:
        str: "ACTIF" | "DÉGRADÉ" | "INACTIF"
    """
    if sentinel_state == "inactive":
        return "INACTIF"
    if not last_check:
        return "DÉGRADÉ"
    try:
        last_dt = datetime.datetime.fromisoformat(last_check)
        elapsed = (datetime.datetime.now(timezone.utc) - last_dt).total_seconds()
        if elapsed > 2 * interval:
            return "DÉGRADÉ"
        return "ACTIF"
    except Exception:
        return "DÉGRADÉ"


def _has_conflicting_baseline(
    session_id: str,
    target_network: str,
    identity: NetworkIdentity,
) -> bool:
    """Return True if a baseline exists for this CIDR but with a different identity.

    Used to detect the case where two networks share the same CIDR but have
    different gateway MACs.

    Args:
        session_id:     Session identifier.
        target_network: CIDR string.
        identity:       Current detected NetworkIdentity.

    Returns:
        bool: True if conflict exists.
    """
    from core.database import get_connection

def _display_hints(state: str) -> None:
    """Display contextual command hints based on Sentinel state."""
    hints = {
        "active":   "› status  › history  › allow  › stop",
        "degraded": "› status  › history  › stop",
        "inactif":  "› sentinel start  › sentinel status",
        "inactive": "› sentinel start  › sentinel status",
    }
    hint = hints.get(state.lower(), "› sentinel help")
    display(f"[dim]{hint}[/dim]")
