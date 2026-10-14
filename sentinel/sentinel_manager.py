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
import time
import uuid
from datetime import timezone
from typing import Optional

import typer

from core import database as _database
from core.database import (
    init_db,
    init_sentinel_db,
    save_session,
    list_sentinel_network_ids,
    sentinel_count_unresolved_events,
    sentinel_get_assets,
    sentinel_get_state,
    sentinel_has_conflicting_baseline,
    sentinel_update_state,
    close_session,
)
from core.logger import display
from sentinel.alerting import AlertCounter, process_changes
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
    ScanDegradedError,
    ScanFailedError,
    check_network,
)
from sentinel.whitelist import load_whitelist
from sentinel.monitor_view import MonitorView
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

    # Step 6 — record initial state in sentinel DB
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
            whitelist=whitelist, counter=counter, owner=owner,
        )
    return "completed"


def _run_loop(
    target_network: str,
    network_id: str,
    run_session_id: str,
    identity: NetworkIdentity,
    interval: int,
    whitelist,
    counter: AlertCounter,
    owner: Owner,
) -> None:
    """Cooperative stop: bounded polling when idle, finish an in-flight check."""
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
            )
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
) -> None:
    """Execute one surveillance check cycle using the sentinel DB."""
    baseline = get_baseline(network_id, identity)
    if not baseline:
        counter.phase('erreur')
        display("[yellow]Baseline vide — impossible de comparer.[/yellow]")
        return

    try:
        changes = check_network(
            target_network=target_network,
            session_id=run_session_id,
            identity=identity,
            baseline=baseline,
        )
        now = datetime.datetime.now(timezone.utc).isoformat()
        sentinel_update_state(
            network_id=network_id,
            sentinel_status="active",
            last_check_time=now,
        )
        if changes:
            process_changes(
                changes=changes,
                session_id=run_session_id,
                network_id=network_id,
                whitelist=whitelist,
                counter=counter,
            )
        counter.phase('attente', finished=True)
    except ScanDegradedError as exc:
        # Partial check: process observed changes, but do not update
        # last_check_time because global discovery was incomplete.
        display(f"[yellow]Monitor: {exc}[/yellow]")
        if exc.changes:
            process_changes(
                changes=exc.changes,
                session_id=run_session_id,
                network_id=network_id,
                whitelist=whitelist,
                counter=counter,
            )
        sentinel_update_state(network_id=network_id, sentinel_status="degraded")
        counter.phase("dégradé", finished=True)
    except ScanFailedError as exc:
        # Ping and targeted ARP did not provide a usable host check.
        # Never update last_check_time and never infer host removal.
        display(f"[yellow]Monitor: {exc}[/yellow]")
        sentinel_update_state(network_id=network_id, sentinel_status="degraded")
        counter.phase("erreur", finished=True)
    except Exception as exc:
        try:
            counter.phase("erreur")
        except Exception:
            pass  # rendering must not replace the original failure
        # Unexpected failures leave through the common owner finalizer.
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
    assets = sentinel_get_assets(network_id)
    known_hosts = len(assets)
    active_hosts = sum(1 for a in assets if a.get("active", 1))

    try:
        unresolved = sentinel_count_unresolved_events(network_id)
    except Exception:
        unresolved = 0

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
    machines = f"{s.get('active_hosts', '?')}/{s.get('known_hosts', '?')} machines"
    alerts = s.get("unresolved_alerts", 0)
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
