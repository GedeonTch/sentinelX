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
    - AlertCounter resets at each start (session-local, never inherited)
    - MAC="" never matches a baseline with known MAC

Rules enforced here:
    - ZERO import sqlite3
    - ZERO print() — display via core/logger.py
    - ZERO risk_score calculation
"""

from __future__ import annotations

import datetime
import signal
import time
import uuid
from datetime import timezone
from typing import Optional

import typer

from core.database import (
    count_unresolved_events,
    get_assets,
    get_sentinel_state,
    init_db,
    save_session,
    update_sentinel_state,
)
from core.logger import display
from sentinel.alerting import AlertCounter, process_changes
from sentinel.baseline import (
    BaselineEntry,
    NetworkIdentity,
    baseline_exists,
    detect_network_identity,
    get_baseline,
    learn_baseline,
)
from sentinel.monitor import check_network
from sentinel.whitelist import load_whitelist


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

    Flow:
        1. Detect NetworkIdentity (CIDR + gateway IP + gateway MAC)
        2. Warn if identity doesn't match existing baseline
        3. Learn baseline if missing or force_relearn
        4. Enter surveillance loop (Ctrl+C to stop)

    Args:
        target_network: CIDR to monitor (e.g. "192.168.1.0/24").
        session_id:     Session ID. Auto-generated if None.
        force_relearn:  Replace baseline for current identity if it exists.
    """
    interval = _load_interval()
    session_id = session_id or f"sentinel-{uuid.uuid4().hex[:8]}"

    # Initialise DB for this session
    init_db(session_id)
    save_session(session_id, target=target_network, profile="sentinel")

    # Step 1 — detect network identity
    display(f"[cyan]Detecting network identity for {target_network}...[/cyan]")
    identity = detect_network_identity(target_network)
    display(f"[dim]Identity: {identity}[/dim]")

    if not identity.gateway_ip:
        display(
            "[yellow]Warning: could not determine gateway IP. "
            "Network identity is partial.[/yellow]"
        )

    # Step 2 — check for conflicting existing baseline
    if not force_relearn and _has_conflicting_baseline(session_id, target_network, identity):
        display(
            f"[yellow][!] Identité réseau non reconnue pour {target_network}.\n"
            f"    Une baseline existe pour ce CIDR mais avec une identité différente.\n"
            f"    Aucune baseline ne sera chargée automatiquement.[/yellow]"
        )
        confirmed = typer.confirm(
            f"Apprendre une nouvelle baseline pour ce réseau ?",
            default=False,
        )
        if not confirmed:
            display("[yellow]Sentinel annulé.[/yellow]")
            return
        force_relearn = True

    # Step 3 — learn baseline if needed
    if not baseline_exists(session_id, identity) or force_relearn:
        confirmed = typer.confirm(
            f"[sentinel] Démarrer la surveillance de {target_network} ?\n"
            f"  Un scan initial sera effectué pour établir la baseline.",
            default=False,
        )
        if not confirmed:
            display("[yellow]Sentinel annulé.[/yellow]")
            return

        ok = learn_baseline(
            target_network=target_network,
            session_id=session_id,
            identity=identity,
            force_relearn=force_relearn,
        )
        if not ok:
            display("[red]Échec de l'apprentissage de la baseline. Sentinel non démarré.[/red]")
            update_sentinel_state(session_id, "inactive")
            return
    else:
        display(f"[green]Baseline existante trouvée — surveillance démarrée.[/green]")

    # Step 4 — initialise state
    now = datetime.datetime.now(timezone.utc).isoformat()
    update_sentinel_state(
        session_id=session_id,
        sentinel_state="active",
        last_check_time=now,
        target_network=target_network,
        gateway_ip=identity.gateway_ip,
        gateway_mac=identity.gateway_mac,
    )

    whitelist = load_whitelist()
    counter = AlertCounter(max_per_hour=whitelist.sentinel_max_alerts_per_hour)

    display(
        f"\n[green][●] SENTINELX ACTIF | {target_network} | "
        f"intervalle {interval}s[/green]"
    )
    display("[dim]Ctrl+C pour arrêter. Baseline conservée à l'arrêt.[/dim]")
    _display_hints("active")

    # Step 5 — surveillance loop
    _run_loop(
        target_network=target_network,
        session_id=session_id,
        identity=identity,
        interval=interval,
        whitelist=whitelist,
        counter=counter,
    )


def _run_loop(
    target_network: str,
    session_id: str,
    identity: NetworkIdentity,
    interval: int,
    whitelist,
    counter: AlertCounter,
) -> None:
    """Run the surveillance loop until interrupted.

    Handles Ctrl+C gracefully — sets state to inactive, preserves baseline.
    """
    try:
        while True:
            time.sleep(interval)
            _do_check(
                target_network=target_network,
                session_id=session_id,
                identity=identity,
                interval=interval,
                whitelist=whitelist,
                counter=counter,
            )
    except KeyboardInterrupt:
        _graceful_stop(session_id)


def _do_check(
    target_network: str,
    session_id: str,
    identity: NetworkIdentity,
    interval: int,
    whitelist,
    counter: AlertCounter,
) -> None:
    """Execute one surveillance check cycle.

    Updates last_check_time only on success.
    Sets state to degraded if check fails, active on success.
    """
    baseline = get_baseline(session_id, identity)
    if not baseline:
        display("[yellow]Baseline vide — impossible de comparer.[/yellow]")
        return

    try:
        changes = check_network(
            target_network=target_network,
            session_id=session_id,
            identity=identity,
            baseline=baseline,
        )
        # Successful check — update last_check_time and state
        now = datetime.datetime.now(timezone.utc).isoformat()
        update_sentinel_state(
            session_id=session_id,
            sentinel_state="active",
            last_check_time=now,
        )

        if changes:
            process_changes(
                changes=changes,
                session_id=session_id,
                whitelist=whitelist,
                counter=counter,
            )

    except Exception as exc:
        # Failed check — do NOT update last_check_time
        display(f"[yellow]Monitor check failed: {exc}[/yellow]")
        # Check if degraded threshold exceeded
        state = get_sentinel_state(session_id)
        last_ok = state.get("last_check_time")
        if last_ok:
            elapsed = (
                datetime.datetime.now(timezone.utc)
                - datetime.datetime.fromisoformat(last_ok)
            ).total_seconds()
            if elapsed > 2 * interval:
                update_sentinel_state(session_id=session_id, sentinel_state="degraded")
                display("[yellow][!] SENTINELX: DÉGRADÉ — aucun check réussi depuis "
                        f"{int(elapsed)}s[/yellow]")


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

def status(session_id: str) -> dict:
    """Return current Sentinel status for a session.

    Computes the display state (active/degraded/inactive) from DB.
    Does not run a network check.

    Args:
        session_id: Session identifier.

    Returns:
        dict with keys: sentinel_state, display_state, target_network,
        gateway_ip, gateway_mac, last_check_time, active_hosts,
        known_hosts, unresolved_alerts.
    """
    interval = _load_interval()
    state = get_sentinel_state(session_id)
    if not state:
        return {"sentinel_state": "inactive", "display_state": "INACTIF"}

    sentinel_state = state.get("sentinel_state", "inactive")
    last_check = state.get("last_check_time")
    target_network = state.get("sentinel_target_network", "")
    gateway_ip = state.get("sentinel_gateway_ip", "")
    gateway_mac = state.get("sentinel_gateway_mac", "")

    # Compute degraded state from last_check_time
    display_state = _compute_display_state(sentinel_state, last_check, interval)

    # Count hosts
    assets = get_assets(session_id)
    known_hosts = len(assets)
    # active hosts = those with active=1
    active_hosts = sum(1 for a in assets if a.get("active", 1))

    # Unresolved alerts
    try:
        unresolved = count_unresolved_events(session_id)
    except Exception:
        unresolved = 0

    # Seconds since last check
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


def display_status(session_id: str) -> None:
    """Display the compact two-line Sentinel status in the terminal."""
    s = status(session_id)
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

def stop(session_id: str) -> None:
    """Stop Sentinel and persist inactive state. Baseline is preserved.

    Args:
        session_id: Session identifier.
    """
    _graceful_stop(session_id)
    display(f"[○] Sentinel arrêté. Session: {session_id}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _graceful_stop(session_id: str) -> None:
    """Mark sentinel as inactive in DB. Never deletes baseline or events."""
    try:
        update_sentinel_state(session_id=session_id, sentinel_state="inactive")
    except Exception:
        pass
    display("\n[○] Sentinel arrêté proprement. Baseline conservée.")


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
    conn = get_connection(session_id)
    try:
        # Check if any baseline row has same target_network but different triplet
        row = conn.execute(
            """
            SELECT COUNT(*) FROM baseline
            WHERE target_network = ?
              AND (gateway_ip != ? OR gateway_mac != ?)
            """,
            (target_network, identity.gateway_ip, identity.gateway_mac),
        ).fetchone()
        return row[0] > 0
    except Exception:
        return False
    finally:
        conn.close()


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
