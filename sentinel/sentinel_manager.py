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
    init_sentinel_db,
    save_session,
    sentinel_count_unresolved_events,
    sentinel_get_state,
    sentinel_has_conflicting_baseline,
    sentinel_update_state,
    update_sentinel_state,
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
from sentinel.monitor import check_network, ScanFailedError
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

    # Step 2 — initialise persistent sentinel DB for this network
    init_sentinel_db(network_id)

    # Step 3 — create a run session for tracking this execution
    run_session_id = session_id or f"sentinel-run-{uuid.uuid4().hex[:8]}"
    init_db(run_session_id)
    save_session(run_session_id, target=target_network, profile="sentinel")

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
            return
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
            return

        ok = learn_baseline(
            target_network=target_network,
            network_id=network_id,
            identity=identity,
            force_relearn=force_relearn,
        )
        if not ok:
            display("[red]Échec de l'apprentissage de la baseline. Sentinel non démarré.[/red]")
            sentinel_update_state(network_id, "inactive")
            return
    else:
        display("[green]Baseline existante trouvée — surveillance démarrée.[/green]")

    # Step 6 — record initial state in sentinel DB
    now = datetime.datetime.now(timezone.utc).isoformat()
    sentinel_update_state(
        network_id=network_id,
        sentinel_status="active",
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

    # Step 7 — surveillance loop
    _run_loop(
        target_network=target_network,
        network_id=network_id,
        identity=identity,
        interval=interval,
        whitelist=whitelist,
        counter=counter,
    )


def _run_loop(
    target_network: str,
    network_id: str,
    identity: NetworkIdentity,
    interval: int,
    whitelist,
    counter: AlertCounter,
) -> None:
    """Run the surveillance loop until interrupted."""
    try:
        while True:
            time.sleep(interval)
            _do_check(
                target_network=target_network,
                network_id=network_id,
                identity=identity,
                interval=interval,
                whitelist=whitelist,
                counter=counter,
            )
    except KeyboardInterrupt:
        _graceful_stop(network_id)


def _do_check(
    target_network: str,
    network_id: str,
    identity: NetworkIdentity,
    interval: int,
    whitelist,
    counter: AlertCounter,
) -> None:
    """Execute one surveillance check cycle using the sentinel DB."""
    baseline = get_baseline(network_id, identity)
    if not baseline:
        display("[yellow]Baseline vide — impossible de comparer.[/yellow]")
        return

    try:
        changes = check_network(
            target_network=target_network,
            session_id=network_id,
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
                session_id=network_id,
                whitelist=whitelist,
                counter=counter,
            )
    except ScanFailedError as exc:
        # Ping scan failed — do NOT update last_check_time
        # Network state is unknown — this is not a successful check
        display(f"[yellow]Monitor: {exc}[/yellow]")
        state = sentinel_get_state(network_id)
        last_ok = state.get("last_check_time")
        if last_ok:
            elapsed = (
                datetime.datetime.now(timezone.utc)
                - datetime.datetime.fromisoformat(last_ok)
            ).total_seconds()
            if elapsed > 2 * interval:
                sentinel_update_state(network_id=network_id, sentinel_status="degraded")
                display("[yellow][!] SENTINELX: DÉGRADÉ[/yellow]")
    except Exception as exc:
        # Unexpected error — same behaviour: no last_check_time update
        display(f"[yellow]Monitor check error: {exc}[/yellow]")


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

def status(session_id: str) -> dict:
    """Return current Sentinel status.

    Accepts session_id for backward compatibility but also checks network_id
    derived from sentinel DB. Falls back gracefully if no sentinel state found.
    """
    interval = _load_interval()
    # Try sentinel state DB first (new path)
    # Since we don't have network_id here, we scan sentinel DBs by session target
    # Fallback: use old session-based state
    state = sentinel_get_state(session_id)
    if state:
        sentinel_state = state.get("sentinel_status", "inactive")
        last_check = state.get("last_check_time")
        target_network = state.get("target_network", "")
        gateway_ip = state.get("gateway_ip", "")
        gateway_mac = state.get("gateway_mac", "")
    else:
        sentinel_state = "inactive"
        last_check = None
        target_network = ""
        gateway_ip = ""
        gateway_mac = ""

    display_state = _compute_display_state(sentinel_state, last_check, interval)
    assets = get_assets(session_id)
    known_hosts = len(assets)
    active_hosts = sum(1 for a in assets if a.get("active", 1))

    try:
        unresolved = sentinel_count_unresolved_events(session_id)
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
    """Stop Sentinel. Baseline preserved in sentinel DB."""
    _graceful_stop(session_id)
    display(f"[○] Sentinel arrêté. Session: {session_id}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _graceful_stop(network_or_session_id: str) -> None:
    """Mark sentinel as inactive. Never deletes baseline or events."""
    try:
        sentinel_update_state(network_or_session_id, "inactive")
    except Exception:
        try:
            update_sentinel_state(network_or_session_id, sentinel_state="inactive")
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
