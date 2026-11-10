"""
sentinel/alerting.py — Sentinel alerting and anti-spam logic

Role: Transform NetworkChange objects into DB events and Findings.
      Apply whitelist filtering. Enforce anti-spam (silent mode).

Rules from spec revision 3:
    - Every change → event in DB (resolved=0 or resolved=1)
    - Whitelisted change → event resolved=1, no Finding, no alert display
    - Non-whitelisted change → event resolved=0, Finding created, alert displayed
    - At most 3 emitted notifications per host/network in a rolling 60 minutes
    - During silence: events and Findings still written; notifications suppressed
    - Versioned event metadata recovers the window after restart
    - Whitelisted INFO does not consume a slot

Sévérités:
    new_host    → MEDIUM
    new_port    → HIGH
    mac_change  → HIGH

T23-B (révision 12):
    - Observation types (NO_FINDING_TYPES) are persisted and budgeted like any
      event, but never create a Finding (§9.2, §9.11 critère 11).
    - Every persisted event takes its timestamp from an EventStamp: strictly
      increasing per network, restored from the database at start (B1, §9.3.1).

Rules enforced here:
- ZERO import sqlite3
- ZERO print() — display via core/logger.py
- ZERO risk_score calculation
- evidence.raw is always populated
"""

from __future__ import annotations

import uuid
import datetime as _dt
from typing import Callable, List, Optional

from core.database import sentinel_save_event, save_finding
from core.finding import (
    Category,
    Confidence,
    Evidence,
    Exposure,
    Finding,
    FindingStatus,
    Severity,
)
from core.logger import display
from sentinel.monitor import NetworkChange
from sentinel.whitelist import Whitelist, is_whitelisted


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

_SEVERITY_MAP = {
    "new_host":   Severity.MEDIUM,
    "new_port":   Severity.HIGH,
    "mac_change": Severity.HIGH,
}

# Observation types: persisted and notified under the T23-A quota, never a Finding (§9.2).
# They have no severity: the monitor view shows "—" for them (B2).
NO_FINDING_TYPES = frozenset({
    "host_not_observed", "port_not_open", "host_recovered",
    "scan_degraded", "host_ports_initialized",
})

# Persisted but never displayed nor budgeted (§9.11 critère 23: host_ports_initialized
# is neither shown nor notified). Contournement documenté : the frozen quota code
# (sentinel/notifications.py, interdit en T23-B) counts an event without notification
# metadata as a reserved slot for 60 min. Its metadata state is therefore 'whitelisted',
# which the quota skips. details.whitelisted stays False: the event is not authorized.
SILENT_TYPES = frozenset({"host_ports_initialized"})


# Backwards-compatible import name, with entirely new per-host durable semantics.
from sentinel.notifications import NotificationWindow, VERSION
from core.logger import get_console
from rich.text import Text
from sentinel.monitor_view import safe_text

AlertCounter = NotificationWindow


class EventStamp:
    """Strictly increasing event timestamps for one network (B1, §9.3.1).

    next() reads the clock; if the result is not after the last timestamp
    handed out, it returns last + 1 µs. Comparisons are on datetime, never on
    strings. The state is restored from the stored events at start.
    """

    def __init__(self, network_id: str, clock: Optional[Callable[[], _dt.datetime]] = None,
                 last: Optional[_dt.datetime] = None):
        self.network_id = network_id
        self.clock = clock or _utcnow
        self.last = last

    @classmethod
    def restore(cls, network_id: str, events: List[dict],
                clock: Optional[Callable[[], _dt.datetime]] = None) -> "EventStamp":
        last = None
        for event in events:
            moment = _parse_aware(event.get("timestamp"))
            if moment is not None and (last is None or moment > last):
                last = moment
        return cls(network_id, clock=clock, last=last)

    def next(self) -> str:
        moment = self.clock()
        if moment.tzinfo is None:
            raise ValueError("EventStamp clock must return a timezone-aware datetime")
        moment = moment.astimezone(_dt.timezone.utc)
        if self.last is not None and moment <= self.last:
            moment = self.last + _dt.timedelta(microseconds=1)
        self.last = moment
        return moment.isoformat(timespec="microseconds")


def _utcnow() -> _dt.datetime:
    # Read through the module attribute, like sentinel/notifications.py, so that a
    # frozen clock in tests controls both the quota and the event stamps.
    return _dt.datetime.now(_dt.timezone.utc)


def _parse_aware(value) -> Optional[_dt.datetime]:
    try:
        moment = _dt.datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return moment.astimezone(_dt.timezone.utc) if moment.tzinfo else None


def _detail_extras(change: NetworkChange) -> dict:
    """Fields the manager replays at restart (§9.8). Added to details; existing keys kept."""
    extras = {}
    if change.change_type in ("new_host", "host_ports_initialized"):
        extras["initial_ports"] = change.initial_ports
        extras["initial_ports_known"] = change.initial_ports_known
    if change.port is not None:
        extras["port"] = change.port
    return extras


def process_changes(changes: List[NetworkChange], session_id: str, whitelist: Whitelist,
                    counter: NotificationWindow, *, network_id: str,
                    stamp: EventStamp) -> List[Finding]:
    """Persist every observation; separately budget real notifications per host.

    Raises ValueError before anything is written when the stamp belongs to
    another network.
    """
    if stamp.network_id != network_id:
        raise ValueError("EventStamp belongs to a different network")
    counter.bind(network_id)
    shown = []
    for change in changes:
        now = stamp.next()
        event_id = str(uuid.uuid4())
        authorized = is_whitelisted(change_type=change.change_type,
                                    asset_ip=change.asset_ip, detail=change.detail,
                                    whitelist=whitelist)
        silent = change.change_type in SILENT_TYPES
        details = {"ip": change.asset_ip, "detail": change.detail, "whitelisted": authorized}
        details.update(_detail_extras(change))
        if authorized or silent:
            details['notification'] = {'version': VERSION, 'state': 'whitelisted', 'decided_at': now}
        # host_ports_initialized is initialization bookkeeping, not an alert: resolved.
        sentinel_save_event(network_id, event_id, change.change_type, now, None,
                            details, resolved=authorized or silent)
        if authorized:
            display(Text(safe_text(f"[INFO] {change.asset_ip} — {change.detail} (changement autorisé / whitelisté)"), style='dim'))
            counter.refresh()
            continue
        if silent:
            counter.refresh()
            continue

        if change.change_type in NO_FINDING_TYPES:
            def emit():
                if counter.view is None:
                    _display_observation(change)
                    get_console().file.flush()
                else:
                    counter.view.emit(now, change, event_id=event_id, session_id=session_id)

            counter.emit(event_id, change, emit)  # budgeted; never added to the returned Findings
            continue

        finding_id = str(uuid.uuid4())
        finding = _make_finding(change, session_id, finding_id, now)
        save_finding(finding)

        def emit():
            if counter.view is None:
                _display_alert(change, finding)
                get_console().file.flush()
            else:
                counter.view.emit(now, change, finding)

        if counter.emit(event_id, change, emit):
            shown.append(finding)
    counter.refresh()
    return shown


# ---------------------------------------------------------------------------
# Finding factory
# ---------------------------------------------------------------------------

def _make_finding(
    change: NetworkChange,
    session_id: str,
    finding_id: str,
    timestamp: str,
) -> Finding:
    """Build a sentinel Finding for a non-whitelisted NetworkChange.

    Args:
        change:     The detected NetworkChange.
        session_id: Current audit session ID.
        finding_id: Pre-generated UUID.
        timestamp:  ISO 8601 creation timestamp.

    Returns:
        Finding: Populated sentinel finding with evidence.raw set.
        target_port is change.port; target_service is "" (never "sentinel", T23-B).
    """
    severity = _SEVERITY_MAP.get(change.change_type, Severity.MEDIUM)

    # knowledge_base lookup for explanation
    explanation = None
    try:
        from knowledge.knowledge_base import get_explanation
        explanation = get_explanation(change.change_type)
    except Exception:
        pass

    return Finding(
        id=finding_id,
        session_id=session_id,
        module=f"sentinel.{change.change_type}",
        created_at=timestamp,
        target_ip=change.asset_ip,
        target_port=change.port,
        target_service="",
        category=Category.NETWORK,
        severity=severity,
        confidence=Confidence.CONFIRMED,
        exposure=Exposure.INTERNAL,
        evidence=Evidence(
            raw=change.evidence,
            command="sentinel monitor (nmap ping + ARP cache)",
        ),
        explanation=explanation,
        cve_refs=[],
        cvss_score=None,
        risk_score=None,
        status=FindingStatus.OPEN,
        remediation_cmd="",
    )


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _display_observation(change: NetworkChange) -> None:
    """Standalone fallback for an observation without monitor view."""
    display(Text(safe_text(f"[INFO] {change.asset_ip} — {change.detail}"), style='dim'))


def _display_alert(change: NetworkChange, finding: Finding) -> None:
    """Standalone fallback. The monitor uses its table instead (no duplicate)."""
    color = 'red' if finding.severity == Severity.HIGH else 'yellow'
    display(Text(safe_text(f"[ALERT] {change.asset_ip} — {change.detail}"), style=color))
