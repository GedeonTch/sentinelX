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

Rules enforced here:
- ZERO import sqlite3
- ZERO print() — display via core/logger.py
- ZERO risk_score calculation
- evidence.raw is always populated
"""

from __future__ import annotations

import uuid
from typing import List

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


# Backwards-compatible import name, with entirely new per-host durable semantics.
from sentinel.notifications import NotificationWindow, VERSION
from core.logger import get_console
from rich.text import Text
from sentinel.monitor_view import safe_text

AlertCounter = NotificationWindow


def process_changes(changes: List[NetworkChange], session_id: str, whitelist: Whitelist,
                    counter: NotificationWindow, *, network_id: str) -> List[Finding]:
    """Persist every observation; separately budget real notifications per host."""
    counter.bind(network_id)
    shown = []
    for change in changes:
        now = counter.clock().isoformat()
        event_id, finding_id = str(uuid.uuid4()), str(uuid.uuid4())
        authorized = is_whitelisted(change_type=change.change_type,
                                    asset_ip=change.asset_ip, detail=change.detail,
                                    whitelist=whitelist)
        details = {"ip": change.asset_ip, "detail": change.detail, "whitelisted": authorized}
        if authorized:
            details['notification'] = {'version': VERSION, 'state': 'whitelisted', 'decided_at': now}
        sentinel_save_event(network_id, event_id, change.change_type, now, None,
                            details, resolved=authorized)
        if authorized:
            display(Text(safe_text(f"[INFO] {change.asset_ip} — {change.detail} (changement autorisé / whitelisté)"), style='dim'))
            counter.refresh()
            continue
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
        target_port=None,
        target_service="sentinel",
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

def _display_alert(change: NetworkChange, finding: Finding) -> None:
    """Standalone fallback. The monitor uses its table instead (no duplicate)."""
    color = 'red' if finding.severity == Severity.HIGH else 'yellow'
    display(Text(safe_text(f"[ALERT] {change.asset_ip} — {change.detail}"), style=color))
