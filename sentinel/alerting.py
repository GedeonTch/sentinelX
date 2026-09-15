"""
sentinel/alerting.py — Sentinel alerting and anti-spam logic

Role: Transform NetworkChange objects into DB events and Findings.
      Apply whitelist filtering. Enforce anti-spam (silent mode).

Rules from spec revision 3:
    - Every change → event in DB (resolved=0 or resolved=1)
    - Whitelisted change → event resolved=1, no Finding, no alert display
    - Non-whitelisted change → event resolved=0, Finding created, alert displayed
    - Silent mode triggers when alert_count >= sentinel_max_alerts_per_hour
    - During silent mode: events and Findings still written to DB, display suspended
    - Silent mode counter is session-local — reset on Sentinel restart
    - After 1h silence → resume message displayed

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

import datetime
import uuid
from dataclasses import dataclass, field
from datetime import timezone
from typing import List, Optional, Tuple

from core.database import save_event, save_finding
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


# ---------------------------------------------------------------------------
# AlertCounter — session-local, resets on restart
# ---------------------------------------------------------------------------

@dataclass
class AlertCounter:
    """Tracks alert count and silent mode state for the current Sentinel session.

    This object is instantiated in sentinel_manager and passed to
    process_changes on every cycle. It is NOT persisted — it resets
    when Sentinel restarts, as required by spec.

    Attributes:
        count:              Total security alerts raised this session.
        silent_since:       Datetime when silent mode started, or None.
        silent_duration_s:  Duration of silent mode in seconds (3600 = 1h).
        max_per_hour:       Threshold — silent mode triggers at count >= this.
    """
    count: int = 0
    silent_since: Optional[datetime.datetime] = None
    silent_duration_s: int = 3600
    max_per_hour: int = 3

    @property
    def is_silent(self) -> bool:
        """Return True if currently in silent mode."""
        if self.silent_since is None:
            return False
        elapsed = (datetime.datetime.now(timezone.utc) - self.silent_since).total_seconds()
        return elapsed < self.silent_duration_s

    def try_exit_silent(self) -> bool:
        """Check if silent mode has expired. Return True if just exited."""
        if self.silent_since is None:
            return False
        elapsed = (datetime.datetime.now(timezone.utc) - self.silent_since).total_seconds()
        if elapsed >= self.silent_duration_s:
            self.silent_since = None
            return True
        return False

    def increment(self) -> bool:
        """Increment alert count. Return True if silent mode just triggered.

        Returns:
            bool: True if this increment caused silent mode to start.
        """
        self.count += 1
        if self.count >= self.max_per_hour and self.silent_since is None:
            self.silent_since = datetime.datetime.now(timezone.utc)
            return True
        return False


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def process_changes(
    changes: List[NetworkChange],
    session_id: str,
    whitelist: Whitelist,
    counter: AlertCounter,
) -> List[Finding]:
    """Process detected network changes and produce events + Findings.

    For each change:
      - Always writes an event to DB
      - Whitelisted → resolved=1, INFO display, no Finding, counter unchanged
      - Non-whitelisted → resolved=0, Finding created, counter incremented
      - If counter >= max_alerts_per_hour → silent mode (Finding still in DB,
        display suspended)

    Args:
        changes:    NetworkChange list from monitor.check_network().
        session_id: Current audit session ID.
        whitelist:  Loaded Whitelist for filtering.
        counter:    Session-local AlertCounter (mutated in place).

    Returns:
        List[Finding]: Findings to display (empty when silent or all whitelisted).
    """
    if not changes:
        return []

    # Check if silent mode has expired before processing
    just_resumed = counter.try_exit_silent()
    if just_resumed:
        _display_resume_message(session_id, counter)

    findings_to_display: List[Finding] = []
    max_alerts = whitelist.sentinel_max_alerts_per_hour

    for change in changes:
        now = datetime.datetime.now(timezone.utc).isoformat()
        event_id = str(uuid.uuid4())
        finding_id = str(uuid.uuid4())

        authorized = is_whitelisted(
            change_type=change.change_type,
            asset_ip=change.asset_ip,
            detail=change.detail,
            whitelist=whitelist,
        )

        # Always write event — whitelisted or not
        save_event(
            session_id=session_id,
            event_id=event_id,
            event_type=change.change_type,
            timestamp=now,
            asset_id=None,
            details={
                "ip": change.asset_ip,
                "detail": change.detail,
                "whitelisted": authorized,
            },
            resolved=authorized,
        )

        if authorized:
            # Whitelisted — INFO display, no Finding, no counter increment
            display(
                f"[dim][INFO] {change.asset_ip} — {change.detail} "
                f"(changement autorisé / whitelisté)[/dim]"
            )
            continue

        # Non-whitelisted — create Finding, always write to DB
        finding = _make_finding(change, session_id, finding_id, now)
        save_finding(finding)

        # Increment counter — may trigger silent mode
        just_silenced = counter.increment()
        if just_silenced:
            _display_silent_mode_message(counter)

        if not counter.is_silent:
            # Display alert
            _display_alert(change, finding)
            findings_to_display.append(finding)
        else:
            # Silent — Finding in DB, no display
            pass

    return findings_to_display


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
    """Display a security alert in the terminal."""
    severity_color = {
        Severity.HIGH:   "red",
        Severity.MEDIUM: "yellow",
    }.get(finding.severity, "white")

    display(
        f"[{severity_color}][ALERT] {change.asset_ip} — {change.detail}[/{severity_color}]"
    )
    display(f"  [dim]Finding: {finding.id[:8]} | severity: {finding.severity.value}[/dim]")
    display(f"  [dim]› netlab sentinel history  › netlab findings show {finding.id[:8]}[/dim]")


def _display_silent_mode_message(counter: AlertCounter) -> None:
    """Display the silent mode activation message."""
    display(
        f"[yellow][!] Sentinel passe en mode silencieux "
        f"({counter.count} alertes atteintes).\n"
        f"    La surveillance continue. Les événements sont enregistrés.\n"
        f"    Les nouvelles alertes ne seront plus affichées pendant 1h.\n"
        f"    › netlab sentinel history  pour consulter l'historique[/yellow]"
    )


def _display_resume_message(session_id: str, counter: AlertCounter) -> None:
    """Display the resume message after silent mode expires."""
    from core.database import count_unresolved_events
    try:
        event_count = count_unresolved_events(session_id)
    except Exception:
        event_count = "?"

    display(
        f"[green][●] Sentinel reprend les alertes normales.\n"
        f"    Événements enregistrés pendant le silence : {event_count}\n"
        f"    › netlab sentinel history  pour consulter[/green]"
    )
