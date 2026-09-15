"""
tests/test_sentinel_alerting.py — Unit tests for sentinel/alerting.py

Covers: process_changes matrice Event/Finding/Display,
        AlertCounter silent mode (count >= seuil),
        whitelisted=resolved=1 no Finding,
        silent mode: Finding in DB no display,
        counter resets (simulated restart).
"""

import datetime
import pytest
from pathlib import Path
from unittest.mock import patch
from datetime import timezone

import core.database as db
from core.finding import FindingStatus, Severity, Category
from sentinel.alerting import AlertCounter, process_changes
from sentinel.monitor import NetworkChange
from sentinel.whitelist import Whitelist

SESSION = "session-alerting-test"

CHANGE_NEW_HOST = NetworkChange(
    change_type="new_host",
    asset_ip="192.168.1.99",
    detail="new host detected",
    evidence="Host 192.168.1.99 responded to ping.",
)
CHANGE_NEW_PORT = NetworkChange(
    change_type="new_port",
    asset_ip="192.168.1.10",
    detail="port 4444 opened",
    evidence="Port 4444/tcp open on 192.168.1.10.",
)
CHANGE_MAC = NetworkChange(
    change_type="mac_change",
    asset_ip="192.168.1.1",
    detail="mac changed from aa:aa:aa:aa:aa:aa to bb:bb:bb:bb:bb:bb",
    evidence="ARP cache shows different MAC.",
)

WL_EMPTY = Whitelist()
WL_HOST_ALLOWED = Whitelist(allowed_new_hosts=["192.168.1.99"])
WL_PORT_ALLOWED = Whitelist(
    allowed_port_changes=[{"host": "192.168.1.10", "ports": [4444]}]
)


@pytest.fixture(autouse=True)
def patch_db_path(tmp_path, monkeypatch):
    def mock_get_db_path(session_id: str):
        d = tmp_path / ".netlab" / "sessions"
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{session_id}.db"
    monkeypatch.setattr(db, "get_db_path", mock_get_db_path)
    db.init_db(SESSION)
    db.save_session(SESSION, target="192.168.1.0/24")


# ---------------------------------------------------------------------------
# AlertCounter
# ---------------------------------------------------------------------------

class TestAlertCounter:
    def test_not_silent_initially(self):
        c = AlertCounter(max_per_hour=3)
        assert not c.is_silent

    def test_triggers_at_threshold(self):
        c = AlertCounter(max_per_hour=3)
        c.increment()
        c.increment()
        triggered = c.increment()  # count = 3, >= 3
        assert triggered is True
        assert c.is_silent

    def test_does_not_trigger_before_threshold(self):
        c = AlertCounter(max_per_hour=3)
        c.increment()
        triggered = c.increment()  # count = 2
        assert triggered is False
        assert not c.is_silent

    def test_silent_mode_expires(self):
        c = AlertCounter(max_per_hour=3, silent_duration_s=1)
        c.increment()
        c.increment()
        c.increment()  # triggers silence
        assert c.is_silent
        # Simulate expiry by backdating silent_since
        c.silent_since = datetime.datetime.now(timezone.utc) - datetime.timedelta(seconds=2)
        assert not c.is_silent

    def test_try_exit_silent_returns_true_when_expired(self):
        c = AlertCounter(max_per_hour=3, silent_duration_s=0)
        c.silent_since = datetime.datetime.now(timezone.utc) - datetime.timedelta(hours=2)
        result = c.try_exit_silent()
        assert result is True
        assert c.silent_since is None

    def test_counter_reset_behavior(self):
        """A new AlertCounter (simulating restart) starts at 0, not silent."""
        c = AlertCounter(max_per_hour=3)
        assert c.count == 0
        assert not c.is_silent


# ---------------------------------------------------------------------------
# process_changes — non-whitelisted
# ---------------------------------------------------------------------------

class TestProcessChangesNonWhitelisted:
    def test_event_written_to_db(self):
        process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter())
        events = db.get_events(SESSION)
        assert len(events) == 1
        assert events[0]["resolved"] == 0

    def test_finding_written_to_db(self):
        process_changes([CHANGE_NEW_PORT], SESSION, WL_EMPTY, AlertCounter())
        findings = db.get_findings(SESSION)
        assert len(findings) == 1
        assert findings[0].category == Category.NETWORK

    def test_finding_returned_for_display(self):
        result = process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter())
        assert len(result) == 1

    def test_severity_new_host_is_medium(self):
        result = process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter())
        assert result[0].severity == Severity.MEDIUM

    def test_severity_new_port_is_high(self):
        result = process_changes([CHANGE_NEW_PORT], SESSION, WL_EMPTY, AlertCounter())
        assert result[0].severity == Severity.HIGH

    def test_severity_mac_change_is_high(self):
        result = process_changes([CHANGE_MAC], SESSION, WL_EMPTY, AlertCounter())
        assert result[0].severity == Severity.HIGH

    def test_finding_evidence_not_empty(self):
        result = process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter())
        assert result[0].evidence.raw != ""

    def test_finding_risk_score_is_none(self):
        result = process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter())
        assert result[0].risk_score is None

    def test_finding_status_is_open(self):
        result = process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter())
        assert result[0].status == FindingStatus.OPEN

    def test_empty_changes_returns_empty(self):
        result = process_changes([], SESSION, WL_EMPTY, AlertCounter())
        assert result == []


# ---------------------------------------------------------------------------
# process_changes — whitelisted
# ---------------------------------------------------------------------------

class TestProcessChangesWhitelisted:
    def test_event_written_resolved_1(self):
        process_changes([CHANGE_NEW_HOST], SESSION, WL_HOST_ALLOWED, AlertCounter())
        events = db.get_events(SESSION)
        assert events[0]["resolved"] == 1

    def test_no_finding_for_whitelisted_change(self):
        process_changes([CHANGE_NEW_HOST], SESSION, WL_HOST_ALLOWED, AlertCounter())
        findings = db.get_findings(SESSION)
        assert findings == []

    def test_no_finding_returned_for_display(self):
        result = process_changes([CHANGE_NEW_HOST], SESSION, WL_HOST_ALLOWED, AlertCounter())
        assert result == []

    def test_counter_not_incremented_for_whitelisted(self):
        counter = AlertCounter(max_per_hour=3)
        process_changes([CHANGE_NEW_HOST], SESSION, WL_HOST_ALLOWED, counter)
        assert counter.count == 0


# ---------------------------------------------------------------------------
# process_changes — silent mode
# ---------------------------------------------------------------------------

class TestProcessChangesSilentMode:
    def test_finding_in_db_during_silence(self):
        """During silent mode, Findings must still be written to DB."""
        counter = AlertCounter(max_per_hour=2)
        # First change triggers silence at count=2
        process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, counter)
        process_changes([CHANGE_NEW_PORT], SESSION, WL_EMPTY, counter)
        assert counter.is_silent
        # Third change — silent mode active
        process_changes([CHANGE_MAC], SESSION, WL_EMPTY, counter)
        findings = db.get_findings(SESSION)
        assert len(findings) == 3  # all three in DB

    def test_no_finding_returned_during_silence(self):
        """During silent mode, no Finding returned for display."""
        counter = AlertCounter(max_per_hour=2)
        process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, counter)
        process_changes([CHANGE_NEW_PORT], SESSION, WL_EMPTY, counter)
        assert counter.is_silent
        result = process_changes([CHANGE_MAC], SESSION, WL_EMPTY, counter)
        assert result == []

    def test_event_written_during_silence(self):
        """Events must always be written, even during silence."""
        counter = AlertCounter(max_per_hour=2)
        process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, counter)
        process_changes([CHANGE_NEW_PORT], SESSION, WL_EMPTY, counter)
        process_changes([CHANGE_MAC], SESSION, WL_EMPTY, counter)
        events = db.get_events(SESSION)
        assert len(events) == 3

    def test_counter_increments_during_silence(self):
        """Alert counter continues to increment during silent mode."""
        counter = AlertCounter(max_per_hour=2)
        process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, counter)
        process_changes([CHANGE_NEW_PORT], SESSION, WL_EMPTY, counter)
        process_changes([CHANGE_MAC], SESSION, WL_EMPTY, counter)
        assert counter.count == 3
