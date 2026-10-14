"""
tests/test_sentinel_alerting.py — Unit tests for sentinel/alerting.py

Covers: process_changes matrice Event/Finding/Display,
        per-host rolling notification quota,
        whitelisted=resolved=1 no Finding,
        silent mode: Finding in DB no display,
        counter reconstruction after restart.
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
NETWORK = "network-alerting-test"

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
    def mock_network_path(network_id: str):
        d = tmp_path / ".netlab" / "sentinel"
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{network_id}.db"
    monkeypatch.setattr(db, "get_db_path", mock_get_db_path)
    monkeypatch.setattr(db, "get_sentinel_db_path", mock_network_path)
    db.init_sentinel_db(NETWORK)
    db.init_db(SESSION)
    db.save_session(SESSION, target="192.168.1.0/24")


# ---------------------------------------------------------------------------
# AlertCounter
# ---------------------------------------------------------------------------

class TestAlertCounter:
    def test_three_emissions_then_fourth_masked(self):
        c = AlertCounter()
        results = [process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, c, network_id=NETWORK) for _ in range(4)]
        assert [len(r) for r in results] == [1, 1, 1, 0]
        row = c.summary()[CHANGE_NEW_HOST.asset_ip]
        assert row['displayed'] == 3 and row['masked'] == 1

    def test_other_host_is_independent(self):
        c = AlertCounter()
        for _ in range(4):
            process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, c, network_id=NETWORK)
        assert len(process_changes([CHANGE_NEW_PORT], SESSION, WL_EMPTY, c, network_id=NETWORK)) == 1

    def test_restart_keeps_window(self):
        for _ in range(3):
            process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK)
        assert process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK) == []


# ---------------------------------------------------------------------------
# process_changes — non-whitelisted
# ---------------------------------------------------------------------------

class TestProcessChangesNonWhitelisted:
    def test_event_written_to_db(self):
        process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK)
        events = db.sentinel_get_events(NETWORK)
        assert len(events) == 1
        assert events[0]["resolved"] == 0

    def test_finding_written_to_db(self):
        process_changes([CHANGE_NEW_PORT], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK)
        findings = db.get_findings(SESSION)
        assert len(findings) == 1
        assert findings[0].category == Category.NETWORK

    def test_finding_returned_for_display(self):
        result = process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK)
        assert len(result) == 1

    def test_severity_new_host_is_medium(self):
        result = process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK)
        assert result[0].severity == Severity.MEDIUM

    def test_severity_new_port_is_high(self):
        result = process_changes([CHANGE_NEW_PORT], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK)
        assert result[0].severity == Severity.HIGH

    def test_severity_mac_change_is_high(self):
        result = process_changes([CHANGE_MAC], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK)
        assert result[0].severity == Severity.HIGH

    def test_finding_evidence_not_empty(self):
        result = process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK)
        assert result[0].evidence.raw != ""

    def test_finding_risk_score_is_none(self):
        result = process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK)
        assert result[0].risk_score is None

    def test_finding_status_is_open(self):
        result = process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK)
        assert result[0].status == FindingStatus.OPEN

    def test_empty_changes_returns_empty(self):
        result = process_changes([], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK)
        assert result == []


# ---------------------------------------------------------------------------
# process_changes — whitelisted
# ---------------------------------------------------------------------------

class TestProcessChangesWhitelisted:
    def test_event_written_resolved_1(self):
        process_changes([CHANGE_NEW_HOST], SESSION, WL_HOST_ALLOWED, AlertCounter(), network_id=NETWORK)
        events = db.sentinel_get_events(NETWORK)
        assert events[0]["resolved"] == 1

    def test_no_finding_for_whitelisted_change(self):
        process_changes([CHANGE_NEW_HOST], SESSION, WL_HOST_ALLOWED, AlertCounter(), network_id=NETWORK)
        findings = db.get_findings(SESSION)
        assert findings == []

    def test_no_finding_returned_for_display(self):
        result = process_changes([CHANGE_NEW_HOST], SESSION, WL_HOST_ALLOWED, AlertCounter(), network_id=NETWORK)
        assert result == []

    def test_counter_not_incremented_for_whitelisted(self):
        counter = AlertCounter()
        process_changes([CHANGE_NEW_HOST], SESSION, WL_HOST_ALLOWED, counter, network_id=NETWORK)
        assert counter.summary()[CHANGE_NEW_HOST.asset_ip]['displayed'] == 0


# ---------------------------------------------------------------------------
# process_changes — silent mode
# ---------------------------------------------------------------------------

class TestProcessChangesSilentMode:
    def test_observations_and_findings_continue_during_silence(self):
        counter = AlertCounter()
        for _ in range(5):
            process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, counter, network_id=NETWORK)
        assert len(db.get_findings(SESSION)) == 5
        events = db.sentinel_get_events(NETWORK)
        assert len(events) == 5
        assert sum(e['details']['notification']['state'] == 'confirmed' for e in events) == 3
        assert sum(e['details']['notification']['state'] == 'masked' for e in events) == 2
        assert counter.summary()[CHANGE_NEW_HOST.asset_ip]['displayed'] == 3
        assert counter.summary()[CHANGE_NEW_HOST.asset_ip]['masked'] == 2
