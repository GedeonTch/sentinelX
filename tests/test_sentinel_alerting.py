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
from sentinel.alerting import (
    NO_FINDING_TYPES, AlertCounter, EventStamp, _make_finding, process_changes,
)
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
        results = [process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, c, network_id=NETWORK, stamp=EventStamp(NETWORK)) for _ in range(4)]
        assert [len(r) for r in results] == [1, 1, 1, 0]
        row = c.summary()[CHANGE_NEW_HOST.asset_ip]
        assert row['displayed'] == 3 and row['masked'] == 1

    def test_other_host_is_independent(self):
        c = AlertCounter()
        for _ in range(4):
            process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, c, network_id=NETWORK, stamp=EventStamp(NETWORK))
        assert len(process_changes([CHANGE_NEW_PORT], SESSION, WL_EMPTY, c, network_id=NETWORK, stamp=EventStamp(NETWORK))) == 1

    def test_restart_keeps_window(self):
        for _ in range(3):
            process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK, stamp=EventStamp(NETWORK))
        assert process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK, stamp=EventStamp(NETWORK)) == []


# ---------------------------------------------------------------------------
# process_changes — non-whitelisted
# ---------------------------------------------------------------------------

class TestProcessChangesNonWhitelisted:
    def test_event_written_to_db(self):
        process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK, stamp=EventStamp(NETWORK))
        events = db.sentinel_get_events(NETWORK)
        assert len(events) == 1
        assert events[0]["resolved"] == 0

    def test_finding_written_to_db(self):
        process_changes([CHANGE_NEW_PORT], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK, stamp=EventStamp(NETWORK))
        findings = db.get_findings(SESSION)
        assert len(findings) == 1
        assert findings[0].category == Category.NETWORK

    def test_finding_returned_for_display(self):
        result = process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK, stamp=EventStamp(NETWORK))
        assert len(result) == 1

    def test_severity_new_host_is_medium(self):
        result = process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK, stamp=EventStamp(NETWORK))
        assert result[0].severity == Severity.MEDIUM

    def test_severity_new_port_is_high(self):
        result = process_changes([CHANGE_NEW_PORT], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK, stamp=EventStamp(NETWORK))
        assert result[0].severity == Severity.HIGH

    def test_severity_mac_change_is_high(self):
        result = process_changes([CHANGE_MAC], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK, stamp=EventStamp(NETWORK))
        assert result[0].severity == Severity.HIGH

    def test_finding_evidence_not_empty(self):
        result = process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK, stamp=EventStamp(NETWORK))
        assert result[0].evidence.raw != ""

    def test_finding_risk_score_is_none(self):
        result = process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK, stamp=EventStamp(NETWORK))
        assert result[0].risk_score is None

    def test_finding_status_is_open(self):
        result = process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK, stamp=EventStamp(NETWORK))
        assert result[0].status == FindingStatus.OPEN

    def test_empty_changes_returns_empty(self):
        result = process_changes([], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK, stamp=EventStamp(NETWORK))
        assert result == []


# ---------------------------------------------------------------------------
# process_changes — whitelisted
# ---------------------------------------------------------------------------

class TestProcessChangesWhitelisted:
    def test_event_written_resolved_1(self):
        process_changes([CHANGE_NEW_HOST], SESSION, WL_HOST_ALLOWED, AlertCounter(), network_id=NETWORK, stamp=EventStamp(NETWORK))
        events = db.sentinel_get_events(NETWORK)
        assert events[0]["resolved"] == 1

    def test_no_finding_for_whitelisted_change(self):
        process_changes([CHANGE_NEW_HOST], SESSION, WL_HOST_ALLOWED, AlertCounter(), network_id=NETWORK, stamp=EventStamp(NETWORK))
        findings = db.get_findings(SESSION)
        assert findings == []

    def test_no_finding_returned_for_display(self):
        result = process_changes([CHANGE_NEW_HOST], SESSION, WL_HOST_ALLOWED, AlertCounter(), network_id=NETWORK, stamp=EventStamp(NETWORK))
        assert result == []

    def test_counter_not_incremented_for_whitelisted(self):
        counter = AlertCounter()
        process_changes([CHANGE_NEW_HOST], SESSION, WL_HOST_ALLOWED, counter, network_id=NETWORK, stamp=EventStamp(NETWORK))
        assert counter.summary()[CHANGE_NEW_HOST.asset_ip]['displayed'] == 0


# ---------------------------------------------------------------------------
# process_changes — silent mode
# ---------------------------------------------------------------------------

class TestProcessChangesSilentMode:
    def test_observations_and_findings_continue_during_silence(self):
        counter = AlertCounter()
        for _ in range(5):
            process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, counter, network_id=NETWORK, stamp=EventStamp(NETWORK))
        assert len(db.get_findings(SESSION)) == 5
        events = db.sentinel_get_events(NETWORK)
        assert len(events) == 5
        assert sum(e['details']['notification']['state'] == 'confirmed' for e in events) == 3
        assert sum(e['details']['notification']['state'] == 'masked' for e in events) == 2
        assert counter.summary()[CHANGE_NEW_HOST.asset_ip]['displayed'] == 3
        assert counter.summary()[CHANGE_NEW_HOST.asset_ip]['masked'] == 2


# ---------------------------------------------------------------------------
# T23-B §9.2, §9.3.1, §9.11 critères 3, 4, 11, 22 — routage, EventStamp (B1)
# ---------------------------------------------------------------------------

FIXED = datetime.datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
CHANGE_HOST_NOT_OBSERVED = NetworkChange(
    change_type="host_not_observed", asset_ip="192.168.1.10",
    detail="host not observed", evidence="ARP NOT_OBSERVED twice.",
)
CHANGE_PORT_NOT_OPEN = NetworkChange(
    change_type="port_not_open", asset_ip="192.168.1.10", detail="port 80 not open",
    evidence="Port 80 absent from two complete scans.", port=80,
)
CHANGE_PORTS_INITIALIZED = NetworkChange(
    change_type="host_ports_initialized", asset_ip="192.168.1.99",
    detail="ports initialized", evidence="first complete TCP scan.",
    initial_ports=[22, 80], initial_ports_known=True,
)


def _fixed_clock(*moments):
    """Clock returning the given instants in order, then the last one forever."""
    queue = list(moments)

    def clock():
        return queue.pop(0) if len(queue) > 1 else queue[0]
    return clock


class RecordingView:
    def __init__(self):
        self.calls = []

    def emit(self, when, change, finding=None, *, event_id=None, session_id=None):
        self.calls.append({"when": when, "change": change, "finding": finding,
                           "event_id": event_id, "session_id": session_id})


class TestObservationTypesWithoutFinding:
    def test_no_finding_types_are_exactly_the_five_observation_types(self):
        assert NO_FINDING_TYPES == {"host_not_observed", "port_not_open", "host_recovered",
                                    "scan_degraded", "host_ports_initialized"}

    @pytest.mark.parametrize("change", [CHANGE_HOST_NOT_OBSERVED, CHANGE_PORT_NOT_OPEN,
                                        CHANGE_PORTS_INITIALIZED])
    def test_observation_persisted_without_finding(self, change):
        result = process_changes([change], SESSION, WL_EMPTY, AlertCounter(), network_id=NETWORK,
                                 stamp=EventStamp(NETWORK))
        assert result == []
        assert db.get_findings(SESSION) == []
        events = db.sentinel_get_events(NETWORK)
        assert [e["type"] for e in events] == [change.change_type]

    def test_observation_is_displayed_through_view_with_event_identity(self):
        view = RecordingView()
        counter = AlertCounter(clock=lambda: FIXED, view=view)
        process_changes([CHANGE_HOST_NOT_OBSERVED], SESSION, WL_EMPTY, counter,
                        network_id=NETWORK, stamp=EventStamp(NETWORK, clock=lambda: FIXED))
        (event,) = db.sentinel_get_events(NETWORK)
        (call,) = view.calls
        assert call["finding"] is None
        assert call["event_id"] == event["id"]
        assert call["session_id"] == SESSION

    def test_observation_consumes_quota_like_any_notification(self):
        counter = AlertCounter(clock=lambda: FIXED)
        stamp = EventStamp(NETWORK, clock=lambda: FIXED)
        for _ in range(4):
            process_changes([CHANGE_PORT_NOT_OPEN], SESSION, WL_EMPTY, counter,
                            network_id=NETWORK, stamp=stamp)
        states = [e["details"]["notification"]["state"] for e in db.sentinel_get_events(NETWORK)]
        assert states.count("confirmed") == 3
        assert states.count("masked") == 1

    def test_mixed_cycle_returns_only_findings(self):
        result = process_changes([CHANGE_HOST_NOT_OBSERVED, CHANGE_NEW_HOST], SESSION, WL_EMPTY,
                                 AlertCounter(), network_id=NETWORK, stamp=EventStamp(NETWORK))
        assert [f.module for f in result] == ["sentinel.new_host"]


class TestMakeFinding:
    def test_target_port_taken_from_change_and_service_is_empty(self):
        change = NetworkChange("new_port", "192.168.1.10", "port 4444 opened", "evidence", port=4444)
        finding = _make_finding(change, SESSION, "f-1", FIXED.isoformat())
        assert finding.target_port == 4444
        assert finding.target_service == ""

    def test_new_host_without_port_keeps_none_port_and_empty_service(self):
        finding = _make_finding(CHANGE_NEW_HOST, SESSION, "f-2", FIXED.isoformat())
        assert finding.target_port is None
        assert finding.target_service == ""
        assert finding.created_at == FIXED.isoformat()


class TestEventStamp:
    def test_same_clock_value_is_made_strictly_increasing_within_a_cycle(self):
        stamp = EventStamp(NETWORK, clock=lambda: FIXED)
        values = [stamp.next() for _ in range(3)]
        moments = [datetime.datetime.fromisoformat(v) for v in values]
        assert moments[0] == FIXED
        assert moments[0] < moments[1] < moments[2]
        assert moments[1] == FIXED + datetime.timedelta(microseconds=1)

    def test_backwards_clock_never_goes_back(self):
        later = FIXED + datetime.timedelta(seconds=10)
        stamp = EventStamp(NETWORK, clock=_fixed_clock(later, FIXED))
        first = datetime.datetime.fromisoformat(stamp.next())
        second = datetime.datetime.fromisoformat(stamp.next())
        assert second == first + datetime.timedelta(microseconds=1)

    def test_naive_clock_is_rejected(self):
        stamp = EventStamp(NETWORK, clock=lambda: datetime.datetime(2026, 1, 1))
        with pytest.raises(ValueError):
            stamp.next()

    def test_restore_takes_maximum_datetime_not_string_order(self):
        # String order would pick "13:00…+02:00" (= 11:00Z); the instant 12:00Z is the real latest.
        events = [
            {"timestamp": "2026-11-08T13:00:00+02:00"},
            {"timestamp": "2026-11-08T12:00:00+00:00"},
            {"timestamp": "garbage"},
        ]
        stamp = EventStamp.restore(NETWORK, events, clock=lambda: FIXED)
        assert stamp.last == datetime.datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        assert stamp.next() == "2026-11-08T12:00:00.000001+00:00"

    def test_restore_without_events_starts_from_clock(self):
        stamp = EventStamp.restore(NETWORK, [], clock=lambda: FIXED)
        assert stamp.last is None
        assert stamp.next() == "2026-11-08T12:00:00.000000+00:00"  # always microseconds (§9.3.1)

    def test_several_events_in_one_cycle_have_distinct_stored_timestamps(self):
        stamp = EventStamp(NETWORK, clock=lambda: FIXED)
        changes = [CHANGE_NEW_HOST, CHANGE_PORT_NOT_OPEN, CHANGE_MAC]
        process_changes(changes, SESSION, WL_EMPTY, AlertCounter(clock=lambda: FIXED),
                        network_id=NETWORK, stamp=stamp)
        stamps = [e["timestamp"] for e in db.sentinel_get_events(NETWORK)]
        assert len(stamps) == 3 and len(set(stamps)) == 3

    def test_several_cycles_and_restart_keep_strict_order(self):
        """Three cycles with a frozen clock; the process restarts before cycles 2 and 3.

        Each restart restores the stamp from the stored events (B1): without restore the
        second cycle would reuse the first cycle's instant.
        """
        def restored():
            events = db.sentinel_network_snapshot(NETWORK)["events"]
            return EventStamp.restore(NETWORK, events, clock=lambda: FIXED)

        process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter(clock=lambda: FIXED),
                        network_id=NETWORK, stamp=EventStamp(NETWORK, clock=lambda: FIXED))
        process_changes([CHANGE_PORT_NOT_OPEN, CHANGE_HOST_NOT_OBSERVED], SESSION, WL_EMPTY,
                        AlertCounter(clock=lambda: FIXED), network_id=NETWORK, stamp=restored())
        cycle2_max = max(datetime.datetime.fromisoformat(e["timestamp"])
                         for e in db.sentinel_get_events(NETWORK))
        process_changes([CHANGE_MAC], SESSION, WL_EMPTY, AlertCounter(clock=lambda: FIXED),
                        network_id=NETWORK, stamp=restored())

        events = db.sentinel_get_events(NETWORK, limit=100)
        assert len(events) == 4
        assert len({e["timestamp"] for e in events}) == 4
        newest = max(events, key=lambda e: datetime.datetime.fromisoformat(e["timestamp"]))
        assert newest["type"] == "mac_change"
        assert datetime.datetime.fromisoformat(newest["timestamp"]) > cycle2_max

    def test_finding_created_at_uses_the_same_stamp_as_event(self):
        stamp = EventStamp(NETWORK, clock=lambda: FIXED)
        (finding,) = process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY,
                                     AlertCounter(clock=lambda: FIXED),
                                     network_id=NETWORK, stamp=stamp)
        (event,) = db.sentinel_get_events(NETWORK)
        assert finding.created_at == event["timestamp"]

    def test_stamp_of_another_network_is_rejected_before_any_write(self):
        with pytest.raises(ValueError):
            process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, AlertCounter(),
                            network_id=NETWORK, stamp=EventStamp("other-network"))
        assert db.sentinel_get_events(NETWORK) == []
        assert db.get_findings(SESSION) == []

    def test_details_keep_existing_keys_and_add_replay_fields(self):
        process_changes([CHANGE_PORTS_INITIALIZED, CHANGE_PORT_NOT_OPEN], SESSION, WL_EMPTY,
                        AlertCounter(), network_id=NETWORK, stamp=EventStamp(NETWORK))
        by_type = {e["type"]: e["details"] for e in db.sentinel_get_events(NETWORK)}
        init = by_type["host_ports_initialized"]
        assert init["ip"] == "192.168.1.99" and init["whitelisted"] is False
        assert init["initial_ports"] == [22, 80] and init["initial_ports_known"] is True
        assert by_type["port_not_open"]["port"] == 80


class TestHostPortsInitializedIsSilent:
    """§9.11 critère 23: host_ports_initialized is persisted, never displayed nor budgeted."""

    def test_not_displayed_and_not_counted_in_quota(self):
        view = RecordingView()
        counter = AlertCounter(clock=lambda: FIXED, view=view)
        process_changes([CHANGE_PORTS_INITIALIZED], SESSION, WL_EMPTY, counter,
                        network_id=NETWORK, stamp=EventStamp(NETWORK, clock=lambda: FIXED))
        assert view.calls == []
        assert counter.summary().get("192.168.1.99", {}).get("displayed", 0) == 0
        assert counter.summary().get("192.168.1.99", {}).get("reserved", 0) == 0

    def test_persisted_with_quota_skipping_state_and_not_authorized(self):
        process_changes([CHANGE_PORTS_INITIALIZED], SESSION, WL_EMPTY, AlertCounter(clock=lambda: FIXED),
                        network_id=NETWORK, stamp=EventStamp(NETWORK, clock=lambda: FIXED))
        (event,) = db.sentinel_get_events(NETWORK)
        assert event["type"] == "host_ports_initialized"
        assert event["details"]["whitelisted"] is False
        assert event["details"]["notification"]["state"] == "whitelisted"
        assert db.get_findings(SESSION) == []

    def test_budget_of_other_hosts_is_untouched_by_initialization(self):
        counter = AlertCounter(clock=lambda: FIXED)
        stamp = EventStamp(NETWORK, clock=lambda: FIXED)
        process_changes([CHANGE_PORTS_INITIALIZED], SESSION, WL_EMPTY, counter, network_id=NETWORK, stamp=stamp)
        for _ in range(3):
            process_changes([CHANGE_NEW_HOST], SESSION, WL_EMPTY, counter, network_id=NETWORK, stamp=stamp)
        assert counter.summary()["192.168.1.99"]["displayed"] == 3
