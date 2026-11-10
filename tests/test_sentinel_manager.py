"""
tests/test_sentinel_manager.py — Unit tests for sentinel/sentinel_manager.py

Covers: status (ACTIF/DÉGRADÉ/INACTIF), _compute_display_state,
        stop preserves baseline, last_check_time only on success.
        start() loop is not unit-tested (blocking) — covered by integration.
"""

import datetime
import uuid
import pytest
from pathlib import Path
from unittest.mock import Mock, patch
from datetime import timezone

import core.database as db
import sentinel.sentinel_manager as sm
from sentinel.sentinel_manager import (
    NetworkState,
    status,
    stop,
    _compute_display_state,
    _graceful_stop,
    _do_check,
    _normalize_and_filter,
    _rebuild_transition_state,
)
from sentinel.alerting import AlertCounter, EventStamp
from sentinel.arp_probe import ArpProbeStatus
from sentinel.baseline import BaselineEntry
from sentinel.monitor import (
    CycleObservations,
    HostTcpObservation,
    NetworkChange,
    ScanDegradedError,
    ScanFailedError,
)
from sentinel.whitelist import Whitelist

SESSION = "session-manager-test"


@pytest.fixture(autouse=True)
def patch_db_path(tmp_path, monkeypatch):
    def mock_get_db_path(session_id: str):
        d = tmp_path / ".netlab" / "sessions"
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{session_id}.db"

    def mock_get_sentinel_db_path(network_id: str):
        d = tmp_path / ".netlab" / "sentinel"
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{network_id}.db"

    monkeypatch.setattr(db, "get_db_path", mock_get_db_path)
    monkeypatch.setattr(db, "get_sentinel_db_path", mock_get_sentinel_db_path)
    monkeypatch.setattr(
        "sentinel.sentinel_manager.list_sentinel_network_ids",
        lambda: [SESSION],
    )
    db.init_db(SESSION)
    db.init_sentinel_db(SESSION)
    db.save_session(SESSION, target="192.168.1.0/24")


# ---------------------------------------------------------------------------
# _compute_display_state
# ---------------------------------------------------------------------------

class TestComputeDisplayState:
    def test_inactive_state(self):
        assert _compute_display_state("inactive", None, 60) == "INACTIF"

    def test_active_recent_check(self):
        now = datetime.datetime.now(timezone.utc).isoformat()
        assert _compute_display_state("active", now, 60) == "ACTIF"

    def test_degraded_when_no_last_check(self):
        assert _compute_display_state("active", None, 60) == "DÉGRADÉ"

    def test_degraded_when_check_too_old(self):
        old = (datetime.datetime.now(timezone.utc) - datetime.timedelta(seconds=200)).isoformat()
        assert _compute_display_state("active", old, 60) == "DÉGRADÉ"

    def test_active_when_check_within_2x_interval(self):
        recent = (datetime.datetime.now(timezone.utc) - datetime.timedelta(seconds=90)).isoformat()
        assert _compute_display_state("active", recent, 60) == "ACTIF"

    def test_degraded_exactly_at_2x_interval(self):
        """At exactly 2×interval seconds → DÉGRADÉ."""
        old = (datetime.datetime.now(timezone.utc) - datetime.timedelta(seconds=121)).isoformat()
        result = _compute_display_state("active", old, 60)
        assert result == "DÉGRADÉ"


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

class TestStatus:
    def test_missing_sentinel_state_is_controlled_error(self):
        with pytest.raises(ValueError, match="No Sentinel state exists"):
            status(SESSION)

    def test_returns_active_when_recently_checked(self):
        now = datetime.datetime.now(timezone.utc).isoformat()
        db.sentinel_update_state(
            network_id=SESSION,
            sentinel_status="active",
            last_check_time=now,
            target_network="192.168.1.0/24",
            gateway_ip="192.168.1.1",
            gateway_mac="aa:aa:aa:aa:aa:aa",
        )
        result = status(SESSION)
        assert result["display_state"] == "ACTIF"

    def test_returns_degraded_when_check_stale(self):
        old = (datetime.datetime.now(timezone.utc) - datetime.timedelta(seconds=500)).isoformat()
        db.sentinel_update_state(
            network_id=SESSION,
            sentinel_status="active",
            last_check_time=old,
        )
        result = status(SESSION)
        assert result["display_state"] == "DÉGRADÉ"

    def test_unresolved_alerts_counted(self):
        db.sentinel_update_state(SESSION, "inactive")
        import uuid
        db.sentinel_save_event(
            network_id=SESSION,
            event_id=str(uuid.uuid4()),
            event_type="new_host",
            timestamp=datetime.datetime.now(timezone.utc).isoformat(),
            asset_id=None,
            details={"ip": "192.168.1.99"},
            resolved=False,
        )
        result = status(SESSION)
        assert result["unresolved_alerts"] >= 1

    def test_status_preserves_unknown_gateway_for_host_only_network(self):
        db.sentinel_update_state(
            network_id=SESSION,
            sentinel_status="active",
            target_network="192.168.56.0/24",
            gateway_ip="",
            gateway_mac="",
        )
        result = status(SESSION)
        assert result["target_network"] == "192.168.56.0/24"
        assert result["gateway_ip"] == ""
        assert result["gateway_mac"] == ""

    def test_unknown_network_is_controlled_error(self):
        with pytest.raises(ValueError, match="Unknown Sentinel network"):
            status("unknown-network")

    def test_no_known_network_is_controlled_error(self, monkeypatch):
        monkeypatch.setattr(
            "sentinel.sentinel_manager.list_sentinel_network_ids", lambda: []
        )
        with pytest.raises(ValueError, match="No known Sentinel network"):
            status()

    def test_status_reads_only_network_context(self):
        db.sentinel_update_state(
            SESSION,
            "active",
            last_check_time=datetime.datetime.now(timezone.utc).isoformat(),
            target_network="192.168.1.0/24",
        )
        with patch("sentinel.sentinel_manager.sentinel_get_state", return_value={
            "sentinel_status": "active",
            "last_check_time": None,
            "target_network": "192.168.1.0/24",
            "gateway_ip": "",
            "gateway_mac": "",
        }) as get_state, patch(
            "sentinel.sentinel_manager.sentinel_identity_machine_counts", return_value=(0, 0)
        ) as get_counts:
            result = status(SESSION)
        get_state.assert_called_once_with(SESSION)
        # The counts are read for the identity recorded in the state, "" included.
        get_counts.assert_called_once_with(SESSION, "192.168.1.0/24", "", "")
        assert result["network_id"] == SESSION
        assert (result["known_hosts"], result["active_hosts"]) == (0, 0)


# ---------------------------------------------------------------------------
# stop / _graceful_stop
# ---------------------------------------------------------------------------

class TestStop:
    def test_stop_sets_state_inactive(self):
        now = datetime.datetime.now(timezone.utc).isoformat()
        db.sentinel_update_state(SESSION, "active", last_check_time=now)
        _graceful_stop(SESSION)
        state = db.sentinel_get_state(SESSION)
        assert state["sentinel_status"] == "inactive"

    def test_stop_preserves_baseline(self):
        """Stopping Sentinel must not delete baseline entries."""
        import uuid
        asset_id = str(uuid.uuid4())
        db.sentinel_save_asset(SESSION, asset_id, "192.168.1.10", "2026-01-01T00:00:00+00:00")
        db.sentinel_save_baseline_entry(
            network_id=SESSION,
            entry_id=str(uuid.uuid4()),
            asset_id=asset_id,
            target_network="192.168.1.0/24",
            gateway_ip="192.168.1.1",
            gateway_mac="aa:aa:aa:aa:aa:aa",
            ports=[22],
            mac=None,
            last_scan="2026-01-01T00:00:00+00:00",
        )
        _graceful_stop(SESSION)
        assert db.sentinel_baseline_exists(SESSION, "192.168.1.0/24", "192.168.1.1", "aa:aa:aa:aa:aa:aa")

    def test_stop_preserves_events(self):
        """Stopping Sentinel must not delete event history."""
        import uuid
        db.sentinel_save_event(
            network_id=SESSION,
            event_id=str(uuid.uuid4()),
            event_type="new_host",
            timestamp=datetime.datetime.now(timezone.utc).isoformat(),
            asset_id=None,
            details={"ip": "192.168.1.99"},
            resolved=False,
        )
        _graceful_stop(SESSION)
        events = db.sentinel_get_events(SESSION)
        assert len(events) == 1


# ---------------------------------------------------------------------------
# last_check_time — only on success
# ---------------------------------------------------------------------------

class TestLastCheckTime:
    def test_last_check_time_set_on_success(self):
        now = datetime.datetime.now(timezone.utc).isoformat()
        db.sentinel_update_state(SESSION, "active", last_check_time=now)
        state = db.sentinel_get_state(SESSION)
        assert state["last_check_time"] == now

    def test_last_check_time_not_updated_on_failure(self):
        """Simulates a failed check by not passing last_check_time."""
        initial = (datetime.datetime.now(timezone.utc) - datetime.timedelta(seconds=30)).isoformat()
        db.sentinel_update_state(SESSION, "active", last_check_time=initial)
        # Failed check: update state only, no last_check_time
        db.sentinel_update_state(SESSION, "degraded", last_check_time=None)
        state = db.sentinel_get_state(SESSION)
        assert state["last_check_time"] == initial
        assert state["sentinel_status"] == "degraded"


def _state():
    return NetworkState(
        stamp=EventStamp(SESSION), known_hosts=set(), initial_ports={}, ports_initialized={},
        open_ports={}, port_absent_count={}, notified_port_not_open={}, host_absent_count={},
        host_not_observed=set(), target_network="192.168.1.0/24",
    )


def _observations(changes=(), services_degraded=False):
    return CycleObservations(current_hosts=[], ping_hosts=[], host_arp_status={}, tcp_observations={},
                             candidate_changes=list(changes), ping_failed=False,
                             services_degraded=services_degraded)


class TestDegradedArpCheck:
    def test_degraded_check_processes_changes_without_updating_last_check(self):
        initial = (datetime.datetime.now(timezone.utc) - datetime.timedelta(seconds=30)).isoformat()
        db.sentinel_update_state(SESSION, "active", last_check_time=initial)
        change = NetworkChange("mac_change", "192.168.1.10", "mac changed", "active ARP")
        whitelist = Whitelist()

        with patch("sentinel.sentinel_manager.get_baseline", return_value={"ip": object()}), \
             patch(
                 "sentinel.sentinel_manager.check_network",
                 side_effect=ScanDegradedError("partial", _observations([change], services_degraded=True)),
             ), \
             patch("sentinel.sentinel_manager.process_changes") as process_changes, \
             patch("sentinel.sentinel_manager.sentinel_update_state") as update_state:
            _do_check(
                target_network="192.168.1.0/24",
                network_id=SESSION,
                run_session_id="run-manager-distinct",
                identity=object(),
                interval=60,
                whitelist=whitelist,
                counter=AlertCounter(),
                state=_state(),
            )

        # One batch: the transition, then the scan_degraded episode event (§9.14).
        process_changes.assert_called_once()
        batch = [c.change_type for c in process_changes.call_args.kwargs["changes"]]
        assert batch == ["mac_change", "scan_degraded"]
        assert update_state.call_args.kwargs["sentinel_status"] == "degraded"
        assert "last_check_time" not in update_state.call_args.kwargs

    def test_ping_success_tcp_failure_keeps_last_check_time(self):
        initial = (datetime.datetime.now(timezone.utc) - datetime.timedelta(seconds=30)).isoformat()
        db.sentinel_update_state(SESSION, "active", last_check_time=initial)
        baseline = {
            "192.168.1.10": BaselineEntry(
                asset_id="a1",
                ip="192.168.1.10",
                mac="",
                ports=[22],
                last_scan="2026-01-01T00:00:00+00:00",
            )
        }

        with patch("sentinel.sentinel_manager.get_baseline", return_value=baseline), \
             patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
             patch("sentinel.monitor._get_arp_mac", return_value=""), \
             patch("sentinel.monitor._get_open_ports", return_value=None), \
             patch("sentinel.sentinel_manager.process_changes") as process_changes:
            _do_check(
                target_network="192.168.1.0/24",
                network_id=SESSION,
                run_session_id="run-manager-distinct",
                identity=object(),
                interval=60,
                whitelist=Whitelist(),
                counter=AlertCounter(),
                state=_state(),
            )

        state = db.sentinel_get_state(SESSION)
        assert state["sentinel_status"] == "degraded"
        assert state["last_check_time"] == initial
        # T23-B §9.2/§9.14: the degraded episode is recorded, and only that (no host or port change).
        process_changes.assert_called_once()
        batch = process_changes.call_args.kwargs["changes"]
        assert [c.change_type for c in batch] == ["scan_degraded"]
        assert batch[0].asset_ip == "192.168.1.0/24"  # B3: network scope


# ---------------------------------------------------------------------------
# T23-B step 5 — transitions, reconstruction, episodes, B1, B3 (§9.5–§9.14)
# ---------------------------------------------------------------------------

HOST = "192.168.1.10"
NET_CIDR = "192.168.1.0/24"
# `ip route get` outputs (local table only): direct L2 on the monitored segment, routed, no route.
ROUTE_L2 = "192.168.1.10 dev eth0 src 192.168.1.5 uid 0\n"
ROUTE_VIA = "192.168.1.10 via 192.168.1.1 dev eth0 src 192.168.1.5 uid 0\n"


def _cycle(current=(), tcp=None, arp=None, candidates=(), degraded=False):
    """Observations for one cycle; every current host carries a TCP observation (§9.3)."""
    tcp = tcp or {}
    return CycleObservations(
        current_hosts=list(current),
        ping_hosts=list(current),
        host_arp_status=dict(arp or {}),
        tcp_observations={ip: HostTcpObservation(ip, tcp.get(ip)) for ip in current},
        candidate_changes=list(candidates),
        ping_failed=False,
        services_degraded=degraded,
    )


def _new_host(ip=HOST, ports=None):
    if ports is None:
        return NetworkChange("new_host", ip, "new host detected", "test")
    return NetworkChange("new_host", ip, "new host detected", "test",
                         initial_ports=list(ports), initial_ports_known=True)


def _st(known=(), ports_initialized=None, open_ports=None):
    """Transition state for NET_CIDR, with the given known hosts and their memory."""
    state = NetworkState(
        stamp=EventStamp(SESSION), known_hosts=set(known), initial_ports={}, ports_initialized={},
        open_ports={}, port_absent_count={}, notified_port_not_open={}, host_absent_count={},
        host_not_observed=set(), target_network=NET_CIDR,
    )
    for ip, ports in (ports_initialized or {}).items():
        state.ports_initialized[ip] = True
        state.initial_ports[ip] = list(ports)
        state.open_ports[ip] = set(ports)
    for ip, ports in (open_ports or {}).items():
        state.open_ports[ip] = set(ports)
    return state


def _types(changes):
    return [c.change_type for c in changes]


class TestTransitions:
    """Pure transitions of _normalize_and_filter (§9.5, §9.6, §9.7)."""

    def test_new_host_with_complete_scan_is_announced_and_initialized_once(self):
        state = _st()
        first = _normalize_and_filter(_cycle([HOST], {HOST: [22]}, candidates=[_new_host(HOST, [22])]), state)
        assert _types(first) == ["new_host", "host_ports_initialized"]
        assert first[1].initial_ports == [22]
        assert state.open_ports[HOST] == {22}
        # Same host seen again (anti-répétition, initialisation déjà faite): nothing new.
        again = _normalize_and_filter(_cycle([HOST], {HOST: [22]}, candidates=[_new_host(HOST, [22])]), state)
        assert again == []

    def test_unknown_ports_then_first_complete_scan_initializes_without_fake_new_port(self):
        state = _st()
        first = _normalize_and_filter(_cycle([HOST], {HOST: None}, candidates=[_new_host(HOST)]), state)
        assert _types(first) == ["new_host"]  # no ports known: no initialization, no new_port
        assert state.ports_initialized[HOST] is False
        second = _normalize_and_filter(_cycle([HOST], {HOST: [22, 80]}), state)
        # §9.5 step 2: one initialization, and the ports already open are not new_port (criterion 18).
        assert _types(second) == ["host_ports_initialized"]
        assert second[0].initial_ports == [22, 80]
        assert _normalize_and_filter(_cycle([HOST], {HOST: [22, 80]}), state) == []

    def test_new_port_is_announced_once_per_opening(self):
        state = _st({HOST}, ports_initialized={HOST: [22]})
        opened = _normalize_and_filter(_cycle([HOST], {HOST: [22, 8080]}), state)
        assert _types(opened) == ["new_port"]
        assert opened[0].port == 8080
        assert _normalize_and_filter(_cycle([HOST], {HOST: [22, 8080]}), state) == []

    def test_port_not_open_after_two_complete_scans_then_never_repeated(self):
        state = _st({HOST}, ports_initialized={HOST: [22, 80]})
        assert _normalize_and_filter(_cycle([HOST], {HOST: [22]}), state) == []  # first absence
        closed = _normalize_and_filter(_cycle([HOST], {HOST: [22]}), state)     # second absence
        assert _types(closed) == ["port_not_open"]
        assert closed[0].port == 80
        assert state.port_absent_count[HOST][80] == 0  # reset at two (criterion 6)
        for _ in range(3):  # still absent: no re-emission (criterion 7)
            assert _normalize_and_filter(_cycle([HOST], {HOST: [22]}), state) == []
        assert state.port_absent_count[HOST][80] < 2

    def test_reopened_port_is_a_new_opening_and_can_close_again(self):
        state = _st({HOST}, ports_initialized={HOST: [22, 80]})
        for _ in range(2):
            _normalize_and_filter(_cycle([HOST], {HOST: [22]}), state)
        back = _normalize_and_filter(_cycle([HOST], {HOST: [22, 80]}), state)
        assert _types(back) == ["new_port"] and back[0].port == 80
        closed_again = [_normalize_and_filter(_cycle([HOST], {HOST: [22]}), state) for _ in range(2)]
        assert closed_again[0] == []
        assert _types(closed_again[1]) == ["port_not_open"] and closed_again[1][0].port == 80

    def test_unknown_tcp_observation_restarts_the_absence_count(self):
        state = _st({HOST}, ports_initialized={HOST: [22, 80]})
        assert _normalize_and_filter(_cycle([HOST], {HOST: [22]}), state) == []
        assert _normalize_and_filter(_cycle([HOST], {HOST: None}), state) == []  # no conclusion
        assert _normalize_and_filter(_cycle([HOST], {HOST: [22]}), state) == []  # count restarted at 1
        assert _types(_normalize_and_filter(_cycle([HOST], {HOST: [22]}), state)) == ["port_not_open"]

    def test_host_not_observed_after_two_reliable_l2_cycles_only(self, monkeypatch):
        monkeypatch.setattr(sm, "_route_output", lambda ip: ROUTE_L2)
        state = _st({HOST}, ports_initialized={HOST: [22]})
        absent = _cycle([], arp={HOST: ArpProbeStatus.NOT_OBSERVED})
        assert _normalize_and_filter(absent, state) == []
        second = _normalize_and_filter(absent, state)
        assert _types(second) == ["host_not_observed"]
        assert second[0].asset_ip == HOST
        assert _normalize_and_filter(absent, state) == []  # not repeated while still absent
        assert HOST in state.host_not_observed

    def test_host_not_observed_never_from_icmp_only_silence(self, monkeypatch):
        monkeypatch.setattr(sm, "_route_output", lambda ip: ROUTE_L2)
        state = _st({HOST}, ports_initialized={HOST: [22]})
        for _ in range(3):  # no ARP probe for this host: ping silence alone is not an absence
            assert _normalize_and_filter(_cycle([], arp={}), state) == []
        assert HOST not in state.host_not_observed

    def test_host_not_observed_never_for_a_routed_host(self, monkeypatch):
        monkeypatch.setattr(sm, "_route_output", lambda ip: ROUTE_VIA)
        state = _st({HOST}, ports_initialized={HOST: [22]})
        for _ in range(3):
            assert _normalize_and_filter(_cycle([], arp={HOST: ArpProbeStatus.NOT_OBSERVED}), state) == []

    def test_host_not_observed_never_when_the_route_is_unknown(self, monkeypatch):
        monkeypatch.setattr(sm, "_route_output", lambda ip: None)
        state = _st({HOST}, ports_initialized={HOST: [22]})
        for _ in range(3):
            assert _normalize_and_filter(_cycle([], arp={HOST: ArpProbeStatus.NOT_OBSERVED}), state) == []

    def test_error_status_resets_the_absence_count(self, monkeypatch):
        monkeypatch.setattr(sm, "_route_output", lambda ip: ROUTE_L2)
        state = _st({HOST}, ports_initialized={HOST: [22]})
        sequence = [ArpProbeStatus.NOT_OBSERVED, ArpProbeStatus.ERROR,
                    ArpProbeStatus.NOT_OBSERVED, ArpProbeStatus.NOT_OBSERVED]
        results = [_types(_normalize_and_filter(_cycle([], arp={HOST: status_}), state)) for status_ in sequence]
        # The ERROR cycle is no conclusion: the next NOT_OBSERVED starts again at one (criterion 15).
        assert results == [[], [], [], ["host_not_observed"]]

    def test_host_recovered_when_it_answers_again(self, monkeypatch):
        monkeypatch.setattr(sm, "_route_output", lambda ip: ROUTE_L2)
        state = _st({HOST}, ports_initialized={HOST: [22]})
        for _ in range(2):
            _normalize_and_filter(_cycle([], arp={HOST: ArpProbeStatus.NOT_OBSERVED}), state)
        back = _normalize_and_filter(_cycle([HOST], {HOST: [22]}), state)
        assert _types(back) == ["host_recovered"]
        assert HOST not in state.host_not_observed
        assert _normalize_and_filter(_cycle([HOST], {HOST: [22]}), state) == []

    def test_mac_change_is_passed_through_unchanged(self):
        state = _st({HOST}, ports_initialized={HOST: [22]})
        change = NetworkChange("mac_change", HOST, "mac changed", "test")
        assert _normalize_and_filter(_cycle([HOST], {HOST: [22]}, candidates=[change]), state) == [change]


def _save_event(event_type, timestamp, ip, details=None):
    body = {"ip": ip, **(details or {})}
    db.sentinel_save_event(SESSION, uuid.uuid4().hex, event_type, timestamp, None, body, resolved=True)


class TestReconstruction:
    """Rebuild from the stored history (§9.8, §9.13, B1): no repetition, no false new_port."""

    def test_replayed_history_is_not_announced_again(self):
        _save_event("new_host", "2026-10-10T12:00:00.000001+00:00", HOST,
                    {"initial_ports": [22], "initial_ports_known": True})
        _save_event("host_ports_initialized", "2026-10-10T12:00:00.000002+00:00", HOST, {"initial_ports": [22]})
        _save_event("new_port", "2026-10-10T12:00:00.000003+00:00", HOST, {"port": 8080})
        state = _rebuild_transition_state(SESSION, {})
        assert state is not None
        assert HOST in state.known_hosts
        assert state.ports_initialized[HOST] is True
        assert state.open_ports[HOST] == {22, 8080}
        # The same host and the same ports after a restart: nothing is announced again.
        candidate = _new_host(HOST, [22, 8080])
        assert _normalize_and_filter(_cycle([HOST], {HOST: [22, 8080]}, candidates=[candidate]), state) == []

    def test_baseline_hosts_start_with_their_ports_and_no_false_new_port(self):
        baseline = {HOST: BaselineEntry(asset_id="a", ip=HOST, mac="", ports=[22],
                                        last_scan="2026-01-01T00:00:00+00:00")}
        state = _rebuild_transition_state(SESSION, baseline)
        assert state.ports_initialized[HOST] is True and state.open_ports[HOST] == {22}
        assert _normalize_and_filter(_cycle([HOST], {HOST: [22]}), state) == []
        assert _types(_normalize_and_filter(_cycle([HOST], {HOST: [22, 80]}), state)) == ["new_port"]

    def test_restored_stamp_is_the_latest_instant_not_the_latest_string(self):
        # 13:00+02:00 is 11:00 UTC; 12:00+00:00 is the latest instant. A string sort would pick the first.
        _save_event("new_host", "2026-10-10T13:00:00+02:00", "192.168.1.20")
        _save_event("new_host", "2026-10-10T12:00:00+00:00", "192.168.1.21")
        state = _rebuild_transition_state(SESSION, {})
        assert state.stamp.last == datetime.datetime(2026, 10, 10, 12, tzinfo=timezone.utc)

    def test_unreadable_history_returns_none(self, monkeypatch):
        def unreadable(network_id):
            raise OSError("simulated unreadable history")
        monkeypatch.setattr(db, "sentinel_network_snapshot", unreadable)
        assert _rebuild_transition_state(SESSION, {}) is None


class TestEpisodesAndCounters:
    """_do_check outcomes: scan_degraded per episode, ScanFailedError, network scope (§9.14, B3)."""

    @pytest.fixture
    def cycle(self, monkeypatch):
        monkeypatch.setattr(sm, "get_baseline", lambda *args: {HOST: BaselineEntry(
            asset_id="a", ip=HOST, mac="", ports=[22], last_scan="2026-01-01T00:00:00+00:00")})
        db.sentinel_update_state(SESSION, "active")

        def run(state, counter, outcome):
            monkeypatch.setattr(sm, "check_network", Mock(side_effect=[outcome]))
            _do_check(target_network=NET_CIDR, network_id=SESSION, run_session_id="run-episodes",
                      identity=object(), interval=60, whitelist=Whitelist(), counter=counter, state=state)
        return run

    def _degraded_events(self):
        return [e for e in db.sentinel_get_events(SESSION) if e["type"] == "scan_degraded"]

    def test_scan_degraded_once_per_episode_and_scoped_to_the_network(self, cycle):
        state, counter = _st({HOST}, ports_initialized={HOST: [22]}), AlertCounter()
        counter.bind(SESSION)
        partial = ScanDegradedError("simulated partial", _cycle([HOST], {HOST: None}, degraded=True))
        cycle(state, counter, partial)  # episode 1 starts
        cycle(state, counter, partial)  # same episode: no new event
        cycle(state, counter, _cycle([HOST], {HOST: [22]}))  # clean cycle ends the episode
        cycle(state, counter, partial)  # episode 2
        events = self._degraded_events()
        assert len(events) == 2
        for event in events:
            assert event["asset_id"] is None  # B3: no fake asset
            assert event["details"]["ip"] == NET_CIDR  # B3: network scope
        assert state.scan_degraded_active is True

    def test_scan_failed_resets_counters_and_records_one_episode_only(self, cycle):
        state, counter = _st({HOST}, ports_initialized={HOST: [22]}), AlertCounter()
        counter.bind(SESSION)
        state.host_absent_count[HOST] = 1
        state.port_absent_count[HOST] = {22: 1}
        cycle(state, counter, ScanFailedError("total absence"))
        cycle(state, counter, ScanFailedError("total absence again"))
        assert len(self._degraded_events()) == 1
        assert state.host_absent_count == {} and state.port_absent_count == {}
        types = [e["type"] for e in db.sentinel_get_events(SESSION)]
        assert types == ["scan_degraded"]  # no host or port conclusion during an absolute failure

    def test_network_quota_applies_across_degraded_episodes(self, cycle):
        # B3: the quota of scan_degraded is the network's. Four episodes: three confirmed, one masked.
        state, counter = _st({HOST}, ports_initialized={HOST: [22]}), AlertCounter()
        counter.bind(SESSION)
        partial = ScanDegradedError("simulated partial", _cycle([HOST], {HOST: None}, degraded=True))
        clean = _cycle([HOST], {HOST: [22]})
        for outcome in (partial, clean, partial, clean, partial, clean, partial):
            cycle(state, counter, outcome)
        events = sorted(self._degraded_events(), key=lambda e: e["timestamp"])
        assert [e["details"]["notification"]["state"] for e in events] == [
            "confirmed", "confirmed", "confirmed", "masked"]
