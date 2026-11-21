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
from unittest.mock import MagicMock, Mock, patch
from datetime import timezone

import core.database as db
import sentinel.sentinel_manager as sm
from sentinel.sentinel_manager import (
    NetworkState,
    status,
    display_status,
    stop,
    _compute_display_state,
    _graceful_stop,
    _do_check,
    _normalize_and_filter,
    _rebuild_transition_state,
    _compute_port_transitions,
)
from sentinel.alerting import AlertCounter, EventStamp
from sentinel.arp_probe import ArpProbeStatus
from sentinel.baseline import BaselineEntry, NetworkIdentity
from sentinel.monitor import (
    CycleObservations,
    HostTcpObservation,
    NetworkChange,
    ScanDegradedError,
    ScanFailedError,
)
from detect.tcp_scan import PortState as TcpPortState
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
        get_counts.assert_called_once_with(
            SESSION, "192.168.1.0/24", "", "", deferred_ips=[]
        )
        assert result["network_id"] == SESSION
        assert (result["known_hosts"], result["active_hosts"]) == (0, 0)
        assert result["initialized_hosts"] == 0
        assert result["deferred_hosts"] == 0
        assert result["absent_hosts"] == 0
        assert result["host_inventory"] == []


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
             patch("sentinel.monitor._get_host_tcp_observation", return_value=HostTcpObservation(ip=HOST, ports=None)), \
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
# Deferred host initialization (Issue B) — partial baseline, degraded start, recovery
# ---------------------------------------------------------------------------

def _deferred_state(deferred):
    """NetworkState: a deferred host is known but not initialized."""
    return NetworkState(
        stamp=EventStamp(SESSION),
        known_hosts=set(deferred),
        initial_ports={ip: None for ip in deferred},
        ports_initialized={ip: False for ip in deferred},
        open_ports={ip: set() for ip in deferred},
        port_absent_count={},
        notified_port_not_open={},
        host_absent_count={},
        host_not_observed=set(),
        deferred_initialization=set(deferred),
        target_network=NET_CIDR,
    )


class TestDeferredInitialization:
    def test_deferred_host_not_observed_keeps_degraded_and_no_last_check(self, monkeypatch):
        """A known deferred host that is absent does not advance last_check_time."""
        initial = (datetime.datetime.now(timezone.utc) - datetime.timedelta(seconds=30)).isoformat()
        db.sentinel_update_state(SESSION, "active", last_check_time=initial)
        state = _deferred_state({HOST})
        baseline = {
            HOST: BaselineEntry(asset_id="a1", ip=HOST, mac="", ports=[22], last_scan="2026-01-01T00:00:00+00:00"),
        }

        with patch("sentinel.sentinel_manager.get_baseline", return_value=baseline), \
             patch("sentinel.sentinel_manager.check_network", return_value=_cycle([], {})), \
             patch("sentinel.sentinel_manager.process_changes") as process_changes:
            _do_check(
                target_network=NET_CIDR, network_id=SESSION, run_session_id="run-deferred",
                identity=object(), interval=60, whitelist=Whitelist(), counter=AlertCounter(),
                state=state,
            )

        assert state.scan_degraded_active is False
        assert state.deferred_initialization == {HOST}
        state_db = db.sentinel_get_state(SESSION)
        assert state_db["sentinel_status"] == "degraded"
        assert state_db["last_check_time"] == initial
        assert process_changes.call_count == 0  # no host/port change for an un-scanned deferred host

    def test_deferred_host_first_complete_scan_persists_and_emits_once(self, monkeypatch):
        """Recovery: first complete scan → baseline persisted, then one init event."""
        state = _deferred_state({HOST})
        baseline = {
            HOST: BaselineEntry(asset_id="a1", ip=HOST, mac="", ports=[22], last_scan="2026-01-01T00:00:00+00:00"),
        }
        monkeypatch.setattr("sentinel.sentinel_manager.get_baseline", lambda *args, **kwargs: baseline)
        monkeypatch.setattr("sentinel.sentinel_manager.check_network", lambda *args, **kwargs: _cycle([HOST], {HOST: [22]}))
        store = Mock()
        monkeypatch.setattr("sentinel.sentinel_manager.store_recovered_host_baseline", store)
        process = Mock()
        monkeypatch.setattr("sentinel.sentinel_manager.process_changes", process)

        _do_check(
            target_network=NET_CIDR, network_id=SESSION, run_session_id="run-recover",
            identity=object(), interval=60, whitelist=Whitelist(), counter=AlertCounter(),
            state=state,
        )

        init_changes = [c for c in process.call_args.kwargs["changes"] if c.change_type == "host_ports_initialized"]
        assert len(init_changes) == 1
        assert init_changes[0].asset_ip == HOST
        assert init_changes[0].initial_ports == [22]
        # The deferred host gets its baseline written before the init event is processed.
        assert store.call_count == 1
        assert list(store.call_args.args[3]) == [22]
        assert state.ports_initialized[HOST] is True
        assert state.deferred_initialization == set()

    def test_healthy_host_is_monitored_while_another_host_stays_deferred(self, monkeypatch):
        """Usable hosts keep producing findings while a deferred host remains UNKNOWN."""
        state = _st({HOST}, ports_initialized={HOST: [22]})
        state.deferred_initialization = {"192.168.1.99"}
        baseline = {
            HOST: BaselineEntry(asset_id="a1", ip=HOST, mac="", ports=[22], last_scan="2026-01-01T00:00:00+00:00"),
        }
        monkeypatch.setattr("sentinel.sentinel_manager.get_baseline", lambda *args, **kwargs: baseline)
        monkeypatch.setattr("sentinel.sentinel_manager.check_network", lambda *args, **kwargs: _cycle([HOST], {HOST: [22, 80]}))
        store = Mock()
        monkeypatch.setattr("sentinel.sentinel_manager.store_recovered_host_baseline", store)
        process = Mock()
        monkeypatch.setattr("sentinel.sentinel_manager.process_changes", process)

        _do_check(
            target_network=NET_CIDR, network_id=SESSION, run_session_id="run-mixed",
            identity=object(), interval=60, whitelist=Whitelist(), counter=AlertCounter(),
            state=state,
        )

        assert [c.change_type for c in process.call_args.kwargs["changes"]] == ["new_port"]
        assert store.call_count == 0  # the healthy host was not deferred
        state_db = db.sentinel_get_state(SESSION)
        assert state_db["sentinel_status"] == "degraded"  # the deferred host keeps the network degraded

    def test_unknown_scan_never_initializes_ports(self):
        """Invalid or incomplete scans never store or emit a port initialization."""
        change = _new_host(HOST, None)
        state = _st()
        changes = _normalize_and_filter(_cycle([HOST], {HOST: None}, candidates=[change]), state)
        assert _types(changes) == ["new_host"]
        assert state.ports_initialized[HOST] is False
        assert state.initial_ports[HOST] is None


class TestStartAfterPartialBaseline:
    def test_partial_baseline_start_is_degraded_until_recovery(self, monkeypatch):
        """Case 2: usable peers stored, a failed host deferred → Sentinel starts degraded."""
        monkeypatch.setattr(sm, "baseline_exists", lambda *args: True)
        monkeypatch.setattr(sm, "get_baseline", lambda *args, **kwargs: {
            HOST: BaselineEntry(asset_id="a1", ip=HOST, mac="", ports=[22], last_scan="2026-01-01T00:00:00+00:00"),
        })
        monkeypatch.setattr(sm, "_rebuild_transition_state", lambda network_id, baseline: _deferred_state({HOST}))
        update = Mock()
        monkeypatch.setattr(sm, "sentinel_update_state", update)
        monkeypatch.setattr(sm, "load_whitelist", lambda: Whitelist())
        monkeypatch.setattr(sm, "learn_baseline", Mock(return_value=True))
        monkeypatch.setattr(sm, "_run_loop", Mock())
        monkeypatch.setattr(sm, "AlertCounter", MagicMock())
        monkeypatch.setattr(sm, "MonitorView", MagicMock())
        monkeypatch.setattr(sm.typer, "confirm", Mock(return_value=True))

        sm._start_owned(
            "192.168.1.0/24", "netid-deferred", "run-deferred",
            NetworkIdentity("192.168.1.0/24", "192.168.1.1", "aa:aa:aa:aa:aa:aa"), 60,
            force_relearn=True, owner=Mock(),
        )

        update.assert_called_once()
        assert update.call_args.kwargs["sentinel_status"] == "degraded"


# ---------------------------------------------------------------------------
# T23-B step 5 — transitions, reconstruction, episodes, B1, B3 (§9.5–§9.14)
# ---------------------------------------------------------------------------

HOST = "192.168.1.10"
PEER = "192.168.1.11"
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


# ---------------------------------------------------------------------------
# A1 / TCP-02 — state-aware port transitions
# ---------------------------------------------------------------------------

def _tcp_obs(ip, ports, states=None):
    """Create a HostTcpObservation with optional per-port states."""
    return HostTcpObservation(ip=ip, ports=ports, states=states)

def _state_a1(known=(), init=None, open_ports=None):
    """NetworkState for A1 tests — host initialized with known open ports."""
    state = NetworkState(
        stamp=EventStamp(SESSION), known_hosts=set(known), initial_ports={},
        ports_initialized={}, open_ports={}, port_absent_count={},
        notified_port_not_open={}, host_absent_count={}, host_not_observed=set(),
        target_network=NET_CIDR,
    )
    if init:
        for ip, ports in init.items():
            state.ports_initialized[ip] = True
            state.initial_ports[ip] = list(ports)
            state.open_ports[ip] = set(ports)
    if open_ports:
        for ip, ports in open_ports.items():
            state.open_ports[ip] = set(ports)
    return state

def _cycle_a1(current=(), tcp=None, arp=None, candidates=(), degraded=False):
    tcp = tcp or {}
    return CycleObservations(
        current_hosts=list(current),
        ping_hosts=list(current),
        host_arp_status=dict(arp or {}),
        tcp_observations=dict(tcp),
        candidate_changes=list(candidates),
        ping_failed=False,
        services_degraded=degraded,
    )

class TestA1PortTransitions:
    """TCP-02: state-aware port transitions."""

    def test_two_consecutive_closed_produces_port_not_open(self):
        """S1: closed x2 -> port_not_open event."""
        ip = "10.0.0.1"
        state = _state_a1(known={ip}, init={ip: [80]}, open_ports={ip: {80}})
        # Cycle 1: port 80 is CLOSED
        c1 = _cycle_a1(current={ip}, tcp={ip: _tcp_obs(ip, [], states={80: TcpPortState.CLOSED})})
        from sentinel.sentinel_manager import _compute_port_transitions
        changes1 = _compute_port_transitions(c1, state)
        assert changes1 == []  # only one closed observation, no event yet
        # Cycle 2: port 80 is CLOSED again
        c2 = _cycle_a1(current={ip}, tcp={ip: _tcp_obs(ip, [], states={80: TcpPortState.CLOSED})})
        changes2 = _compute_port_transitions(c2, state)
        assert len(changes2) == 1
        assert changes2[0].change_type == "port_not_open"
        assert changes2[0].port == 80

    def test_closed_then_filtered_no_closure(self):
        """S7: closed -> filtered -> no port_not_open event."""
        ip = "10.0.0.2"
        state = _state_a1(known={ip}, init={ip: [80]}, open_ports={ip: {80}})
        # Cycle 1: CLOSED
        c1 = _cycle_a1(current={ip}, tcp={ip: _tcp_obs(ip, [], states={80: TcpPortState.CLOSED})})
        _compute_port_transitions(c1, state)
        # Cycle 2: FILTERED -> resets counter
        c2 = _cycle_a1(current={ip}, tcp={ip: _tcp_obs(ip, [], states={80: TcpPortState.FILTERED})})
        changes2 = _compute_port_transitions(c2, state)
        assert changes2 == []  # no closure event
        assert state.port_absent_count[ip].get(80, 0) == 0  # counter reset

    def test_two_filtered_no_closure(self):
        """Two consecutive FILTERED observations must NOT produce port_not_open."""
        ip = "10.0.0.3"
        state = _state_a1(known={ip}, init={ip: [80]}, open_ports={ip: {80}})
        c1 = _cycle_a1(current={ip}, tcp={ip: _tcp_obs(ip, [], states={80: TcpPortState.FILTERED})})
        _compute_port_transitions(c1, state)
        c2 = _cycle_a1(current={ip}, tcp={ip: _tcp_obs(ip, [], states={80: TcpPortState.FILTERED})})
        changes2 = _compute_port_transitions(c2, state)
        assert changes2 == []

    def test_open_filtered_uncertain_no_closure(self):
        """S8: open|filtered -> UNCERTAIN -> no closure."""
        ip = "10.0.0.4"
        state = _state_a1(known={ip}, init={ip: [80]}, open_ports={ip: {80}})
        c1 = _cycle_a1(current={ip}, tcp={ip: _tcp_obs(ip, [], states={80: TcpPortState.UNCERTAIN})})
        changes = _compute_port_transitions(c1, state)
        assert changes == []
        assert state.port_absent_count[ip].get(80, 0) == 0

    def test_host_fully_filtered_no_mass_closure(self):
        """S11: all ports filtered -> no port_not_open events."""
        ip = "10.0.0.5"
        state = _state_a1(known={ip}, init={ip: [22, 80, 443]}, open_ports={ip: {22, 80, 443}})
        states = {p: TcpPortState.FILTERED for p in [22, 80, 443]}
        c1 = _cycle_a1(current={ip}, tcp={ip: _tcp_obs(ip, [], states=states)})
        changes = _compute_port_transitions(c1, state)
        assert changes == []  # no mass closure

    def test_host_absent_resets_counters(self):
        """S5: host absent from one cycle -> counters reset; reappearance needs 2 closed."""
        ip = "10.0.0.6"
        state = _state_a1(known={ip}, init={ip: [80]}, open_ports={ip: {80}})
        # Cycle 1: CLOSED (counter = 1)
        c1 = _cycle_a1(current={ip}, tcp={ip: _tcp_obs(ip, [], states={80: TcpPortState.CLOSED})})
        _compute_port_transitions(c1, state)
        assert state.port_absent_count[ip].get(80, 0) == 1
        # Cycle 2: host absent -> counters cleared
        c2 = _cycle_a1(current=set())
        _compute_port_transitions(c2, state)
        assert state.port_absent_count.get(ip, {}).get(80, 0) == 0
        # Cycle 3: CLOSED (counter = 1, not 2)
        c3 = _cycle_a1(current={ip}, tcp={ip: _tcp_obs(ip, [], states={80: TcpPortState.CLOSED})})
        changes3 = _compute_port_transitions(c3, state)
        assert changes3 == []  # only 1 observation after reset

    def test_reopen_resets_counter_and_notification(self):
        """Port reopens before two closed -> no port_not_open; notification cleared."""
        ip = "10.0.0.7"
        state = _state_a1(known={ip}, init={ip: [80]}, open_ports={ip: {80}})
        # Cycle 1: CLOSED
        c1 = _cycle_a1(current={ip}, tcp={ip: _tcp_obs(ip, [], states={80: TcpPortState.CLOSED})})
        _compute_port_transitions(c1, state)
        # Cycle 2: OPEN again -> counter reset, no closure
        c2 = _cycle_a1(current={ip}, tcp={ip: _tcp_obs(ip, [80], states={80: TcpPortState.OPEN})})
        changes2 = _compute_port_transitions(c2, state)
        assert changes2 == []  # no port_not_open
        assert state.port_absent_count[ip].get(80, 0) == 0

    def test_new_port_emitted_on_open(self):
        """New OPEN port produces new_port event."""
        ip = "10.0.0.8"
        state = _state_a1(known={ip}, init={ip: [22]}, open_ports={ip: {22}})
        c1 = _cycle_a1(current={ip}, tcp={ip: _tcp_obs(ip, [22, 80], states={22: TcpPortState.OPEN, 80: TcpPortState.OPEN})})
        changes = _compute_port_transitions(c1, state)
        new_ports = [c for c in changes if c.change_type == "new_port"]
        assert len(new_ports) == 1
        assert new_ports[0].port == 80

    def test_incomplete_scan_resets_counters(self):
        """INCOMPLETE observation (ports=None) -> reset all counters."""
        ip = "10.0.0.9"
        state = _state_a1(known={ip}, init={ip: [80]}, open_ports={ip: {80}})
        # Cycle 1: CLOSED (counter = 1)
        c1 = _cycle_a1(current={ip}, tcp={ip: _tcp_obs(ip, [], states={80: TcpPortState.CLOSED})})
        _compute_port_transitions(c1, state)
        assert state.port_absent_count[ip].get(80, 0) == 1
        # Cycle 2: INCOMPLETE
        c2 = _cycle_a1(current={ip}, tcp={ip: _tcp_obs(ip, None)})
        _compute_port_transitions(c2, state)
        assert state.port_absent_count.get(ip, {}).get(80, 0) == 0

    def test_two_incomplete_observations_never_produce_a_false_closure(self):
        """Issue A: unknown scans are never read as closed → no port_not_open, ever."""
        ip = "10.0.0.19"
        state = _state_a1(known={ip}, init={ip: [80]}, open_ports={ip: {80}})
        first = _cycle_a1(current={ip}, tcp={ip: _tcp_obs(ip, None)})
        second = _cycle_a1(current={ip}, tcp={ip: _tcp_obs(ip, None)})
        assert _compute_port_transitions(first, state) == []
        assert _compute_port_transitions(second, state) == []
        assert state.open_ports[ip] == {80}

    def test_legacy_path_still_works_without_states(self):
        """Backward compatibility: HostTcpObservation without states field uses legacy path."""
        ip = "10.0.0.10"
        state = _state_a1(known={ip}, init={ip: [80]}, open_ports={ip: {80}})
        # Legacy: no states, only ports list
        c1 = _cycle_a1(current={ip}, tcp={ip: _tcp_obs(ip, [])})
        changes1 = _compute_port_transitions(c1, state)
        assert changes1 == []  # one absent observation
        c2 = _cycle_a1(current={ip}, tcp={ip: _tcp_obs(ip, [])})
        changes2 = _compute_port_transitions(c2, state)
        assert len(changes2) == 1
        assert changes2[0].change_type == "port_not_open"


# ---------------------------------------------------------------------------
# R1-R4 regression tests — Arena review corrections
# ---------------------------------------------------------------------------

class TestR1DeferredHostVisibility:
    """R1: deferred, initialized and historical hosts are exposed separately."""

    GW = "192.168.1.1"
    MAC = "aa:bb:cc:dd:ee:ff"
    NOW = "2026-11-01T12:00:00+00:00"

    def _state(self, sentinel_status="degraded", last_check=None):
        db.sentinel_update_state(
            SESSION, sentinel_status, last_check_time=last_check,
            target_network=NET_CIDR, gateway_ip=self.GW, gateway_mac=self.MAC,
        )

    def _baseline(self, ip=HOST, ports=(22,)):
        asset_id = str(uuid.uuid4())
        db.sentinel_save_asset(SESSION, asset_id, ip, self.NOW)
        db.sentinel_save_baseline_entry(
            SESSION, str(uuid.uuid4()), asset_id, NET_CIDR,
            self.GW, self.MAC, list(ports), None, self.NOW,
        )
        return asset_id

    def _deferred_event(self, ips, cidr=NET_CIDR):
        db.sentinel_save_event(
            SESSION, str(uuid.uuid4()), "baseline_initialization", self.NOW,
            None,
            {"ip": cidr, "deferred_ips": list(ips), "successful_ips": [],
             "active_ips": [], "whitelisted": False,
             "notification": {"version": 1, "state": "whitelisted",
                              "decided_at": self.NOW}},
            resolved=True,
        )

    def test_status_exposes_deferred_host_as_unknown_degraded(self):
        self._state()
        self._deferred_event([HOST])
        result = status(SESSION)
        assert result["deferred_hosts"] == 1
        assert result["initialized_hosts"] == 0
        assert result["known_hosts"] == 1
        assert result["active_hosts"] == 0
        assert result["absent_hosts"] == 0
        assert {"ip": HOST, "state": "UNKNOWN / DEGRADED",
                "active": False} in result["host_inventory"]

    def test_legacy_baseline_without_initialization_event_is_not_deferred(self):
        """Old DBs have baseline rows but no baseline_initialization event."""
        self._state()
        self._baseline()
        result = status(SESSION)
        assert result["deferred_hosts"] == 0
        assert result["initialized_hosts"] == 1
        assert result["known_hosts"] == 1
        assert result["active_hosts"] == 1
        assert result["host_inventory"] == [
            {"ip": HOST, "state": "INITIALIZED", "active": True}
        ]

    def test_recovered_host_without_recovery_event_is_not_deferred(self):
        """A stale historical deferred_ips entry is reconciled with the baseline."""
        self._state()
        self._baseline()
        self._deferred_event([HOST])
        result = status(SESSION)
        assert result["deferred_hosts"] == 0
        assert result["initialized_hosts"] == 1
        assert {"ip": HOST, "state": "INITIALIZED",
                "active": True} in result["host_inventory"]

    def test_deferred_host_from_another_network_is_not_listed(self):
        self._state()
        self._deferred_event([HOST], cidr="10.0.0.0/24")
        result = status(SESSION)
        assert result["deferred_hosts"] == 0
        assert result["host_inventory"] == []

    def test_display_status_shows_deferred_ip_and_state(self, monkeypatch):
        self._state()
        self._deferred_event([HOST])
        shown = Mock()
        monkeypatch.setattr(sm, "display", shown)
        display_status(SESSION)
        text = " ".join(str(call.args[0]) for call in shown.call_args_list)
        assert HOST in text
        assert "UNKNOWN / DEGRADED" in text
        assert "différés: 1" in text

    def test_historical_absent_host_is_separate_from_initialized_hosts(self):
        self._state()
        self._baseline()
        db.sentinel_save_asset(
            SESSION, "retired-host", "192.168.1.99", self.NOW, active=False
        )
        db.sentinel_save_event(
            SESSION, "evt-retired", "new_port", self.NOW, "retired-host",
            {"ip": "192.168.1.99", "port": 80, "detail": "port 80 opened"},
            resolved=False,
        )
        result = status(SESSION)
        assert result["initialized_hosts"] == 1
        assert result["absent_hosts"] == 1
        assert result["known_hosts"] == 1
        assert {"ip": "192.168.1.99", "state": "ABSENT",
                "active": False} in result["host_inventory"]


class TestR2NoNetworkCidrPseudoHost:
    """R2: network-scoped events (ip is a CIDR) must not create pseudo-host rows."""

    def test_host_summary_skips_cidr_events(self):
        """R2: baseline_initialization events using CIDR as ip produce no host row."""
        import datetime
        from sentinel.notifications import host_summary
        now = datetime.datetime.now(datetime.timezone.utc)
        cidr_event = {
            "id": "ev-cidr",
            "timestamp": now.isoformat(),
            "type": "baseline_initialization",
            "details": {
                "ip": NET_CIDR,          # CIDR — must be skipped
                "detail": "baseline initialization",
                "whitelisted": False,
                "notification": {"version": 1, "state": "whitelisted",
                                 "decided_at": now.isoformat()},
            },
            "resolved": 1,
        }
        result = host_summary([cidr_event], now)
        assert NET_CIDR not in str(result), (
            "CIDR must not appear as a pseudo-host in host_summary"
        )
        assert len(result) == 0, (
            "host_summary must produce zero rows for a CIDR-only event list"
        )

    def test_host_summary_keeps_genuine_host_events(self):
        """R2: genuine host events still produce a row after the CIDR fix."""
        import datetime
        from sentinel.notifications import host_summary
        now = datetime.datetime.now(datetime.timezone.utc)
        host_event = {
            "id": "ev-host",
            "timestamp": now.isoformat(),
            "type": "new_port",
            "details": {
                "ip": HOST,              # real host IP — must be kept
                "detail": "port 80 opened",
                "whitelisted": False,
            },
            "resolved": 0,
        }
        result = host_summary([host_event], now)
        assert len(result) == 1, "genuine host event must produce exactly one row"

    def test_mixed_cidr_and_host_events(self):
        """R2: CIDR events filtered out; real host events retained."""
        import datetime
        from sentinel.notifications import host_summary
        now = datetime.datetime.now(datetime.timezone.utc)
        cidr_ev = {
            "id": "ev-cidr",
            "timestamp": now.isoformat(),
            "type": "baseline_initialization",
            "details": {"ip": NET_CIDR, "detail": "init",
                        "notification": {"version": 1, "state": "whitelisted",
                                         "decided_at": now.isoformat()},
                        "whitelisted": False},
            "resolved": 1,
        }
        host_ev = {
            "id": "ev-host",
            "timestamp": now.isoformat(),
            "type": "new_host",
            "details": {"ip": HOST, "detail": "new host", "whitelisted": False},
            "resolved": 0,
        }
        result = host_summary([cidr_ev, host_ev], now)
        from sentinel.notifications import host_key
        assert host_key(HOST) in result, "host event must remain"
        assert len(result) == 1, "CIDR must not add a row"


class TestR3AtomicRecovery:
    """R3: recovered baseline and host_ports_initialized event written atomically."""

    IDENTITY = NetworkIdentity(NET_CIDR, "192.168.1.1", "aa:bb:cc:dd:ee:ff")
    NOW = "2026-11-20T10:00:00+00:00"

    def _recovery_setup(self, monkeypatch):
        import sentinel.baseline as baseline_mod
        monkeypatch.setattr(baseline_mod, "_get_arp_mac", lambda ip: "")
        db.sentinel_update_state(
            SESSION, "degraded", target_network=NET_CIDR,
            gateway_ip=self.IDENTITY.gateway_ip,
            gateway_mac=self.IDENTITY.gateway_mac,
        )
        baseline = {
            PEER: BaselineEntry(asset_id="peer-asset", ip=PEER, mac="",
                                ports=[22], last_scan="2026-01-01T00:00:00+00:00"),
        }
        monkeypatch.setattr(sm, "get_baseline", lambda *a, **kw: baseline)
        monkeypatch.setattr(
            sm, "check_network",
            lambda *a, **kw: _cycle([HOST, PEER], {HOST: [22], PEER: [22]}),
        )
        state = NetworkState(
            stamp=EventStamp(SESSION), known_hosts={HOST, PEER},
            initial_ports={HOST: None, PEER: [22]},
            ports_initialized={HOST: False, PEER: True},
            open_ports={HOST: set(), PEER: {22}},
            port_absent_count={}, notified_port_not_open={},
            host_absent_count={}, host_not_observed=set(),
            deferred_initialization={HOST}, target_network=NET_CIDR,
        )
        return baseline, state

    def _run_check(self, state):
        _do_check(
            target_network=NET_CIDR, network_id=SESSION, run_session_id="run-r3",
            identity=self.IDENTITY, interval=60, whitelist=Whitelist(),
            counter=AlertCounter(), state=state,
        )

    def _events(self):
        return sorted(db.sentinel_get_events(SESSION, limit=100),
                      key=lambda event: event["timestamp"])

    def _initialization_events(self):
        return [event for event in self._events()
                if event["type"] == "host_ports_initialized"]

    def test_store_recovered_with_event_is_atomic(self, monkeypatch):
        """R3: when initialization_event is provided, baseline + event in one tx."""
        from sentinel.baseline import store_recovered_host_baseline
        from sentinel.baseline import NetworkIdentity as NI
        import uuid as _uuid

        identity = NI(target_network=NET_CIDR,
                      gateway_ip="192.168.1.1", gateway_mac="aa:bb:cc:dd:ee:ff")
        event_id = str(_uuid.uuid4())
        init_ev = {
            "event_id": event_id,
            "timestamp": "2026-11-20T10:00:00+00:00",
            "type": "host_ports_initialized",
            "details": {
                "ip": HOST,
                "detail": "baseline recovered",
                "whitelisted": False,
                "notification": {"version": 1, "state": "whitelisted",
                                 "decided_at": "2026-11-20T10:00:00+00:00"},
            },
            "resolved": True,
        }
        store_recovered_host_baseline(
            SESSION, identity, HOST, [22, 80],
            initialization_event=init_ev,
        )
        # Both the baseline row and the event must exist
        entries = db.sentinel_get_baseline_entries(
            SESSION, NET_CIDR, "192.168.1.1", "aa:bb:cc:dd:ee:ff"
        )
        ips = [e["ip"] for e in entries]
        assert HOST in ips, "baseline row must exist after atomic write"

        events = db.sentinel_get_events(SESSION, limit=100)
        event_ids = [e["id"] for e in events]
        assert event_id in event_ids, "initialization event must be persisted atomically"

    def test_exactly_one_initialization_event_on_recovery(self, monkeypatch):
        """R3: idempotent — duplicate event_id via INSERT OR IGNORE prevents duplication."""
        from sentinel.baseline import store_recovered_host_baseline
        from sentinel.baseline import NetworkIdentity as NI
        import uuid as _uuid

        identity = NI(target_network=NET_CIDR,
                      gateway_ip="192.168.1.1", gateway_mac="aa:bb:cc:dd:ee:ff")
        event_id = str(_uuid.uuid4())
        init_ev = {
            "event_id": event_id,
            "timestamp": "2026-11-20T10:00:00+00:00",
            "type": "host_ports_initialized",
            "details": {
                "ip": HOST, "detail": "baseline recovered",
                "whitelisted": False,
                "notification": {"version": 1, "state": "whitelisted",
                                 "decided_at": "2026-11-20T10:00:00+00:00"},
            },
            "resolved": True,
        }
        # Call twice — second call must be idempotent (INSERT OR IGNORE)
        store_recovered_host_baseline(
            SESSION, identity, HOST, [22], initialization_event=init_ev,
        )
        store_recovered_host_baseline(
            SESSION, identity, HOST, [22], initialization_event=init_ev,
        )
        events = db.sentinel_get_events(SESSION, limit=100)
        matching = [e for e in events if e["id"] == event_id]
        assert len(matching) == 1, "exactly one event must exist after two calls"
        entries = db.sentinel_get_baseline_entries(
            SESSION, NET_CIDR, "192.168.1.1", "aa:bb:cc:dd:ee:ff"
        )
        assert len(entries) == 1, "repeated recovery must not duplicate the baseline row"

    def test_do_check_persists_one_baseline_and_one_initialization_event(self, monkeypatch):
        """R3: real _do_check writes the baseline and exactly one event."""
        baseline, state = self._recovery_setup(monkeypatch)
        self._run_check(state)

        entries = db.sentinel_get_baseline_entries(
            SESSION, NET_CIDR, self.IDENTITY.gateway_ip, self.IDENTITY.gateway_mac
        )
        host_rows = [entry for entry in entries if entry["ip"] == HOST]
        assert len(host_rows) == 1
        assert host_rows[0]["ports"] == [22]

        events = self._events()
        init_events = self._initialization_events()
        assert len(init_events) == 1
        assert init_events[0]["details"]["ip"] == HOST
        assert init_events[0]["details"]["initial_ports"] == [22]
        assert not [event for event in events
                    if event["type"] in ("new_host", "new_port", "port_not_open")]
        assert state.ports_initialized[HOST] is True
        assert state.deferred_initialization == set()

    def test_restart_reconstruction_marks_recovered_host_initialized(self, monkeypatch):
        """R3: after a restart the recovered host is no longer deferred."""
        from sentinel.baseline import get_baseline as real_get_baseline
        baseline, state = self._recovery_setup(monkeypatch)
        self._run_check(state)

        rebuilt = _rebuild_transition_state(
            SESSION, real_get_baseline(SESSION, self.IDENTITY)
        )
        assert rebuilt is not None
        assert HOST in rebuilt.known_hosts
        assert rebuilt.ports_initialized[HOST] is True
        assert rebuilt.initial_ports[HOST] == [22]
        assert HOST not in rebuilt.deferred_initialization

    def test_interruption_after_atomic_persistence_does_not_duplicate(self, monkeypatch):
        """R3: a crash between the atomic commit and process_changes is restart-safe."""
        from sentinel.baseline import get_baseline as real_get_baseline
        baseline, state = self._recovery_setup(monkeypatch)
        original_process = sm.process_changes

        def crash_after_persistence(*args, **kwargs):
            raise RuntimeError("simulated crash after atomic persistence")

        monkeypatch.setattr(sm, "process_changes", crash_after_persistence)
        with pytest.raises(RuntimeError, match="simulated crash"):
            self._run_check(state)

        assert len(self._initialization_events()) == 1

        rebuilt = _rebuild_transition_state(
            SESSION, real_get_baseline(SESSION, self.IDENTITY)
        )
        assert rebuilt is not None
        assert HOST not in rebuilt.deferred_initialization

        # Resume: a fresh cycle must not write a second initialization event.
        monkeypatch.setattr(sm, "process_changes", original_process)
        monkeypatch.setattr(
            sm, "get_baseline", lambda *a, **kw: real_get_baseline(SESSION, self.IDENTITY)
        )
        monkeypatch.setattr(
            sm, "check_network", lambda *a, **kw: _cycle([HOST], {HOST: [22]})
        )
        self._run_check(rebuilt)

        events = self._events()
        assert len(self._initialization_events()) == 1
        assert not [event for event in events
                    if event["type"] in ("new_host", "new_port", "port_not_open")]

    def test_atomic_recovery_rolls_back_baseline_when_event_write_fails(self):
        """R3: an event write failure leaves no baseline row behind."""
        import sqlite3
        from sentinel.baseline import SentinelStorageError, store_recovered_host_baseline

        conn = sqlite3.connect(str(db.get_sentinel_db_path(SESSION)))
        try:
            conn.execute(
                "CREATE TRIGGER fail_init_event BEFORE INSERT ON events "
                "BEGIN SELECT RAISE(ABORT, 'event write refused'); END"
            )
            conn.commit()
        finally:
            conn.close()

        init_ev = {
            "event_id": str(uuid.uuid4()),
            "timestamp": self.NOW,
            "type": "host_ports_initialized",
            "details": {"ip": HOST, "detail": "baseline recovered",
                        "whitelisted": False},
            "resolved": True,
        }
        with pytest.raises(SentinelStorageError):
            store_recovered_host_baseline(
                SESSION, self.IDENTITY, HOST, [22], initialization_event=init_ev,
            )

        entries = db.sentinel_get_baseline_entries(
            SESSION, NET_CIDR, self.IDENTITY.gateway_ip, self.IDENTITY.gateway_mac
        )
        assert entries == []
        assert db.sentinel_get_events(SESSION, limit=100) == []


class TestR4InvalidXmlRegressionViaDoCheck:
    """R4: invalid XML through the real check_network → _do_check path."""

    def test_invalid_xml_preserves_baseline_and_does_not_advance_last_check(self, monkeypatch):
        """A real invalid TCP XML is INCOMPLETE, never an empty port list.

        The healthy peer must still be processed, while the affected host keeps
        its baseline ports and produces no closure/opening/initialization event.
        """
        from tests.test_sentinel_baseline_reliability import nmap_tcp_xml

        initial_time = "2026-11-01T10:00:00+00:00"
        identity = NetworkIdentity(NET_CIDR, "192.168.1.1", "aa:bb:cc:dd:ee:ff")
        db.sentinel_update_state(
            SESSION, "active", last_check_time=initial_time,
            target_network=NET_CIDR, gateway_ip=identity.gateway_ip,
            gateway_mac=identity.gateway_mac,
        )
        for ip, asset_id in ((HOST, "a1"), (PEER, "a2")):
            db.sentinel_save_asset(
                SESSION, asset_id, ip, "2026-01-01T00:00:00+00:00"
            )
            db.sentinel_save_baseline_entry(
                SESSION, str(uuid.uuid4()), asset_id, NET_CIDR,
                identity.gateway_ip, identity.gateway_mac, [22], None,
                "2026-01-01T00:00:00+00:00",
            )
        baseline = {
            HOST: BaselineEntry(asset_id="a1", ip=HOST, mac="", ports=[22],
                                last_scan="2026-01-01T00:00:00+00:00"),
            PEER: BaselineEntry(asset_id="a2", ip=PEER, mac="", ports=[22],
                                last_scan="2026-01-01T00:00:00+00:00"),
        }
        monkeypatch.setattr(sm, "get_baseline", lambda *a, **kw: baseline)
        monkeypatch.setattr(
            "sentinel.monitor._get_active_hosts", lambda *a, **kw: [HOST, PEER]
        )
        monkeypatch.setattr("sentinel.monitor._get_arp_mac", lambda ip: "")

        tcp_calls = []

        def fake_tcp(ip, profile, ports, **kwargs):
            tcp_calls.append(ip)
            if ip == HOST:
                return "not xml <<<"
            return nmap_tcp_xml(ip=PEER, open_ports=[22])

        monkeypatch.setattr("sentinel.monitor._tcp_run_nmap", fake_tcp)

        # The real observation layer must turn the invalid XML into INCOMPLETE
        # (ports is None), never into an empty list. The healthy peer is complete.
        from sentinel.monitor import _get_host_tcp_observation
        assert _get_host_tcp_observation(HOST).ports is None
        assert _get_host_tcp_observation(PEER).ports == [22]
        tcp_calls.clear()

        state = NetworkState(
            stamp=EventStamp(SESSION),
            known_hosts={HOST, PEER},
            initial_ports={HOST: [22], PEER: [22]},
            ports_initialized={HOST: True, PEER: True},
            open_ports={HOST: {22}, PEER: {22}},
            port_absent_count={},
            notified_port_not_open={},
            host_absent_count={},
            host_not_observed=set(),
            deferred_initialization=set(),
            target_network=NET_CIDR,
        )

        _do_check(
            target_network=NET_CIDR, network_id=SESSION, run_session_id="run-invalid-xml",
            identity=identity, interval=60, whitelist=Whitelist(),
            counter=AlertCounter(), state=state,
        )

        # Both hosts were really scanned; the healthy peer was processed.
        assert tcp_calls == [HOST, PEER]
        assert state.open_ports[HOST] == {22}
        assert state.open_ports[PEER] == {22}
        assert state.port_absent_count.get(HOST, {}) == {}
        assert state.port_absent_count.get(PEER, {}) == {}

        final_state = db.sentinel_get_state(SESSION)
        assert final_state["last_check_time"] == initial_time, (
            "last_check_time must not advance after a partial/degraded scan"
        )
        assert final_state["sentinel_status"] == "degraded"

        entries = db.sentinel_get_baseline_entries(
            SESSION, NET_CIDR, identity.gateway_ip, identity.gateway_mac
        )
        assert {entry["ip"]: entry["ports"] for entry in entries} == {
            HOST: [22], PEER: [22]
        }

        events = db.sentinel_get_events(SESSION, limit=100)
        assert [event["type"] for event in events] == ["scan_degraded"]
        assert not [event for event in events
                    if event["type"] in
                    ("port_not_open", "new_port", "new_host", "host_ports_initialized")]
        assert not [event for event in events
                    if (event["details"].get("initial_ports") == [])]
