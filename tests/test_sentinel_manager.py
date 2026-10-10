"""
tests/test_sentinel_manager.py — Unit tests for sentinel/sentinel_manager.py

Covers: status (ACTIF/DÉGRADÉ/INACTIF), _compute_display_state,
        stop preserves baseline, last_check_time only on success.
        start() loop is not unit-tested (blocking) — covered by integration.
"""

import datetime
import pytest
from pathlib import Path
from unittest.mock import patch
from datetime import timezone

import core.database as db
from sentinel.sentinel_manager import (
    status,
    stop,
    _compute_display_state,
    _graceful_stop,
    _do_check,
)
from sentinel.alerting import AlertCounter
from sentinel.baseline import BaselineEntry
from sentinel.monitor import NetworkChange, ScanDegradedError
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
            "sentinel.sentinel_manager.sentinel_get_assets", return_value=[]
        ) as get_assets:
            result = status(SESSION)
        get_state.assert_called_once_with(SESSION)
        get_assets.assert_called_once_with(SESSION)
        assert result["network_id"] == SESSION


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


class TestDegradedArpCheck:
    def test_degraded_check_processes_changes_without_updating_last_check(self):
        initial = (datetime.datetime.now(timezone.utc) - datetime.timedelta(seconds=30)).isoformat()
        db.sentinel_update_state(SESSION, "active", last_check_time=initial)
        change = NetworkChange("mac_change", "192.168.1.10", "mac changed", "active ARP")
        whitelist = Whitelist()

        with patch("sentinel.sentinel_manager.get_baseline", return_value={"ip": object()}), \
             patch(
                 "sentinel.sentinel_manager.check_network",
                 side_effect=ScanDegradedError("partial", [change]),
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
            )

        process_changes.assert_called_once()
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
            )

        state = db.sentinel_get_state(SESSION)
        assert state["sentinel_status"] == "degraded"
        assert state["last_check_time"] == initial
        process_changes.assert_not_called()
