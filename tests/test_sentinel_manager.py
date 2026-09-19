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
)

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
    def test_returns_inactive_when_no_sentinel_data(self):
        result = status(SESSION)
        # Session exists but no sentinel state set → inactive
        assert result.get("display_state") in ("INACTIF", "DÉGRADÉ")

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
