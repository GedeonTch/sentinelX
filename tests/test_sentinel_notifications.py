"""Controlled clock, real temporary SQLite; no scans, no user data."""
import datetime as dt
import io
import socket
import subprocess
from unittest.mock import Mock

import pytest
from rich.console import Console
from core import database as db, logger
from sentinel.alerting import AlertCounter, process_changes
from sentinel.monitor import NetworkChange
from sentinel.whitelist import Whitelist
from sentinel.notifications import host_summary, notification_state

NET, RUN = 'quota-network', 'quota-run'
HOST = '192.0.2.10'
CHANGE = NetworkChange('new_port', HOST, 'port 8080 opened', 'simulated')


class Clock:
    def __init__(self):
        self.value = dt.datetime(2026, 10, 12, 12, tzinfo=dt.timezone.utc)
    def __call__(self):
        return self.value
    def advance(self, seconds):
        self.value += dt.timedelta(seconds=seconds)


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(db, '_real_user_home', lambda: tmp_path)
    monkeypatch.setattr(socket, 'socket', Mock(side_effect=AssertionError('No network')))
    monkeypatch.setattr(subprocess, 'Popen', Mock(side_effect=AssertionError('No scanner')))
    monkeypatch.setattr(logger, '_console', Console(file=io.StringIO(), width=90))
    db.init_sentinel_db(NET)
    db.sentinel_update_state(NET, 'inactive', target_network='192.0.2.0/24')
    db.init_db(RUN)
    db.save_session(RUN, target='192.0.2.0/24')
    return Clock()


def send(counter, change=CHANGE, network=NET, whitelist=None):
    return process_changes([change], RUN, whitelist or Whitelist(), counter, network_id=network)


def test_rolling_window_exact_boundary_not_fixed_pause(store):
    c = AlertCounter(clock=store)
    for _ in range(3):
        assert len(send(c)) == 1
        store.advance(600)
    assert send(c) == []  # t=1800, fourth suppressed
    store.advance(1799)
    assert send(c) == []  # t=3599
    store.advance(1)
    assert len(send(c)) == 1  # first leaves exactly at t=3600
    assert c.summary()[HOST]['displayed'] == 3
    assert send(c) == []
    store.advance(600)
    assert len(send(c)) == 1  # second slot at 4200, no extra fixed cooldown
    assert len(db.get_findings(RUN)) == 8


def test_restart_and_network_host_isolation(store):
    for _ in range(3):
        assert send(AlertCounter(clock=store))
    assert send(AlertCounter(clock=store)) == []
    assert send(AlertCounter(clock=store), NetworkChange('new_host', '192.0.2.11', 'new', 'test'))
    db.init_sentinel_db('second-network')
    assert send(AlertCounter(clock=store), network='second-network')


def test_whitelist_never_uses_quota_even_when_host_silent(store):
    c = AlertCounter(clock=store)
    for _ in range(4):
        send(c)
    wl = Whitelist(allowed_port_changes=[{'host': HOST, 'ports': [8080]}])
    assert send(c, whitelist=wl) == []
    assert c.summary()[HOST]['displayed'] == 3
    assert c.summary()[HOST]['masked'] == 1
    assert len(db.get_findings(RUN)) == 4
    assert sum(notification_state(e) == 'whitelisted' for e in db.sentinel_get_events(NET)) == 1
    assert '[INFO]' in logger.get_console().file.getvalue()


def test_preparing_recovered_once_and_reserve_survives_restart(store):
    for i in range(3):
        db.sentinel_save_event(NET, f'pending-{i}', 'new_port', store().isoformat(), None,
                              {'ip': HOST, 'notification': {'version': 1, 'state': 'preparing'}}, False)
    c = AlertCounter(clock=store)
    c.bind(NET)
    first = db.sentinel_network_snapshot(NET)['events']
    assert all(notification_state(e) == 'uncertain' for e in first)
    store.advance(1800)
    c2 = AlertCounter(clock=store)
    c2.bind(NET)
    assert db.sentinel_network_snapshot(NET)['events'] == first
    assert send(c2) == []
    store.advance(1800)
    assert send(AlertCounter(clock=store))  # no extension on the second restart


@pytest.mark.parametrize('failure', ['terminal', 'confirmation'])
def test_failed_emission_is_not_confirmed_and_original_interrupt_survives(store, monkeypatch, failure):
    c = AlertCounter(clock=store)
    original = KeyboardInterrupt('SECRET_CANARY')
    from sentinel import alerting
    if failure == 'terminal':
        monkeypatch.setattr(alerting, '_display_alert', Mock(side_effect=original))
    else:
        real = db.sentinel_set_notification
        def fail_confirm(network, event, meta, expected=None):
            if meta['state'] == 'confirmed':
                raise original
            return real(network, event, meta, expected)
        monkeypatch.setattr(db, 'sentinel_set_notification', fail_confirm)
    with pytest.raises(KeyboardInterrupt) as caught:
        send(c)
    assert caught.value is original
    event = db.sentinel_get_events(NET)[0]
    assert notification_state(event) == 'uncertain'
    assert 'SECRET_CANARY' not in str(event)
    c.refresh()
    row = c.summary()[HOST]
    assert row['displayed'] == 0 and row['reserved'] == 1
    assert len(db.get_findings(RUN)) == 1


def test_no_output_if_intention_cannot_be_persisted(store, monkeypatch):
    from sentinel import alerting
    output = Mock()
    monkeypatch.setattr(alerting, '_display_alert', output)
    monkeypatch.setattr(db, 'sentinel_set_notification', Mock(side_effect=OSError('db failure')))
    with pytest.raises(OSError):
        send(AlertCounter(clock=store))
    output.assert_not_called()
    assert len(db.sentinel_get_events(NET)) == len(db.get_findings(RUN)) == 1


def test_legacy_unknown_not_rewritten_and_expires(store):
    for i in range(3):
        db.sentinel_save_event(NET, f'legacy-{i}', 'new_port', store().isoformat(), None, {'ip': HOST}, False)
    original = db.sentinel_network_snapshot(NET)['events']
    c = AlertCounter(clock=store)
    assert send(c) == []
    assert c.summary()[HOST]['displayed'] == 0
    assert c.summary()[HOST]['unknown'] == 3
    assert [e for e in db.sentinel_network_snapshot(NET)['events'] if e['id'].startswith('legacy')] == original
    store.advance(3600)
    assert send(AlertCounter(clock=store))


def test_history_over_100_does_not_hide_recent_confirmations(store):
    c = AlertCounter(clock=store)
    for _ in range(3):
        send(c)
    store.advance(1)
    for i in range(110):
        db.sentinel_save_event(NET, f'noise-{i}', 'new_host', store().isoformat(), None,
                              {'ip': '192.0.2.11', 'whitelisted': True}, True)
    assert send(AlertCounter(clock=store)) == []


def test_clock_rollback_does_not_free_slots(store):
    for _ in range(3):
        send(AlertCounter(clock=store))
    store.advance(-100)
    assert send(AlertCounter(clock=store)) == []


def test_empty_cycle_has_no_resume_message_or_reactivation(store):
    c = AlertCounter(clock=store)
    for _ in range(4):
        send(c)
    store.advance(3600)
    assert process_changes([], RUN, Whitelist(), c, network_id=NET) == []
    assert c.summary()[HOST]['available'] == 3
    assert send(c)


def test_old_threshold_setting_does_not_override_locked_rule(store):
    c = AlertCounter(clock=store)
    wl = Whitelist(sentinel_max_alerts_per_hour=1)
    assert [len(send(c, whitelist=wl)) for _ in range(4)] == [1, 1, 1, 0]


def test_silent_host_does_not_suspend_following_monitor_cycles(store, monkeypatch):
    from sentinel import sentinel_manager as manager
    from sentinel.baseline import NetworkIdentity
    c = AlertCounter(clock=store)
    for _ in range(3):
        send(c)
    check = Mock(return_value=[CHANGE])
    monkeypatch.setattr(manager, 'get_baseline', lambda *args: {'known': object()})
    monkeypatch.setattr(manager, 'check_network', check)
    owner = Mock()
    owner.wait.side_effect = [False, False, True]
    owner.admit_cycle.return_value = True
    manager._run_loop('192.0.2.0/24', NET, RUN,
                      NetworkIdentity('192.0.2.0/24', '', ''), 60, Whitelist(), c, owner)
    assert check.call_count == 2 and owner.end_cycle.call_count == 2
    assert len(db.get_findings(RUN)) == 5
    assert len(db.sentinel_get_events(NET)) == 5
    assert c.summary()[HOST]['displayed'] == 3 and c.summary()[HOST]['masked'] == 2


def test_failed_uncertain_write_recovers_on_next_start_without_losing_original(store, monkeypatch):
    from sentinel import alerting
    real = db.sentinel_set_notification
    original = KeyboardInterrupt('SECRET_CANARY')
    monkeypatch.setattr(alerting, '_display_alert', Mock(side_effect=original))
    def fail_recovery(network, event, meta, expected=None):
        if meta['state'] == 'uncertain':
            raise OSError('storage unavailable')
        return real(network, event, meta, expected)
    with monkeypatch.context() as scoped:
        scoped.setattr(db, 'sentinel_set_notification', fail_recovery)
        with pytest.raises(KeyboardInterrupt) as caught:
            send(AlertCounter(clock=store))
        assert caught.value is original
    assert notification_state(db.sentinel_get_events(NET)[0]) == 'preparing'
    store.advance(8000)
    recovered = AlertCounter(clock=store)
    recovered.bind(NET)
    event = db.sentinel_get_events(NET)[0]
    assert event['details']['notification']['reserved_until'] == (store() + dt.timedelta(hours=1)).isoformat()
    assert recovered.summary()[HOST]['reserved'] == 1


def test_intention_precedes_terminal_and_confirm_follows(store, monkeypatch):
    from sentinel import alerting
    observed = []
    def emitted(change, finding):
        observed.append(notification_state(db.sentinel_get_events(NET)[0]))
    monkeypatch.setattr(alerting, '_display_alert', emitted)
    assert send(AlertCounter(clock=store))
    assert observed == ['preparing']
    assert notification_state(db.sentinel_get_events(NET)[0]) == 'confirmed'


def test_no_schema_change_and_legacy_whitelist_does_not_reserve(store):
    conn = db.get_sentinel_connection(NET)
    try:
        before = [tuple(r) for r in conn.execute("SELECT name,sql FROM sqlite_master ORDER BY name")]
    finally:
        conn.close()
    for i in range(4):
        db.sentinel_save_event(NET, f'white-{i}', 'new_port', store().isoformat(), None,
                              {'ip': HOST, 'whitelisted': True}, True)
    c = AlertCounter(clock=store)
    assert [len(send(c)) for _ in range(4)] == [1, 1, 1, 0]
    conn = db.get_sentinel_connection(NET)
    try:
        assert [tuple(r) for r in conn.execute("SELECT name,sql FROM sqlite_master ORDER BY name")] == before
    finally:
        conn.close()
