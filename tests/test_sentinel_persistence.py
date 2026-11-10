"""Network/session routing integration: real temporary SQLite, simulated network/time."""
import datetime
import socket
import subprocess
from unittest.mock import Mock

import pytest

import core.database as db
import sentinel.alerting as alerting
import sentinel.monitor as monitor
import sentinel.sentinel_manager as manager
from sentinel.baseline import BaselineEntry, NetworkIdentity, compute_network_id
from sentinel.whitelist import Whitelist

TARGET = '192.0.2.0/24'
IDENTITY = NetworkIdentity(TARGET, '192.0.2.1', '02:00:00:00:00:01')
NETWORK = compute_network_id(IDENTITY)
RUN = 'sentinel-run-persistence-test'
NOW = datetime.datetime(2026, 10, 10, 12, tzinfo=datetime.timezone.utc)


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    def session_path(key):
        folder = tmp_path / 'sessions'
        folder.mkdir(exist_ok=True)
        return folder / f'{key}.db'

    def network_path(key):
        folder = tmp_path / 'sentinel'
        folder.mkdir(exist_ok=True)
        return folder / f'{key}.db'

    class FixedDatetime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW if tz else NOW.replace(tzinfo=None)

    monkeypatch.setattr(db, 'get_db_path', session_path)
    monkeypatch.setattr(db, 'get_sentinel_db_path', network_path)
    monkeypatch.setattr(manager, 'list_sentinel_network_ids', lambda: [NETWORK])
    monkeypatch.setattr(manager.datetime, 'datetime', FixedDatetime)
    monkeypatch.setattr(socket, 'socket', Mock(side_effect=AssertionError('No real network')))
    monkeypatch.setattr(subprocess, 'Popen', Mock(side_effect=AssertionError('No real subprocess scan')))
    monkeypatch.setattr(manager, 'detect_network_identity', lambda target: IDENTITY)
    monkeypatch.setattr(manager, 'baseline_exists', lambda *args: True)
    monkeypatch.setattr(manager, '_load_interval', lambda: 60)
    monkeypatch.setattr(manager, 'get_baseline', lambda *args: {
        '192.0.2.10': BaselineEntry(asset_id='known', ip='192.0.2.10', mac='', ports=[22], last_scan=NOW.isoformat())
    })
    monkeypatch.setattr(monitor, '_get_arp_mac', lambda ip: '')
    monkeypatch.setattr(monitor, '_get_open_ports', lambda ip, **kwargs: [22])
    return session_path, network_path


@pytest.mark.parametrize('mode', ['normal', 'whitelisted', 'multiple_hosts'])
@pytest.mark.parametrize('degraded', [False, True])
def test_start_routes_events_to_network_and_findings_to_run(isolated, monkeypatch, mode, degraded):
    """Exercises start -> loop -> check -> real process_changes -> DB -> status."""
    session_path, network_path = isolated
    assert NETWORK != RUN
    new_hosts = ['192.0.2.99'] if mode != 'multiple_hosts' else [f'192.0.2.{i}' for i in (11, 12, 13, 14, 99)]
    allowed = ['192.0.2.99'] if mode != 'normal' else []
    wl = Whitelist(allowed_new_hosts=allowed, sentinel_max_alerts_per_hour=3)
    monkeypatch.setattr(manager, 'load_whitelist', lambda: wl)
    monkeypatch.setattr(monitor, '_get_active_hosts', lambda target, **kwargs: ['192.0.2.10', *new_hosts])
    if degraded:
        monkeypatch.setattr(monitor, '_get_open_ports', lambda ip, **kwargs: None)
    shown = Mock()
    monkeypatch.setattr(alerting, 'display', shown)
    alerts = Mock()
    monkeypatch.setattr(manager.MonitorView, 'emit', alerts)
    db.init_sentinel_db('other-network')

    ticks = 0
    states = []
    def simulated_sleep(seconds):
        nonlocal ticks
        assert seconds == 60
        ticks += 1
        if ticks == 2:
            states.append(db.sentinel_get_state(NETWORK))
            raise KeyboardInterrupt
    monkeypatch.setattr(manager.Owner, 'wait', lambda owner, seconds: simulated_sleep(seconds) or False)

    manager.start(TARGET, session_id=RUN)

    events = db.sentinel_get_events(NETWORK)
    new_events = [e for e in events if e['type'] == 'new_host']
    init_events = [e for e in events if e['type'] == 'host_ports_initialized']
    scan_events = [e for e in events if e['type'] == 'scan_degraded']
    # T23-B: one new_host per new host, plus its host_ports_initialized when the scan is complete.
    assert len(new_events) == len(new_hosts)
    assert len(init_events) == (0 if degraded else len(new_hosts))
    # §9.14 / B3: exactly one scan_degraded for the single degraded episode, none otherwise.
    assert len(scan_events) == (1 if degraded else 0)
    if degraded:
        assert scan_events[0]['asset_id'] is None and scan_events[0]['details']['ip'] == TARGET
    assert len(events) == len(new_events) + len(init_events) + len(scan_events)
    assert {e['details']['ip'] for e in new_events} == set(new_hosts)
    # B1: stamps are strictly increasing per network (the clock is frozen at NOW).
    stamps = [e['timestamp'] for e in events]
    assert len(set(stamps)) == len(stamps)
    assert min(stamps) == NOW.isoformat(timespec='microseconds')  # §9.3.1 format
    assert all(bool(e['resolved']) == (e['details']['ip'] in allowed) for e in new_events)
    assert all(bool(e['resolved']) for e in init_events)  # initialization is not an alert
    unresolved = len(new_hosts) - len(allowed)
    expected_unresolved = unresolved + len(scan_events)  # observations are unresolved events
    assert len(db.sentinel_get_events(NETWORK, resolved=False)) == expected_unresolved
    assert len(db.sentinel_get_events(NETWORK, resolved=True)) == len(allowed) + len(init_events)
    assert manager.status(NETWORK)['unresolved_alerts'] == expected_unresolved
    assert db.sentinel_get_events('other-network') == []
    findings = db.get_findings(RUN)
    assert len(findings) == unresolved  # no Finding for host_ports_initialized or scan_degraded
    assert all(f.session_id == RUN and f.severity.value == 'medium' and f.risk_score is None for f in findings)
    assert db.get_session(RUN)['id'] == RUN
    assert db.get_events(RUN) == []
    assert not session_path(NETWORK).exists()
    assert network_path(NETWORK).exists()
    assert states[0]['sentinel_status'] == ('degraded' if degraded else 'active')
    assert alerts.call_count == unresolved + len(scan_events)  # independent quotas for distinct hosts
    if allowed:
        assert any('[INFO]' in str(call) for call in shown.call_args_list)


def test_network_events_survive_distinct_runs(isolated, monkeypatch):
    """Each run routes its own new host to its own Finding; known hosts are not re-announced (§9.5, known_hosts)."""
    session_path, _ = isolated
    monkeypatch.setattr(manager, 'load_whitelist', Whitelist)
    hosts_by_run = {
        RUN: ['192.0.2.10', '192.0.2.99'],
        'sentinel-run-second': ['192.0.2.10', '192.0.2.99', '192.0.2.98'],  # .99 already known
    }
    for index, run in enumerate((RUN, 'sentinel-run-second'), 1):
        monkeypatch.setattr(monitor, '_get_active_hosts', lambda target, run=run, **kwargs: hosts_by_run[run])
        monkeypatch.setattr(manager.Owner, 'wait', Mock(side_effect=[False, KeyboardInterrupt]))
        manager.start(TARGET, session_id=run)
        findings = db.get_findings(run)
        new_ip = '192.0.2.99' if index == 1 else '192.0.2.98'
        assert len(findings) == 1 and findings[0].session_id == run
        assert findings[0].target_ip == new_ip
        assert db.get_events(run) == []
        new_events = [e for e in db.sentinel_get_events(NETWORK) if e['type'] == 'new_host']
        assert len(new_events) == index  # .99 is not announced again in the second run
        assert manager.status(NETWORK)['unresolved_alerts'] == index
    assert len(db.get_findings(RUN)) == 1
    assert not session_path(NETWORK).exists()


def test_generated_run_id_is_not_replaced_by_network_id(isolated, monkeypatch):
    session_path, _ = isolated
    monkeypatch.setattr(manager, 'load_whitelist', Whitelist)
    monkeypatch.setattr(monitor, '_get_active_hosts', lambda target, **kwargs: ['192.0.2.10', '192.0.2.99'])
    monkeypatch.setattr(manager.Owner, 'wait', Mock(side_effect=[False, KeyboardInterrupt]))
    manager.start(TARGET)
    files = list(session_path(RUN).parent.glob('*.db'))
    assert len(files) == 1
    generated_run = files[0].stem
    assert generated_run.startswith('sentinel-run-') and generated_run != NETWORK
    assert db.get_findings(generated_run)[0].session_id == generated_run
    assert sorted(e['type'] for e in db.sentinel_get_events(NETWORK)) == ['host_ports_initialized', 'new_host']
    assert not session_path(NETWORK).exists()


def test_notification_window_reads_network_not_run_storage(isolated, monkeypatch):
    session_path, _ = isolated
    db.init_sentinel_db(NETWORK)
    db.init_db(RUN)
    db.save_session(RUN, target=TARGET)
    for index in range(2):
        db.sentinel_save_event(NETWORK, f'previous-{index}', 'new_host', NOW.isoformat(), None,
                               {'ip': '192.0.2.99'}, False)
    db.save_event(RUN, 'session-decoy', 'new_host', NOW.isoformat(), None, {}, False)
    counter = alerting.AlertCounter()
    change = monitor.NetworkChange('new_host', '192.0.2.99', 'new host detected', 'synthetic')
    assert len(alerting.process_changes([change], RUN, Whitelist(), counter, network_id=NETWORK, stamp=alerting.EventStamp(NETWORK))) == 1
    assert alerting.process_changes([change], RUN, Whitelist(), counter, network_id=NETWORK, stamp=alerting.EventStamp(NETWORK)) == []
    row = counter.summary()['192.0.2.99']
    assert row['displayed'] == 1 and row['reserved'] == 2 and row['masked'] == 1
    assert len(db.sentinel_get_events(NETWORK)) == 4
    assert len(db.get_events(RUN)) == 1
    assert not session_path(NETWORK).exists()
