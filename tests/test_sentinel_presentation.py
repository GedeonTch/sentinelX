"""Rich and offline HTML acceptance; no real probes or user databases."""
import hashlib
import io
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from core import database as db, logger
from sentinel.alerting import AlertCounter
from sentinel.monitor import NetworkChange
from sentinel.monitor_view import MonitorView
from reports.sentinel_report import generate_sentinel_report
from tests.test_sentinel_notifications import store, send, NET, HOST, RUN


@pytest.mark.parametrize('tty,width', [(False, 90), (False, 35), (True, 65)])
def test_tables_do_not_replay_masked_details_or_count_refreshes(store, tty, width):
    output = io.StringIO()
    console = Console(file=output, force_terminal=tty, width=width)
    c = AlertCounter(clock=store)
    c.bind(NET)
    with MonitorView('192.0.2.0/24', 60, c, console, session_id=RUN) as view:
        c.view = view
        assert view.last_finished is None
        for i in range(4):
            detail = 'MASKED_CANARY' if i == 3 else f'visible-{i} [red]\x1b[31m'
            send(c, NetworkChange('new_port', HOST, detail, 'test'))
        view.set_phase('dégradé', store().isoformat())
        view.set_phase('attente')
        assert len(view.rows) == 3
        assert c.summary()[HOST]['displayed'] == 3
        assert c.summary()[HOST]['masked'] == 1
        assert view.last_finished == store().isoformat()
    text = output.getvalue()
    assert 'MASKED_CANARY' not in text
    assert '[red]' in text  # untrusted markup displayed literally
    assert 'Affichées' in text or width == 35
    if not tty:
        assert '\x1b' not in text
        assert text.count('visible-0') == 1


@pytest.mark.parametrize('tty,width', [(True, 120), (True, 35), (False, 120), (False, 35)])
def test_view_closes_on_interrupt(store, tty, width):
    c = AlertCounter(clock=store)
    c.bind(NET)
    output = io.StringIO()
    view = MonitorView(NET, 60, c, Console(file=output, force_terminal=tty, width=width), session_id=RUN)
    with pytest.raises(KeyboardInterrupt):
        with view:
            # Check startup output before any interruption or refresh.
            import re
            text = re.sub(r'\x1b\[[0-9;?]*[A-Za-z]', '', output.getvalue())
            assert 'Ctrl+C pour arrêter. Baseline conservée à l’arrêt.' in ' '.join(text.split())
            assert 'netlab ' not in text  # no unavailable command suggestions
            raise KeyboardInterrupt
    assert view.phase == 'interruption'
    if tty:
        assert not view.live.is_started
        assert not view.console._live_stack
    else:
        assert view.live is None


def test_report_offline_escaped_readonly_and_unique(store, tmp_path):
    attack = '<script>alert("CANARY")</script><img src=x onerror=alert(1)>'
    c = AlertCounter(clock=store)
    for _ in range(4):
        send(c, NetworkChange('new_port', HOST, attack, 'RAW_EVIDENCE_MUST_NOT_LEAK'))
    db.sentinel_save_event(NET, 'legacy', 'new_host', store().isoformat(), None,
                          {'ip': '<svg onload=alert(1)>', 'detail': attack}, False)
    db.sentinel_save_event(NET, 'legacy-white', 'new_host', store().isoformat(), None,
                          {'ip': HOST, 'detail': 'authorized', 'whitelisted': True}, True)
    db_path = db.get_sentinel_db_path(NET)
    before = hashlib.sha256(db_path.read_bytes()).hexdigest()
    snapshot = db.sentinel_network_snapshot(NET)
    one = generate_sentinel_report(NET, tmp_path, store)
    two = generate_sentinel_report(NET, tmp_path, store)
    assert one != two and one.exists() and two.exists()
    assert one.name.startswith(f'sentinel-status-{NET}-20261012T120000')
    html = one.read_text()
    assert NET in html and store().isoformat() in html
    assert '<script>' not in html and '<svg onload' not in html
    assert '&lt;script&gt;' in html
    assert 'RAW_EVIDENCE_MUST_NOT_LEAK' not in html
    assert 'Notification inconnue' in html and 'Notification masquée par quota' in html
    assert 'data:image/png;base64,' in html and '#e10600' in html
    assert '<details' in html and 'Voir plus' in html
    assert '<script src' not in html and 'href="http' not in html and 'src="http' not in html
    assert 'pas une preuve que Sentinel est encore actif' in html
    assert 'entre deux contrôles' in html
    assert db.sentinel_network_snapshot(NET) == snapshot
    assert hashlib.sha256(db_path.read_bytes()).hexdigest() == before


def test_report_does_not_recover_pending_notifications(store, tmp_path):
    db.sentinel_save_event(NET, 'pending', 'new_port', store().isoformat(), None,
                          {'ip': HOST, 'notification': {'version': 1, 'state': 'preparing'}}, False)
    before = db.sentinel_network_snapshot(NET)
    html = generate_sentinel_report(NET, tmp_path, store).read_text()
    assert 'Émission en préparation' in html
    assert db.sentinel_network_snapshot(NET) == before


@pytest.mark.parametrize('flags', [('-n', '-o'), ('--network', '--output-format')])
def test_report_cli_syntax(store, tmp_path, monkeypatch, flags):
    from cli import app
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(logger, '_console', Console(width=120))
    result = CliRunner().invoke(app, ['sentinel', 'report', flags[0], NET, flags[1], 'html'])
    assert result.exit_code == 0, result.output
    paths = list(tmp_path.glob(f'sentinel-status-{NET}-*.html'))
    assert len(paths) == 1
    assert paths[0].name in ''.join(result.output.split())


def test_report_rejects_unknown_network_and_format_without_files(store, tmp_path, monkeypatch):
    from cli import app
    monkeypatch.chdir(tmp_path)
    for args in [['-n', '../escape', '-o', 'html'], ['-n', 'unknown', '-o', 'html'], ['-n', NET, '-o', 'pdf']]:
        result = CliRunner().invoke(app, ['sentinel', 'report', *args])
        assert result.exit_code != 0
    assert not list(tmp_path.glob('*.html'))
    assert not (tmp_path / '.netlab' / 'sentinel' / 'unknown.db').exists()


def test_start_does_not_fake_a_completed_check(store, monkeypatch):
    from sentinel import sentinel_manager as manager
    from sentinel.baseline import NetworkIdentity, compute_network_id
    identity = NetworkIdentity('192.0.2.0/24', '192.0.2.1', '02:00:00:00:00:01')
    network = compute_network_id(identity)
    monkeypatch.setattr(manager, 'detect_network_identity', lambda target: identity)
    monkeypatch.setattr(manager, 'baseline_exists', lambda *args: True)
    observed = []
    def interrupted(**kwargs):
        observed.append(db.sentinel_get_state(network))
        assert kwargs['counter'].view.last_finished is None
        assert kwargs['counter'].view.session_id == 'no-check-yet'
        raise KeyboardInterrupt
    monkeypatch.setattr(manager, '_run_loop', interrupted)
    manager.start('192.0.2.0/24', 'no-check-yet')
    assert observed[0]['last_check_time'] is None
    assert db.get_session('no-check-yet')['status'] == 'partial'


@pytest.mark.parametrize('outcome', ['degraded', 'error'])
def test_monitor_labels_partial_or_failed_check_honestly(store, monkeypatch, outcome):
    from sentinel import sentinel_manager as manager
    from sentinel.monitor import ScanDegradedError, ScanFailedError
    from sentinel.whitelist import Whitelist
    from unittest.mock import Mock
    c = AlertCounter(clock=store)
    c.bind(NET)
    c.view = MonitorView(NET, 60, c, Console(file=io.StringIO()), session_id=RUN)
    monkeypatch.setattr(manager, 'get_baseline', lambda *args: {'known': object()})
    error = ScanDegradedError('simulated partial', []) if outcome == 'degraded' else ScanFailedError('simulated error')
    monkeypatch.setattr(manager, 'check_network', Mock(side_effect=error))
    manager._do_check('192.0.2.0/24', NET, RUN, object(), 60, Whitelist(), c)
    assert c.view.phase == ('dégradé' if outcome == 'degraded' else 'erreur')
    assert c.view.last_finished == store().isoformat()
    assert db.sentinel_get_state(NET)['last_check_time'] is None


@pytest.mark.parametrize('tty,width', [(False, 120), (False, 35), (True, 120), (True, 35)])
def test_monitor_shows_existing_finding_reference_only_when_emitted(store, monkeypatch, tty, width):
    from sentinel import alerting

    output = io.StringIO()
    c = AlertCounter(clock=store)
    c.bind(NET)
    saved, rendered = [], []
    save = alerting.save_finding

    def record_save(finding):
        save(finding)
        saved.append(finding)

    monkeypatch.setattr(alerting, 'save_finding', record_save)
    with MonitorView(NET, 60, c, Console(file=output, force_terminal=tty, width=width), session_id=RUN) as view:
        c.view = view
        emit = view.emit

        def record_emit(when, change, finding):
            assert finding is saved[-1]  # the persisted object, not a new Finding
            rendered.append(finding)
            emit(when, change, finding)

        monkeypatch.setattr(view, 'emit', record_emit)
        # Displayed MEDIUM, masked HIGH: absence of severity is independently testable.
        for _ in range(3):
            assert len(send(c, NetworkChange('new_host', HOST, 'visible-host', 'test'))) == 1
        assert send(c, NetworkChange('new_port', HOST, 'MASKED_REFERENCE_CANARY', 'test')) == []
        view.set_phase('attente')
        assert len(view.rows) == 3
    assert len(saved) == len(db.get_findings(RUN)) == 4
    assert rendered == saved[:3]
    # Rich borders/line wrapping may split the command in a narrow terminal.
    import re
    text = re.sub(r'\x1b\[[0-9;?]*[A-Za-z]', '', output.getvalue())
    compact = ''.join(c for c in text if not c.isspace() and c not in '│┃')
    for finding in rendered:
        assert finding.id[:8] in text
        assert finding.id in compact
        assert 'sentinel findings show' not in str(view.rows)
        if not tty:
            assert compact.count(finding.id) == 1  # UUID once per emitted notification
    assert 'MEDIUM' in text
    assert 'HIGH' not in text
    assert saved[-1].id[:8] not in text
    assert 'MASKED_REFERENCE_CANARY' not in text
    assert c.summary()[HOST]['displayed'] == 3
    assert c.summary()[HOST]['masked'] == 1


def test_monitor_displays_high_severity_from_finding(store):
    c = AlertCounter(clock=store)
    c.bind(NET)
    output = io.StringIO()
    with MonitorView(NET, 60, c, Console(file=output, width=120), session_id=RUN) as view:
        c.view = view
        finding, = send(c)
    assert finding.id[:8] in output.getvalue()
    assert 'HIGH' in output.getvalue()
