"""Rich and offline HTML acceptance; no real probes or user databases."""
import hashlib
import io
import re
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


# ---------------------------------------------------------------------------
# T23-A — UX du moniteur (docs/SENTINEL-FINDINGS.md, section Monitor)
# ---------------------------------------------------------------------------

NON_TTY_TITLE = 'Alertes de cette exécution'
TTY_LIST_TITLE = 'Alertes affichées — 20 dernières de cette exécution'  # removed from the frame (T23-A fix)
FOOTER_COMMAND = f'sentinel findings show <UUID_COMPLET> -s {RUN}'


@pytest.mark.parametrize('count', [1, 3])
def test_non_tty_title_once_and_each_notification_once(store, count):
    output = io.StringIO()
    c = AlertCounter(clock=store)
    c.bind(NET)
    with MonitorView(NET, 60, c, Console(file=output, force_terminal=False, width=100), session_id=RUN) as view:
        c.view = view
        emitted = []
        for _ in range(count):
            emitted.extend(send(c))
        view.set_phase('attente')
    text = output.getvalue()
    assert text.count(NON_TTY_TITLE) == 1
    assert '20 dernières' not in text
    assert text.count('sentinel findings show') == 1
    assert text.rstrip().endswith(FOOTER_COMMAND)
    assert len(emitted) == count
    for finding in emitted:
        assert text.count(finding.id) == 1  # emitted exactly once, full UUID


def test_non_tty_zero_notification_is_explicit_once(store):
    output = io.StringIO()
    c = AlertCounter(clock=store)
    c.bind(NET)
    with MonitorView(NET, 60, c, Console(file=output, force_terminal=False, width=100), session_id=RUN) as view:
        c.view = view
    text = output.getvalue()
    assert text.count(NON_TTY_TITLE) == 1
    assert text.count('Aucune notification affichée pendant cette exécution.') == 1
    assert text.count('sentinel findings show') == 1
    assert text.rstrip().endswith(FOOTER_COMMAND)


def test_non_tty_footer_and_title_once_after_ctrl_c(store):
    output = io.StringIO()
    c = AlertCounter(clock=store)
    c.bind(NET)
    emitted = []
    with pytest.raises(KeyboardInterrupt):
        with MonitorView(NET, 60, c, Console(file=output, force_terminal=False, width=100), session_id=RUN) as view:
            c.view = view
            emitted.extend(send(c))
            raise KeyboardInterrupt
    text = output.getvalue()
    assert text.count(NON_TTY_TITLE) == 1
    assert text.count('sentinel findings show') == 1
    assert text.rstrip().endswith(FOOTER_COMMAND)
    assert text.count(emitted[0].id) == 1


def test_tty_notification_printed_once_above_frame_without_list_title(store):
    output = io.StringIO()
    c = AlertCounter(clock=store)
    c.bind(NET)
    with MonitorView(NET, 60, c, Console(file=output, force_terminal=True, width=120), session_id=RUN) as view:
        c.view = view
        finding, = send(c)
        view.set_phase('attente')
    text = output.getvalue()
    assert TTY_LIST_TITLE not in text  # the live frame no longer holds the alert list
    assert NON_TTY_TITLE not in text
    assert text.count(finding.id) == 1
    assert text.count('sentinel findings show') >= 1


def test_start_with_absent_gateway_warns_and_runs_normally(store, monkeypatch):
    from sentinel import sentinel_manager as manager
    from sentinel.baseline import NetworkIdentity, compute_network_id
    identity = NetworkIdentity('192.0.2.0/24', '', '')
    network = compute_network_id(identity)
    messages, loops = [], []
    monkeypatch.setattr(manager, 'display', lambda *args, **kwargs: messages.append(str(args[0]) if args else ''))
    monkeypatch.setattr(manager, 'detect_network_identity', lambda target: identity)
    monkeypatch.setattr(manager, 'baseline_exists', lambda *args: True)
    monkeypatch.setattr(manager, '_run_loop', lambda **kwargs: loops.append(kwargs['identity']))
    manager.start('192.0.2.0/24', 'gateway-absent')
    assert loops == [identity]  # the monitor cycle still starts
    assert any('could not determine gateway IP' in m for m in messages)
    assert any('Network identity is partial' in m for m in messages)
    assert not any('Échec' in m or 'failed' in m.lower() for m in messages)
    assert db.get_session('gateway-absent')['status'] == 'completed'
    assert db.sentinel_get_state(network)['sentinel_status'] == 'inactive'


# ---------------------------------------------------------------------------
# T23-A correction — bounded live frame, notifications printed once above it
# ---------------------------------------------------------------------------

HOST_ROW_RE = re.compile(r'192\.0\.2\.\d+')
HIDDEN_RE = re.compile(r'(\d+) hôte\(s\) non affiché')


def _frame_text(view, width, height):
    buffer = io.StringIO()
    Console(file=buffer, width=width, height=height).print(view)
    return buffer.getvalue()


def _frame_height(view, width, height):
    console = Console(file=io.StringIO(), force_terminal=True, width=width, height=height)
    return len(console.render_lines(view, console.options, pad=False))


def _fourteen_hosts_twenty_notifications(c):
    emitted = []
    for i in range(10, 24):  # 14 hosts, one notification each
        emitted.extend(send(c, NetworkChange('new_host', f'192.0.2.{i}', 'new host detected', 'test')))
    for i in range(10, 16):  # 6 more notifications on known hosts (quota allows 3 per host)
        emitted.extend(send(c, NetworkChange('new_host', f'192.0.2.{i}', 'new host detected', 'test')))
    assert len(emitted) == 20
    return emitted


@pytest.mark.parametrize('rows,cols', [(24, 80), (30, 169)])
def test_tty_frame_bounded_and_notifications_outside_frame(store, rows, cols):
    output = io.StringIO()
    console = Console(file=output, force_terminal=True, width=cols, height=rows)
    c = AlertCounter(clock=store)
    c.bind(NET)
    with MonitorView(NET, 60, c, console, session_id=RUN) as view:
        c.view = view
        emitted = _fourteen_hosts_twenty_notifications(c)
        # Height never reaches the terminal height: Live.stop() ends with a newline.
        assert _frame_height(view, cols, rows) <= rows - 1
        frame = _frame_text(view, cols, rows)
        # Notifications are not in the frame; hidden hosts are counted, never silently dropped.
        for finding in emitted:
            assert finding.id not in ''.join(frame.split())
        shown = len(HOST_ROW_RE.findall(frame))
        hidden = int(HIDDEN_RE.search(frame).group(1)) if HIDDEN_RE.search(frame) else 0
        assert shown + hidden == 14
        assert 'Notifications affichées cette exécution : 20' in frame
        assert frame.count('sentinel findings show') == 1
    text = output.getvalue()
    for finding in emitted:  # written exactly once, at emission
        assert text.count(finding.id) == 1


def test_tty_tall_terminal_shows_every_host_without_note(store):
    cols, rows = 140, 60
    output = io.StringIO()
    c = AlertCounter(clock=store)
    c.bind(NET)
    with MonitorView(NET, 60, c, Console(file=output, force_terminal=True, width=cols, height=rows), session_id=RUN) as view:
        c.view = view
        _fourteen_hosts_twenty_notifications(c)
        frame = _frame_text(view, cols, rows)
    assert len(HOST_ROW_RE.findall(frame)) == 14
    assert 'non affiché' not in frame
    assert _frame_height(view, cols, rows) <= rows - 1


def test_tty_refresh_without_notification_redraws_frame_in_place(store):
    cols, rows = 80, 24
    output = io.StringIO()
    console = Console(file=output, force_terminal=True, width=cols, height=rows)
    c = AlertCounter(clock=store)
    c.bind(NET)
    with MonitorView(NET, 60, c, console, session_id=RUN) as view:
        c.view = view
        _fourteen_hosts_twenty_notifications(c)
        height = _frame_height(view, cols, rows)
        for _ in range(3):
            before = len(output.getvalue())
            view.live.refresh()  # no new notification
            redraw = output.getvalue()[before:]
            # Each redraw moves the cursor back to the top of the frame and rewrites it:
            # no line is added to the output, hence nothing accumulates above the frame.
            assert redraw.count('\x1b[1A') == height - 1
            assert redraw.count('\n') == height - 1
            assert 'UUID du Finding' not in redraw


def test_non_tty_phase_transitions_print_snapshot_once(store):
    output = io.StringIO()
    c = AlertCounter(clock=store)
    c.bind(NET)
    with MonitorView(NET, 60, c, Console(file=output, force_terminal=False, width=100), session_id=RUN) as view:
        c.view = view
        emitted = _fourteen_hosts_twenty_notifications(c)
        for phase in ('contrôle', 'attente', 'contrôle', 'attente'):
            view.set_phase(phase, store().isoformat())
    text = output.getvalue()
    assert text.count('SENTINEL ● SURVEILLANCE ACTIVE') == 1
    assert text.count('État des hôtes') == 1
    assert text.count(NON_TTY_TITLE) == 1
    assert text.count('sentinel findings show') == 1
    assert '\x1b' not in text
    for finding in emitted:
        assert text.count(finding.id) == 1


# ---------------------------------------------------------------------------
# Plain-log progress line after each check that ended (presentation only)
# ---------------------------------------------------------------------------

PROGRESS_RE = re.compile(r'^\[\d{2}:\d{2}:\d{2}\] (Contrôle [^—]+) — (.+)\.$', re.M)


@pytest.mark.parametrize('width', [120, 40])
def test_non_tty_one_progress_line_per_completed_check(store, width):
    output = io.StringIO()
    c = AlertCounter(clock=store)
    c.bind(NET)
    with MonitorView(NET, 60, c, Console(file=output, force_terminal=False, width=width), session_id=RUN) as view:
        c.view = view
        view.set_phase('contrôle')
        (finding,) = send(c)
        view.set_phase('attente')  # transition without an end of check: no line
        view.set_phase('attente', store().isoformat())  # the check ended: one line
        view.set_phase('contrôle')
        view.set_phase('attente')
        view.set_phase('attente', store().isoformat())  # second check, no notification
    text = output.getvalue()
    lines = PROGRESS_RE.findall(text)
    assert lines == [
        ('Contrôle terminé', '1 notification(s) affichée(s) pendant ce contrôle'),
        ('Contrôle terminé', 'aucune notification affichée pendant ce contrôle'),
    ]
    assert text.count(finding.id) == 1  # the progress line never repeats a notification
    assert '\x1b' not in text


@pytest.mark.parametrize('phase,label', [
    ('dégradé', 'Contrôle partiel, non enregistré comme réussi'),
    ('erreur', 'Contrôle en échec, non enregistré comme réussi'),
])
def test_non_tty_partial_or_failed_check_is_never_announced_as_success(store, phase, label):
    output = io.StringIO()
    c = AlertCounter(clock=store)
    c.bind(NET)
    with MonitorView(NET, 60, c, Console(file=output, force_terminal=False, width=120), session_id=RUN) as view:
        c.view = view
        view.set_phase('contrôle')
        view.set_phase(phase, store().isoformat())
    text = output.getvalue()
    assert PROGRESS_RE.findall(text) == [(label, 'aucune notification affichée pendant ce contrôle')]
    assert 'Contrôle terminé' not in text


class _CycleOwner:
    """Drives the real _run_loop for a fixed number of cycles, then ends it cooperatively."""

    def __init__(self, cycles):
        self.left = cycles

    def wait(self, seconds):
        if self.left == 0:
            return True
        self.left -= 1
        return False

    def admit_cycle(self):
        return True

    def end_cycle(self):
        pass


@pytest.mark.parametrize('tty', [False, True])
def test_real_loop_progress_follows_each_check_outcome(store, monkeypatch, tty):
    from sentinel import sentinel_manager as manager
    from sentinel.monitor import ScanDegradedError
    from sentinel.whitelist import Whitelist
    from unittest.mock import Mock
    monkeypatch.setattr(manager, 'get_baseline', lambda *args: {'known': object()})
    outcomes = [
        [NetworkChange('new_host', HOST, 'new host detected', 'test')],  # success, one notification
        [],                                                            # success, nothing new
        ScanDegradedError('simulated partial', []),                    # partial: not a success
    ]
    monkeypatch.setattr(manager, 'check_network', Mock(side_effect=outcomes))
    output = io.StringIO()
    c = AlertCounter(clock=store)
    c.bind(NET)
    with MonitorView(NET, 60, c, Console(file=output, force_terminal=tty, width=120), session_id=RUN) as view:
        c.view = view
        manager._run_loop(target_network='192.0.2.0/24', network_id=NET, run_session_id=RUN,
                          identity=object(), interval=60, whitelist=Whitelist(), counter=c,
                          owner=_CycleOwner(len(outcomes)))
    text = output.getvalue()
    findings = db.get_findings(RUN)
    assert len(findings) == 1
    if tty:
        # TTY keeps its frame: no progress line at all (the frame itself may show the id).
        assert 'Contrôle terminé' not in text and 'Contrôle partiel' not in text
        return
    assert text.count(findings[0].id) == 1  # plain log: the notification is printed once
    assert [label for label, _ in PROGRESS_RE.findall(text)] == [
        'Contrôle terminé', 'Contrôle terminé', 'Contrôle partiel, non enregistré comme réussi']
    assert PROGRESS_RE.findall(text)[0][1] == '1 notification(s) affichée(s) pendant ce contrôle'
    assert text.count('SENTINEL ● SURVEILLANCE ACTIVE') == 1
    assert text.count('État des hôtes') == 1
    assert text.count('sentinel findings show') == 1
    assert '\x1b' not in text
