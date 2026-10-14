"""Final monitor contract and installed CLI; only temporary databases, no probes."""
import dataclasses
import hashlib
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid

import pytest
from rich.console import Console
from typer.testing import CliRunner

from core import database as db, logger
from core.finding import Evidence
from sentinel.alerting import AlertCounter, _make_finding
from sentinel.monitor import NetworkChange
from sentinel.monitor_view import MonitorView
from tests.test_sentinel_notifications import store, send, NET, HOST, RUN


@pytest.mark.parametrize('tty,width', [(False, 35), (False, 120), (True, 35), (True, 120)])
@pytest.mark.parametrize('count', [1, 3])
@pytest.mark.parametrize('interrupt', [False, True])
def test_final_footer_uuid_and_session(store, tty, width, count, interrupt):
    c = AlertCounter(clock=store)
    c.bind(NET)
    output = io.StringIO()
    console = Console(file=output, force_terminal=tty, width=width)
    view = MonitorView(NET, 60, c, console, session_id=RUN)
    emitted = []
    try:
        with view:
            c.view = view
            for _ in range(count):
                emitted.extend(send(c))
            if count == 3:
                assert send(c, NetworkChange('new_port', HOST, 'MASKED_FINAL_CANARY', 'test')) == []
            view.set_phase('attente')
            # TTY redrawing repeats bytes, not instructions within a visible frame.
            for _ in range(2):
                frame = io.StringIO()
                Console(file=frame, width=width).print(view)
                text = frame.getvalue()
                assert text.count('sentinel findings show') == 1
                assert text.rfind('sentinel findings show') > text.rfind('UUID du Finding')
                assert f'-s{RUN}' in ''.join(text.split())
                assert 'netlab' not in text
                assert ''.join(text.split()).index(RUN) < ''.join(text.split()).index(emitted[0].id)
                for finding in emitted:
                    assert finding.id in ''.join(text.split())  # all 36 characters; no borders/ellipsis
                    if width >= 36:
                        assert finding.id in text
                assert 'MASKED_FINAL_CANARY' not in text
            if not tty:
                assert 'sentinel findings show' not in output.getvalue()
            if interrupt:
                raise KeyboardInterrupt
    except KeyboardInterrupt:
        assert interrupt
    raw = re.sub(r'\x1b\[[0-9;?]*[A-Za-z]', '', output.getvalue())
    assert ''.join(raw.split()).endswith(f'sentinelfindingsshow<UUID_COMPLET>-s{RUN}')
    if not tty:
        assert raw.count('sentinel findings show') == 1
        for finding in emitted:
            assert ''.join(raw.split()).count(finding.id) == 1
    else:
        assert not view.live.is_started
    if count == 3:
        masked = [f for f in db.get_findings(RUN) if f.id not in {e.id for e in emitted}]
        assert len(masked) == 1
        assert masked[0].id not in raw
    assert 'MASKED_FINAL_CANARY' not in raw


def test_view_refuses_other_session_without_rendering(store):
    output = io.StringIO()
    c = AlertCounter(clock=store)
    c.bind(NET)
    view = MonitorView(NET, 60, c, Console(file=output), session_id='another-run')
    finding = _make_finding(NetworkChange('new_host', HOST, 'new', 'test'), RUN, str(uuid.uuid4()), store().isoformat())
    with pytest.raises(ValueError, match='session'):
        view.emit(store().isoformat(), NetworkChange('new_host', HOST, 'new', 'test'), finding)
    assert not view.rows and finding.id not in output.getvalue()


@pytest.fixture
def consultation(tmp_path, monkeypatch):
    monkeypatch.setattr(db, '_real_user_home', lambda: tmp_path)
    for sid, profile in [('sentinel-a', 'sentinel'), ('sentinel-b', 'sentinel'), ('scan-a', 'normal')]:
        db.init_db(sid)
        db.save_session(sid, target=HOST, profile=profile)
    identifier = str(uuid.uuid4())
    findings = {}
    for sid in ('sentinel-a', 'sentinel-b', 'scan-a'):
        finding = _make_finding(NetworkChange('new_host', HOST, 'new', f'EVIDENCE_{sid}'),
                                sid, identifier, '2026-10-12T12:00:00+00:00')
        if sid == 'scan-a':
            finding = dataclasses.replace(finding, module='tcp_scan')
        db.save_finding(finding)
        findings[sid] = finding
    return tmp_path, identifier, findings


def hashes(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob('*') if p.is_file()}


def assert_data_unchanged(root, before):
    after = hashes(root)
    assert all(after.get(name) == digest for name, digest in before.items())
    # SQLite mode=ro may create WAL coordination files for a known WAL database.
    # No database, directory for an unknown session, or business data is created.
    for name in after.keys() - before.keys():
        assert name.endswith(('.db-wal', '.db-shm'))
        assert name[:-4] in before


@pytest.mark.parametrize('case', ['scan', 'mixed-finding', 'mixed-outcome', 'unknown-profile',
                                  'no-session', 'corrupt', 'unknown-session', 'unknown-id', 'short-id', 'unsafe-session'])
def test_consultation_refuses_contexts_without_writes(consultation, monkeypatch, case):
    from cli import sentinel_app
    root, identifier, findings = consultation
    sid = 'sentinel-a'
    if case == 'scan':
        sid = 'scan-a'
    elif case == 'mixed-finding':
        db.save_finding(dataclasses.replace(findings[sid], id=str(uuid.uuid4()), module='udp_scan'))
    elif case == 'mixed-outcome':
        db.save_scan_outcome(sid, HOST, 'tcp_scan', 'completed', 0)
    elif case == 'unknown-profile':
        db.save_session(sid, target=HOST, profile='unknown')
    elif case == 'no-session':
        sid = 'empty-session'
        db.init_db(sid)
    elif case == 'corrupt':
        sid = 'corrupt'
        db.get_db_path(sid).write_bytes(b'not sqlite')
    elif case == 'unknown-session':
        sid = 'absent'
    elif case == 'unknown-id':
        identifier = str(uuid.uuid4())
    elif case == 'short-id':
        identifier = identifier[:8]
    elif case == 'unsafe-session':
        sid = '../escape'
    before = hashes(root)
    monkeypatch.setattr(logger, '_console', Console(width=150))
    result = CliRunner().invoke(sentinel_app, ['findings', 'show', identifier, '-s', sid])
    assert result.exit_code != 0
    assert 'EVIDENCE_' not in result.output
    assert_data_unchanged(root, before)


def test_unknown_home_is_not_created(tmp_path, monkeypatch):
    root = tmp_path / 'not-created'
    monkeypatch.setattr(db, '_real_user_home', lambda: root)
    with pytest.raises(ValueError):
        db.sentinel_read_finding('unknown', str(uuid.uuid4()))
    assert not root.exists()


def test_installed_standalone_command_exact_session(consultation):
    root, identifier, findings = consultation
    executable = os.environ.get('SENTINEL_TEST_EXECUTABLE') or shutil.which('sentinel')
    assert executable, 'Install the project entry point before running this acceptance test'
    env = os.environ.copy()
    for name in ('SUDO_USER', 'SUDO_UID', 'PYTHONPATH'):
        env.pop(name, None)
    env.update(HOME=str(root), USERPROFILE=str(root), PYTHONDONTWRITEBYTECODE='1', NO_COLOR='1')
    before = hashes(root)
    for sid in ('sentinel-a', 'sentinel-b'):
        import shlex
        from types import SimpleNamespace
        monitor_output = io.StringIO()
        with MonitorView(NET, 60, SimpleNamespace(summary=lambda: {}),
                         Console(file=monitor_output, width=180), session_id=sid) as view:
            view.emit('2026-10-12T12:00:00+00:00',
                      NetworkChange('new_host', HOST, 'new', 'test'), findings[sid])
        lines = monitor_output.getvalue().splitlines()
        template, = [line for line in lines if line.startswith('sentinel findings show')]
        argv = shlex.split(template.replace('<UUID_COMPLET>', identifier))
        assert argv == ['sentinel', 'findings', 'show', identifier, '-s', sid]
        result = subprocess.run([executable, *argv[1:]],
                                cwd=root, env=env, text=True, capture_output=True, timeout=20)
        assert result.returncode == 0, result.stdout + result.stderr
        assert identifier in result.stdout
        assert f'EVIDENCE_{sid}' in result.stdout
        assert f'EVIDENCE_{"sentinel-b" if sid == "sentinel-a" else "sentinel-a"}' not in result.stdout
        assert 'EVIDENCE_scan-a' not in result.stdout
    result = subprocess.run([executable, 'findings', 'show', identifier, '-s', 'scan-a'],
                            cwd=root, env=env, text=True, capture_output=True, timeout=20)
    assert result.returncode != 0
    assert 'EVIDENCE_scan-a' not in result.stdout
    assert_data_unchanged(root, before)
    assert db.get_finding_by_id('scan-a', identifier) == findings['scan-a']


def test_reader_sees_committed_wal_without_recovering_events(consultation):
    root, identifier, findings = consultation
    conn = db.get_connection('sentinel-a')
    try:
        conn.execute('UPDATE findings SET evidence=? WHERE id=?',
                     ('{"raw":"COMMITTED_WAL","command":"simulated"}', identifier))
        conn.commit()
        db_before = (root / '.netlab/sessions/sentinel-a.db').read_bytes()
        wal_before = (root / '.netlab/sessions/sentinel-a.db-wal').read_bytes()
        found = db.sentinel_read_finding('sentinel-a', identifier)
        assert found.evidence.raw == 'COMMITTED_WAL'
        assert (root / '.netlab/sessions/sentinel-a.db').read_bytes() == db_before
        assert (root / '.netlab/sessions/sentinel-a.db-wal').read_bytes() == wal_before
    finally:
        conn.close()


def test_sentinel_usage_matches_invocation_name():
    from cli import app, sentinel_app

    runner = CliRunner()
    nested = runner.invoke(app, ["sentinel"], prog_name="netlab")
    standalone = runner.invoke(sentinel_app, [], prog_name="sentinel")

    assert nested.exit_code == 0, nested.output
    assert "Usage: netlab sentinel " in nested.output
    assert standalone.exit_code == 0, standalone.output
    assert "Usage: sentinel " in standalone.output
