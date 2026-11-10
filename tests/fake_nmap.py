"""Fake ``nmap`` executable for interruption tests (POSIX only).

No network and no installed nmap are needed: a shell wrapper named ``nmap`` is
placed first on PATH and runs this script with the same interpreter. Behaviour
is selected by environment variables:

- FAKE_NMAP_MODE: ``sleep`` (run until killed), ``ignore-term`` (ignores SIGTERM),
  ``xml-by-ip`` (serve ``<target>.xml`` from FAKE_NMAP_DIR, '/' replaced by '_'; exit 1 if absent),
  ``exit1`` (exit 1), ``hang-ip`` (serve XML, but the target FAKE_NMAP_HANG never
  answers: its pid is written to FAKE_NMAP_HANGPID and the process sleeps).
- FAKE_NMAP_COUNT: file appended on every invocation.
- FAKE_NMAP_PIDFILE: file receiving the pid of every invocation.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

FAKE_NMAP = r'''
import os, signal, sys, time
from pathlib import Path

mode = os.environ['FAKE_NMAP_MODE']
target = sys.argv[-1]
with open(os.environ['FAKE_NMAP_COUNT'], 'a') as handle:
    handle.write(target + '\n')
Path(os.environ['FAKE_NMAP_PIDFILE']).write_text(str(os.getpid()))
base = Path(os.environ['FAKE_NMAP_DIR'])

if mode == 'hang-ip' and target == os.environ.get('FAKE_NMAP_HANG'):
    Path(os.environ['FAKE_NMAP_HANGPID']).write_text(str(os.getpid()))
    time.sleep(60)
elif mode == 'sleep':
    time.sleep(60)
elif mode == 'ignore-term':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(60)
elif mode in ('xml-by-ip', 'hang-ip'):
    xml = base / (target.replace('/', '_') + '.xml')  # a CIDR target is served by 'A_B_C_D_N.xml'
    if not xml.exists():
        sys.exit(1)
    sys.stdout.write(xml.read_text(encoding='utf-8'))
    sys.exit(0)
elif mode == 'exit1':
    sys.exit(1)
'''


def pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def install(tmp_path, monkeypatch, mode, hang=None):
    """Put the fake nmap first on PATH and export its settings for this test."""
    if sys.platform == 'win32':
        pytest.skip('fake nmap is a POSIX shell wrapper')
    bindir = tmp_path / 'fake-bin'
    bindir.mkdir(exist_ok=True)
    script = tmp_path / 'fake_nmap.py'
    script.write_text(FAKE_NMAP, encoding='utf-8')
    wrapper = bindir / 'nmap'
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding='utf-8')
    wrapper.chmod(0o755)
    monkeypatch.setenv('PATH', f'{bindir}{os.pathsep}{os.environ["PATH"]}')
    monkeypatch.setenv('FAKE_NMAP_MODE', mode)
    monkeypatch.setenv('FAKE_NMAP_DIR', str(tmp_path))
    monkeypatch.setenv('FAKE_NMAP_COUNT', str(tmp_path / 'count'))
    monkeypatch.setenv('FAKE_NMAP_PIDFILE', str(tmp_path / 'pid'))
    monkeypatch.setenv('FAKE_NMAP_HANGPID', str(tmp_path / 'hang.pid'))
    if hang is not None:
        monkeypatch.setenv('FAKE_NMAP_HANG', hang)


def runs(tmp_path):
    count = tmp_path / 'count'
    return len(count.read_text().splitlines()) if count.exists() else 0


def hang_pid(tmp_path):
    path = tmp_path / 'hang.pid'
    return int(path.read_text()) if path.exists() else None


def kill_leftovers(tmp_path):
    """Failure recovery only: never leave a fake scan running after a test."""
    for name in ('pid', 'hang.pid'):
        path = tmp_path / name
        if path.exists() and pid_alive(int(path.read_text())):
            os.kill(int(path.read_text()), 9)
