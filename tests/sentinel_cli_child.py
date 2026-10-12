"""Subprocess test entry point: real Typer CLI, simulated network adapters only.

Not shipped as a runtime mode. No production environment-variable test hooks.
"""
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core import database as db
from sentinel import sentinel_manager as manager, monitor
from sentinel.baseline import NetworkIdentity
from sentinel.whitelist import Whitelist
from sentinel.lifecycle import Owner

home = Path(os.environ['SENTINEL_TEST_HOME'])
db._real_user_home = lambda: home
mode = os.environ.get('SENTINEL_TEST_MODE', 'normal')
run = os.environ.get('SENTINEL_TEST_RUN', 'unused')
markers = home / 'markers'
markers.mkdir(parents=True, exist_ok=True)


def mark(suffix, text='1'):
    (markers / (run + '.' + suffix)).write_text(text)


def forbidden(*args, **kwargs):
    raise AssertionError('Real network/scanner forbidden in lifecycle tests')


socket.socket = forbidden
subprocess.Popen = forbidden
monitor._get_arp_mac = lambda ip: ''
monitor._get_open_ports = lambda ip: None if mode == 'degraded' else [22]
monitor._get_active_hosts = lambda target: ['192.0.2.10', '192.0.2.99']
manager.detect_network_identity = lambda target: NetworkIdentity(target, '192.0.2.1', '02:00:00:00:00:01')
manager._load_interval = lambda: .05
manager.typer.confirm = lambda *args, **kwargs: True
manager.load_whitelist = lambda: Whitelist(allowed_new_hosts=['192.0.2.99'] if mode == 'whitelisted' else [])


def learn(target_network, network_id, identity, force_relearn=False):
    asset = uuid.uuid4().hex
    db.sentinel_save_asset(network_id, asset, '192.0.2.10', '2026-10-10T12:00:00+00:00')
    db.sentinel_save_baseline_entry(network_id, uuid.uuid4().hex, asset,
        target_network, identity.gateway_ip, identity.gateway_mac, [22], '',
        '2026-10-10T12:00:00+00:00')
    return True


manager.learn_baseline = learn
original_check = manager.check_network
cycles = 0


def check(**kwargs):
    global cycles
    cycles += 1
    mark('cycles', str(cycles))
    mark('entered')
    deadline = time.monotonic() + 20
    while not (markers / (run + '.release')).exists():
        if time.monotonic() > deadline:
            raise AssertionError('Test orchestrator did not release simulated scan')
        time.sleep(.01)
    if mode == 'fatal':
        raise RuntimeError('FATAL_SECRET_CANARY simulated fatal check')
    result = original_check(**kwargs)
    mark('checked')
    return result


manager.check_network = check
original_wait = Owner.wait


def wait(self, seconds):
    if cycles:
        mark('waiting')
        seconds = 60
    return original_wait(self, seconds)


Owner.wait = wait
if mode == 'finalization-failure':
    def failed(*args, **kwargs):
        raise OSError('simulated finalization failure')
    manager.close_session = failed

if mode in ('race-stop-first', 'race-admission-first'):
    original_admit = Owner.admit_cycle
    def gated_admit(self):
        # Pause exactly on either side of the atomic admission commit, after
        # the idle polling check has already returned. Files are barriers, not
        # timing guesses about how long the other CLI might take.
        admitted = None
        if mode == 'race-admission-first':
            admitted = original_admit(self)
        mark('admission-ready')
        deadline = time.monotonic() + 20
        while not (markers / (run + '.admission-release')).exists():
            if time.monotonic() > deadline:
                raise AssertionError('Test did not release cycle admission')
            time.sleep(.01)
        return original_admit(self) if admitted is None else admitted
    Owner.admit_cycle = gated_admit

if mode == 'delayed-exit':
    original_start = manager.start
    def delayed_start(*args, **kwargs):
        original_start(*args, **kwargs)
        mark('finalized')
        deadline = time.monotonic() + 20
        while not (markers / (run + '.exit')).exists():
            if time.monotonic() > deadline:
                raise AssertionError('Test did not release process exit')
            time.sleep(.01)
    manager.start = delayed_start

if mode == 'save-interrupt':
    original_save = manager.save_session
    def save_then_interrupt(*args, **kwargs):
        original_save(*args, **kwargs)
        raise KeyboardInterrupt('SAVE_SECRET_CANARY')
    manager.save_session = save_then_interrupt

from cli import app
app()
