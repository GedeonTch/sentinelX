"""Sentinel monitor stays reactive during Nmap: a stop request interrupts the scan.

The real subprocess path is exercised with a fake ``nmap`` executable placed first
on PATH: no network, no installed nmap, no real scan. The fake is a POSIX shell
wrapper, so the process tests are skipped on Windows; the rest runs everywhere.
"""
import os
import subprocess
import sys
import time
from unittest.mock import Mock, patch

import pytest

from core import process_control as pc
from core.process_control import ScanInterrupted, run_process
from sentinel import monitor, sentinel_manager as manager
from sentinel.baseline import BaselineEntry, NetworkIdentity
from sentinel.monitor import _get_active_hosts, _get_open_ports, check_network
from tests.fake_nmap import install, kill_leftovers, pid_alive, runs
from tests.test_sentinel_baseline_reliability import nmap_tcp_xml

pytestmark = pytest.mark.skipif(sys.platform == 'win32', reason='fake nmap is a POSIX shell wrapper')

IDENTITY = NetworkIdentity('192.0.2.0/24', '192.0.2.1', '02:00:00:00:00:01')


@pytest.fixture
def fake_nmap(tmp_path, monkeypatch):
    install(tmp_path, monkeypatch, 'sleep')  # each test selects its mode with setenv
    yield tmp_path
    kill_leftovers(tmp_path)


def started(tmp_path):
    """Predicate: the fake nmap process has started (its pid is written)."""
    return lambda: (tmp_path / 'pid').exists()


def pid_of(tmp_path):
    return int((tmp_path / 'pid').read_text())


CMD = ['nmap', '-sn', '-oX', '-', '192.0.2.10']


class TestRunProcess:
    def test_stop_during_running_nmap_terminates_the_child(self, fake_nmap, monkeypatch):
        monkeypatch.setenv('FAKE_NMAP_MODE', 'sleep')
        began = time.monotonic()
        with pytest.raises(ScanInterrupted):
            run_process(CMD, 300, started(fake_nmap))
        assert time.monotonic() - began < 3, 'stop must be honoured within a few poll intervals'
        assert not pid_alive(pid_of(fake_nmap)), 'no nmap process may survive the stop'

    def test_stop_before_start_never_launches_nmap(self, fake_nmap, monkeypatch):
        monkeypatch.setenv('FAKE_NMAP_MODE', 'sleep')
        with pytest.raises(ScanInterrupted):
            run_process(CMD, 300, lambda: True)
        assert runs(fake_nmap) == 0

    def test_child_ignoring_sigterm_is_killed_after_grace(self, fake_nmap, monkeypatch):
        monkeypatch.setenv('FAKE_NMAP_MODE', 'ignore-term')
        monkeypatch.setattr(pc, 'STOP_GRACE', 0.5)
        began = time.monotonic()
        with pytest.raises(ScanInterrupted):
            run_process(CMD, 300, started(fake_nmap))
        elapsed = time.monotonic() - began
        assert 0.5 <= elapsed < 5, f'terminate() ignored: kill() must follow the grace period ({elapsed:.2f}s)'
        assert not pid_alive(pid_of(fake_nmap))

    def test_timeout_kills_the_child_and_raises_timeout(self, fake_nmap, monkeypatch):
        monkeypatch.setenv('FAKE_NMAP_MODE', 'sleep')
        with pytest.raises(subprocess.TimeoutExpired):
            run_process(CMD, 0.5, lambda: False)
        assert not pid_alive(pid_of(fake_nmap))

    def test_keyboard_interrupt_during_wait_kills_the_child(self, fake_nmap, monkeypatch):
        monkeypatch.setenv('FAKE_NMAP_MODE', 'sleep')

        def ctrl_c():
            if (fake_nmap / 'pid').exists():
                raise KeyboardInterrupt
            return False

        with pytest.raises(KeyboardInterrupt):
            run_process(CMD, 300, ctrl_c)
        assert not pid_alive(pid_of(fake_nmap))

    def test_large_output_does_not_block_the_child(self, fake_nmap, monkeypatch):
        """No PIPE without a reader: a 2 MiB XML document must come back whole."""
        monkeypatch.setenv('FAKE_NMAP_MODE', 'xml-by-ip')
        payload = 'x' * (2 * 1024 * 1024)
        (fake_nmap / '192.0.2.10.xml').write_text(payload, encoding='utf-8')
        completed = run_process(CMD, 60, lambda: False)
        assert completed.returncode == 0
        assert completed.stdout == payload

    def test_without_predicate_it_is_the_historic_subprocess_run(self):
        done = subprocess.CompletedProcess(CMD, 0, 'ok', '')
        with patch('core.process_control.subprocess.run', return_value=done) as run:
            assert run_process(CMD, 300) is done
        run.assert_called_once_with(CMD, capture_output=True, text=True, timeout=300)


class TestMonitorReactivity:
    def test_stop_during_ping_is_an_interruption_not_an_unknown_result(self, fake_nmap, monkeypatch):
        monkeypatch.setenv('FAKE_NMAP_MODE', 'sleep')
        with pytest.raises(ScanInterrupted):
            _get_active_hosts('192.0.2.0/24', should_stop=started(fake_nmap))
        assert not pid_alive(pid_of(fake_nmap))

    def test_stop_during_tcp_scan_is_an_interruption_not_an_unknown_result(self, fake_nmap, monkeypatch):
        monkeypatch.setenv('FAKE_NMAP_MODE', 'sleep')
        with pytest.raises(ScanInterrupted):
            _get_open_ports('192.0.2.10', should_stop=started(fake_nmap))
        assert not pid_alive(pid_of(fake_nmap))

    def test_stop_between_two_hosts_skips_the_next_host(self, fake_nmap, monkeypatch):
        monkeypatch.setenv('FAKE_NMAP_MODE', 'xml-by-ip')
        (fake_nmap / '192.0.2.10.xml').write_text(nmap_tcp_xml('192.0.2.10', open_ports=[22]), encoding='utf-8')
        done = {'hosts': 0}
        attempted = []   # every attempt, even one that the scanner refuses to start
        real_get_open_ports = monitor._get_open_ports

        def counting(ip, skip_host_discovery=False, should_stop=None):
            attempted.append(ip)
            result = real_get_open_ports(ip, skip_host_discovery=skip_host_discovery, should_stop=should_stop)
            done['hosts'] += 1
            return result

        monkeypatch.setattr(monitor, '_get_open_ports', counting)
        monkeypatch.setattr(monitor, '_get_active_hosts',
                            lambda target, should_stop=None: ['192.0.2.10', '192.0.2.11'])
        with pytest.raises(ScanInterrupted):
            check_network('192.0.2.0/24', 'run', IDENTITY, {}, set(),
                          should_stop=lambda: done['hosts'] >= 1)
        assert attempted == ['192.0.2.10'], 'the second host must not even be attempted after the stop'
        assert done['hosts'] == 1
        assert runs(fake_nmap) == 1

    def test_nominal_timeout_is_300_seconds_on_both_monitor_scans(self):
        stop = lambda: False
        with patch('detect.tcp_scan.run_process',
                   return_value=subprocess.CompletedProcess([], 0, nmap_tcp_xml('192.0.2.10'), '')) as tcp_run:
            assert _get_open_ports('192.0.2.10', should_stop=stop) == []
        assert tcp_run.call_args.args[1] == 300 and tcp_run.call_args.args[2] is stop
        with patch('recon.device_fingerprint.run_process',
                   return_value=subprocess.CompletedProcess([], 0, '', '')) as ping_run:
            _get_active_hosts('192.0.2.0/24', should_stop=stop)
        assert ping_run.call_args.args[1] == 300 and ping_run.call_args.args[2] is stop

    def test_real_timeout_is_unknown_not_empty(self, fake_nmap, monkeypatch):
        monkeypatch.setenv('FAKE_NMAP_MODE', 'sleep')
        real_run = pc.run_process

        def short_deadline(cmd, timeout, should_stop=None):
            return real_run(cmd, 0.5, should_stop)

        monkeypatch.setattr('detect.tcp_scan.run_process', short_deadline)
        assert _get_open_ports('192.0.2.10', should_stop=lambda: False) is None
        assert not pid_alive(pid_of(fake_nmap))

    def test_complete_scan_without_open_port_is_empty_list(self, fake_nmap, monkeypatch):
        monkeypatch.setenv('FAKE_NMAP_MODE', 'xml-by-ip')
        (fake_nmap / '192.0.2.10.xml').write_text(nmap_tcp_xml('192.0.2.10'), encoding='utf-8')
        assert _get_open_ports('192.0.2.10', should_stop=lambda: False) == []

    def test_non_zero_exit_is_unknown_with_the_interruptible_runner(self, fake_nmap, monkeypatch):
        monkeypatch.setenv('FAKE_NMAP_MODE', 'exit1')
        assert _get_open_ports('192.0.2.10', should_stop=lambda: False) is None


class TestCycleAbandon:
    def _state(self):
        return manager.NetworkState(
            stamp=Mock(), known_hosts=set(), initial_ports={}, ports_initialized={},
            open_ports={}, port_absent_count={}, notified_port_not_open={},
            host_absent_count={}, host_not_observed=set(),
        )

    def test_interrupted_check_persists_nothing(self, monkeypatch):
        entry = BaselineEntry('asset', '192.0.2.10', '', [22], '')
        monkeypatch.setattr(manager, 'get_baseline', lambda *args: {'192.0.2.10': entry})
        monkeypatch.setattr(manager, 'check_network', Mock(side_effect=ScanInterrupted('stop')))
        persisted = Mock()
        monkeypatch.setattr(manager, 'process_changes', persisted)
        state_update = Mock()
        monkeypatch.setattr(manager, 'sentinel_update_state', state_update)
        state = self._state()
        with pytest.raises(ScanInterrupted):
            manager._do_check(target_network='192.0.2.0/24', network_id='net', run_session_id='run',
                              identity=IDENTITY, interval=60, whitelist=Mock(), counter=Mock(),
                              state=state, should_stop=lambda: True)
        persisted.assert_not_called()          # no transition, no scan_degraded
        state_update.assert_not_called()       # no last_check, no status change
        assert state.scan_degraded_active is False
        assert state.host_absent_count == {} and state.port_absent_count == {}

    def test_interrupted_cycle_is_released_and_the_loop_returns(self, monkeypatch):
        class Owner:
            def __init__(self):
                self.waits = 0
                self.ended = 0

            def wait(self, seconds):
                self.waits += 1
                return False

            def admit_cycle(self):
                return True

            def requested(self):
                return False

            def end_cycle(self):
                self.ended += 1

        owner = Owner()
        seen = {}

        def interrupted(**kwargs):
            seen.update(kwargs)
            raise ScanInterrupted('stop during the check')

        monkeypatch.setattr(manager, '_do_check', interrupted)
        counter = Mock()
        manager._run_loop(target_network='192.0.2.0/24', network_id='net', run_session_id='run',
                          identity=IDENTITY, interval=60, whitelist=Mock(), counter=counter,
                          owner=owner, state=self._state())  # returns normally
        assert owner.ended == 1, 'end_cycle must release the cycle exactly once'
        assert owner.waits == 1, 'no further cycle may start after the interruption'
        assert seen['should_stop'] == owner.requested
        counter.phase.assert_called_with('arrêt')

    def test_a_normal_cycle_still_releases_and_continues(self, monkeypatch):
        class Owner:
            def __init__(self):
                self.waits = 0
                self.ended = 0

            def wait(self, seconds):
                self.waits += 1
                return self.waits > 2

            def admit_cycle(self):
                return True

            def requested(self):
                return False

            def end_cycle(self):
                self.ended += 1

        owner = Owner()
        monkeypatch.setattr(manager, '_do_check', Mock())
        manager._run_loop(target_network='192.0.2.0/24', network_id='net', run_session_id='run',
                          identity=IDENTITY, interval=60, whitelist=Mock(), counter=Mock(),
                          owner=owner, state=self._state())
        assert manager._do_check.call_count == 2
        assert owner.ended == 2
