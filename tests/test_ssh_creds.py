"""T22 SSH (password only): deterministic tests. No network, no real host, HOME is temporary.

The transport is a scripted stand-in; the clock is simulated; no real sleep happens.
"""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import builtins
import inspect
import io
import json
import multiprocessing
import os
import re
import socket
import stat
import sys
import threading

import paramiko
from paramiko.ssh_exception import BadAuthenticationType, PartialAuthentication
import pytest
from typer.testing import CliRunner

import cli
import detect.default_creds as dc
from core.finding import Confidence, Severity
from detect.credential_dictionary import CATALOG, Candidate, DictionaryError, load_catalog, load_dictionary, prepare_candidates

HOST, SESSION = '192.0.2.10', 'test-ssh'
CANARY = 'SYNTHETIC_SSH_SECRET_77'
KEY_LINE = f'[{HOST}]:22 ssh-ed25519 AAAAKEY1\n'
runner = CliRunner()


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        self.now += 0.5  # every poll advances the simulated clock; deadlines are reached quickly
        return self.now


class FakeKey:
    def get_name(self):
        return 'ssh-ed25519'

    def get_base64(self):
        return 'AAAAKEY1'


class FakeSock:
    def close(self):
        pass


class FakeTransport:
    """Scripted paramiko.Transport. Any channel, command or terminal API access is recorded."""
    FORBIDDEN = ('open_', 'invoke_', 'exec_', 'get_pty', 'request_', 'auth_publickey', 'auth_none', 'auth_interactive')

    def __init__(self, *, negotiate=True, on_auth=None, key=None, on_start=None):
        self.negotiate, self.on_auth, self.key = negotiate, on_auth, key or FakeKey()
        self.on_start = on_start
        self.active = False
        self.authenticated = False
        self.exc = None
        self.auth_calls = []
        self.closed = False
        self.forbidden_access = []

    def start_client(self, event=None):
        self.active = True
        if self.on_start is not None:
            self.on_start()  # lets a scenario move the simulated clock during negotiation
        if self.negotiate:
            event.set()  # otherwise the waiter must reach its own deadline

    def is_active(self):
        return self.active

    def get_remote_server_key(self):
        return self.key

    def auth_password(self, username, password, event=None):
        self.auth_calls.append((username, password))
        if self.on_auth is not None:
            self.on_auth(self, event)

    def is_authenticated(self):
        return self.authenticated

    def get_exception(self):
        exc, self.exc = self.exc, None
        return exc

    def close(self):
        self.closed = True
        self.active = False

    def __getattr__(self, name):
        if name.startswith(self.FORBIDDEN):
            self.forbidden_access.append(name)  # recorded; any call through it fails loudly
            def refused(*args, **kwargs):
                raise AssertionError('forbidden SSH API: ' + name)
            return refused
        raise AttributeError(name)


def accept(t, event):
    t.authenticated = True
    event.set()


def refuse(t, event):
    event.set()  # explicit USERAUTH_FAILURE: no stored exception, transport still active


def partial(t, event):
    t.exc = PartialAuthentication(['keyboard-interactive'])
    event.set()


def bad_method(t, event):
    t.exc = BadAuthenticationType('Bad authentication type', ['publickey'])
    event.set()


def silent(t, event):
    pass  # no answer after the password was sent


def drop(t, event):
    t.active = False  # connection ends during auth, without an answer


def protocol_error(t, event):
    t.exc = paramiko.SSHException(CANARY)  # server text must never leave memory
    event.set()


def locked(t, event):
    t.exc = paramiko.SSHException('too many authentication failures')
    event.set()


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setenv('USERPROFILE', str(tmp_path))
    monkeypatch.setattr(dc.socket, 'socket', Mock(side_effect=AssertionError('No real network')))
    monkeypatch.setattr(dc.typer, 'confirm', Mock(return_value=True))
    clock = FakeClock()
    monkeypatch.setattr(dc, 'time', SimpleNamespace(monotonic=clock.monotonic, sleep=lambda seconds: None))
    monkeypatch.setattr(dc, '_SSH_POLL_SECONDS', 0)
    return clock


@pytest.fixture
def sink():
    return Mock(ready=True, record=Mock(return_value=True))


def ssh(user, password=CANARY):
    return Candidate('ssh', user, password)


def dell(password=CANARY):
    base = load_catalog('dell-idrac-legacy-root')[0]
    return Candidate('ssh', base.username, password, qualified=True, provenance=base.provenance)


def ssh_run(monkeypatch, sink, candidates, factory):
    made = []

    def opener(target_ip, timeout):
        transport = factory(len(made))
        made.append(transport)
        return FakeSock(), transport

    monkeypatch.setattr(dc, '_open_ssh_transport', opener)
    report = dc.CheckReport()
    findings = dc.check_default_creds(HOST, SESSION, candidates=candidates, recorder=sink, report=report,
                                      services=('ssh',))
    return findings, report, made


def trust_file():
    return dc.ssh_trust_path()


# --- Trust on first use (TOFU) -------------------------------------------------------------

def test_first_contact_key_is_saved_before_any_password(monkeypatch, sink):
    seen = {}

    def check_then_accept(t, event):
        seen['file'] = trust_file().read_text(encoding='utf-8')
        accept(t, event)

    findings, report, made = ssh_run(monkeypatch, sink, [dell()], lambda i: FakeTransport(on_auth=check_then_accept))
    assert seen['file'] == KEY_LINE                       # stored before the password was sent
    assert report.services[0].host_keys_learned == 1
    assert len(findings) == 1 and sink.record.call_count == 1
    home = Path(os.environ['HOME'])
    assert (home / '.ssh' / 'known_hosts').exists() is False      # the OpenSSH file is never created or touched
    assert trust_file() == home / '.netlab' / 'ssh_known_hosts'
    assert stat.S_IMODE(trust_file().stat().st_mode) == 0o600
    assert stat.S_IMODE(trust_file().parent.stat().st_mode) == 0o700


def test_known_key_continues_and_file_is_not_rewritten(monkeypatch, sink):
    trust_file().parent.mkdir(parents=True)
    trust_file().write_text(KEY_LINE, encoding='utf-8')
    findings, report, made = ssh_run(monkeypatch, sink, [dell()], lambda i: FakeTransport(on_auth=accept))
    assert made[0].auth_calls == [('root', CANARY)]
    assert report.services[0].host_keys_learned == 0
    assert trust_file().read_text(encoding='utf-8') == KEY_LINE


def test_changed_key_blocks_without_password_and_is_not_replaced(monkeypatch, sink):
    old = f'[{HOST}]:22 ssh-ed25519 AAAAOLDKEY\n'
    trust_file().parent.mkdir(parents=True)
    trust_file().write_text(old, encoding='utf-8')
    findings, report, made = ssh_run(monkeypatch, sink, [dell(), ssh('admin', 'other')],
                                     lambda i: FakeTransport(on_auth=accept))
    assert len(made) == 1 and made[0].auth_calls == []    # no password sent, second candidate not reached
    assert report.services[0].details['SSH_HOST_KEY_CHANGED'] == 1
    assert report.services[0].outcomes['ERROR'] == 1
    assert trust_file().read_text(encoding='utf-8') == old  # never replaced automatically
    assert findings == [] and sink.record.call_count == 0


def test_unreadable_trust_file_blocks_without_password(monkeypatch, sink):
    trust_file().mkdir(parents=True)  # a directory where the file should be: not a regular file
    findings, report, made = ssh_run(monkeypatch, sink, [dell()], lambda i: FakeTransport(on_auth=accept))
    assert made[0].auth_calls == []
    assert report.services[0].details['SSH_TRUST_FILE_UNSAFE'] == 1
    assert findings == [] and sink.record.call_count == 0


def test_unwritable_trust_file_blocks_without_password(monkeypatch, sink):
    monkeypatch.setattr(dc.os, 'replace', Mock(side_effect=OSError('denied')))
    findings, report, made = ssh_run(monkeypatch, sink, [dell()], lambda i: FakeTransport(on_auth=accept))
    assert made[0].auth_calls == []                       # never accepted without being remembered
    assert report.services[0].details['SSH_TRUST_STORE_UNAVAILABLE'] == 1
    assert not trust_file().exists()
    assert list(trust_file().parent.glob('*.tmp')) == []  # temporary file removed
    assert sink.record.call_count == 0


def test_malformed_trust_file_blocks_without_password(monkeypatch, sink):
    trust_file().parent.mkdir(parents=True)
    trust_file().write_text('this is not a trust line\n', encoding='utf-8')
    findings, report, made = ssh_run(monkeypatch, sink, [dell()], lambda i: FakeTransport(on_auth=accept))
    assert made[0].auth_calls == []
    assert report.services[0].details['SSH_TRUST_STORE_UNAVAILABLE'] == 1


# --- Links and foreign write access on the trust file (Linux). The personal ~/.ssh/known_hosts is never read or written.

PERSONAL_LINE = f'[{HOST}]:22 ssh-ed25519 AAAAPERSONAL\n'  # would read as "changed" if it were ever consulted


@pytest.fixture
def personal(monkeypatch):
    """A personal OpenSSH file with a conflicting key, plus a watch on every open/replace/unlink of its real path."""
    path = Path(os.environ['HOME']) / '.ssh' / 'known_hosts'
    path.parent.mkdir(parents=True)
    path.write_text(PERSONAL_LINE, encoding='utf-8')
    os.chmod(path, 0o644)
    target = os.path.realpath(path)
    touched = []

    def watch(name, *args):
        for arg in args[:2]:
            if isinstance(arg, (str, bytes, os.PathLike)):
                try:
                    if os.path.realpath(os.fsdecode(arg)) == target:  # resolves links: a read through a link is caught too
                        touched.append((name, os.fsdecode(arg)))
                except (TypeError, ValueError):
                    pass

    real_os_open, real_replace, real_unlink, real_io_open = os.open, os.replace, os.unlink, io.open

    def spy_open(file, flags, *args, **kwargs):
        watch('os.open', file)
        return real_os_open(file, flags, *args, **kwargs)

    def spy_io_open(file, *args, **kwargs):
        watch('open', file)
        return real_io_open(file, *args, **kwargs)

    def spy_replace(src, dst, *args, **kwargs):
        watch('os.replace', src, dst)
        return real_replace(src, dst, *args, **kwargs)

    def spy_unlink(file, *args, **kwargs):
        watch('os.unlink', file)
        return real_unlink(file, *args, **kwargs)

    monkeypatch.setattr(os, 'open', spy_open)
    monkeypatch.setattr(os, 'replace', spy_replace)
    monkeypatch.setattr(os, 'unlink', spy_unlink)
    monkeypatch.setattr(io, 'open', spy_io_open)
    monkeypatch.setattr(builtins, 'open', spy_io_open)
    return SimpleNamespace(path=path, content=PERSONAL_LINE, mtime=os.stat(path).st_mtime_ns, touched=touched)


def assert_personal_untouched(personal):
    accesses = list(personal.touched)  # checked before this helper reads the file itself
    assert accesses == [], accesses
    assert os.stat(personal.path).st_mtime_ns == personal.mtime
    assert personal.path.read_text(encoding='utf-8') == personal.content


def test_symlink_trust_file_to_personal_known_hosts_is_refused(monkeypatch, sink, personal):
    trust_file().parent.mkdir(parents=True)
    os.symlink(personal.path, trust_file())
    findings, report, made = ssh_run(monkeypatch, sink, [dell()], lambda i: FakeTransport(on_auth=accept))
    assert made[0].auth_calls == []                                  # no password sent
    assert report.services[0].details['SSH_TRUST_FILE_UNSAFE'] == 1
    assert report.services[0].outcomes['ERROR'] == 1 and sink.record.call_count == 0
    assert trust_file().is_symlink() and os.readlink(trust_file()) == str(personal.path)  # link not replaced
    assert_personal_untouched(personal)


def test_symlinked_netlab_directory_is_refused(monkeypatch, sink, personal, tmp_path):
    elsewhere = tmp_path / 'elsewhere'
    elsewhere.mkdir()
    os.symlink(elsewhere, trust_file().parent)                       # ~/.netlab itself is a link
    findings, report, made = ssh_run(monkeypatch, sink, [dell()], lambda i: FakeTransport(on_auth=accept))
    assert made[0].auth_calls == []
    assert report.services[0].details['SSH_TRUST_FILE_UNSAFE'] == 1
    assert list(elsewhere.iterdir()) == []                           # nothing written through the link
    assert_personal_untouched(personal)


@pytest.mark.parametrize('mode', [0o666, 0o646, 0o622])
def test_trust_file_writable_by_group_or_others_is_refused(monkeypatch, sink, personal, mode):
    trust_file().parent.mkdir(parents=True)
    trust_file().write_text(KEY_LINE, encoding='utf-8')
    os.chmod(trust_file(), mode)
    findings, report, made = ssh_run(monkeypatch, sink, [dell()], lambda i: FakeTransport(on_auth=accept))
    assert made[0].auth_calls == []                                  # refused even though the key is known
    assert report.services[0].details['SSH_TRUST_FILE_UNSAFE'] == 1
    assert trust_file().read_text(encoding='utf-8') == KEY_LINE     # not repaired, not rewritten
    assert stat.S_IMODE(os.stat(trust_file()).st_mode) == mode
    assert_personal_untouched(personal)


@pytest.mark.parametrize('mode', [0o777, 0o770])
def test_trust_directory_writable_by_group_or_others_is_refused(monkeypatch, sink, personal, mode):
    trust_file().parent.mkdir(parents=True)
    os.chmod(trust_file().parent, mode)
    findings, report, made = ssh_run(monkeypatch, sink, [dell()], lambda i: FakeTransport(on_auth=accept))
    assert made[0].auth_calls == []
    assert report.services[0].details['SSH_TRUST_FILE_UNSAFE'] == 1
    assert not trust_file().exists()                                 # no file created in a foreign-writable directory
    assert stat.S_IMODE(os.stat(trust_file().parent).st_mode) == mode  # the existing directory mode is not changed
    assert_personal_untouched(personal)


def _with_uid(st, uid):
    fields = list(tuple(st)[:10])  # standard stat fields; index 4 is st_uid
    fields[4] = uid
    return os.stat_result(tuple(fields))


@pytest.mark.parametrize('target', ['file', 'directory'])
def test_foreign_owner_is_refused(monkeypatch, sink, personal, target):
    real_uid = os.getuid()
    trust_file().parent.mkdir(parents=True)
    if target == 'file':
        trust_file().write_text(KEY_LINE, encoding='utf-8')
        os.chmod(trust_file(), 0o600)
        # Only the file reports a foreign owner. The directory (owned by the real user, mode 0755) passes its
        # check, so the refusal must come from the file check itself.
        _lstat_showing(monkeypatch, lambda: _with_uid(os.stat(trust_file()), real_uid + 1))
        expected = 'SSH trust file is not owned by the current user'
    else:
        monkeypatch.setattr(dc.os, 'getuid', lambda: real_uid + 1)  # the directory is the foreign-owned object
        expected = 'SSH trust directory is not owned by the current user'
    with pytest.raises(dc.TrustFileUnsafe, match=expected):
        dc._ssh_read_trust(trust_file())
    findings, report, made = ssh_run(monkeypatch, sink, [dell()], lambda i: FakeTransport(on_auth=accept))
    assert made[0].auth_calls == []
    assert report.services[0].details['SSH_TRUST_FILE_UNSAFE'] == 1
    assert_personal_untouched(personal)


def _lstat_showing(monkeypatch, fake_for_trust):
    """Make lstat describe the trust file as fake_for_trust (simulates a swap between check and open)."""
    real_lstat = os.lstat
    wanted = os.path.abspath(trust_file())

    def lstat(path, *args, **kwargs):
        if os.path.abspath(os.fsdecode(path)) == wanted:
            return fake_for_trust()
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(dc.os, 'lstat', lstat)


def test_link_swapped_in_after_the_check_is_refused_by_nofollow(monkeypatch, sink, personal):
    trust_file().parent.mkdir(parents=True)
    os.symlink(personal.path, trust_file())
    _lstat_showing(monkeypatch, lambda: os.stat(personal.path))      # check saw a plain file; the open finds a link
    findings, report, made = ssh_run(monkeypatch, sink, [dell()], lambda i: FakeTransport(on_auth=accept))
    assert made[0].auth_calls == []
    assert report.services[0].details['SSH_TRUST_FILE_UNSAFE'] == 1
    assert_personal_untouched(personal)


def test_file_replaced_after_the_check_is_refused(monkeypatch, sink, personal, tmp_path):
    trust_file().parent.mkdir(parents=True)
    trust_file().write_text(KEY_LINE, encoding='utf-8')
    os.chmod(trust_file(), 0o600)
    decoy = tmp_path / 'decoy'
    decoy.write_text(KEY_LINE, encoding='utf-8')
    os.chmod(decoy, 0o600)
    _lstat_showing(monkeypatch, lambda: os.stat(decoy))              # check saw another inode than the one opened
    findings, report, made = ssh_run(monkeypatch, sink, [dell()], lambda i: FakeTransport(on_auth=accept))
    assert made[0].auth_calls == []
    assert report.services[0].details['SSH_TRUST_FILE_UNSAFE'] == 1
    assert_personal_untouched(personal)


def test_safe_existing_trust_file_is_still_accepted(monkeypatch, sink, personal):
    trust_file().parent.mkdir(parents=True)
    trust_file().write_text(KEY_LINE, encoding='utf-8')
    os.chmod(trust_file().parent, 0o755)                             # group/others may read, not write
    os.chmod(trust_file(), 0o644)
    findings, report, made = ssh_run(monkeypatch, sink, [dell()], lambda i: FakeTransport(on_auth=accept))
    assert made[0].auth_calls == [('root', CANARY)]
    assert report.services[0].details['SSH_TRUST_FILE_UNSAFE'] == 0
    assert_personal_untouched(personal)


# --- Authentication outcomes -------------------------------------------------------------------

def test_accepted_password_is_saved_and_no_further_action(monkeypatch, sink):
    findings, report, made = ssh_run(monkeypatch, sink, [dell()], lambda i: FakeTransport(on_auth=accept))
    assert report.services[0].outcomes['SUCCESS'] == 1
    assert sink.record.call_args.kwargs['context'] == 'ssh-password'
    assert sink.record.call_args.kwargs['kind'] == 'password'
    assert sink.record.call_args.kwargs['endpoint'] == f'{HOST}:22'
    assert sink.record.call_args.kwargs['proof'] == 'AUTHENTICATED'
    assert made[0].closed is True and made[0].forbidden_access == []
    assert len(findings) == 1


def test_refused_password_is_negative_and_does_not_stop_other_candidates(monkeypatch, sink):
    findings, report, made = ssh_run(monkeypatch, sink, [dell(), ssh('admin', 'x')],
                                     lambda i: FakeTransport(on_auth=refuse))
    assert report.services[0].outcomes['NO_MATCH'] == 2
    assert report.services[0].details['AUTH_REJECTED'] == 2
    assert report.services[0].candidates_tested == 2
    assert sink.record.call_count == 0 and findings == []


def test_method_unavailable_is_inconclusive_not_wrong_password(monkeypatch, sink):
    findings, report, made = ssh_run(monkeypatch, sink, [dell()], lambda i: FakeTransport(on_auth=bad_method))
    assert report.services[0].outcomes['INCONCLUSIVE'] == 1
    assert report.services[0].details['PASSWORD_METHOD_UNAVAILABLE'] == 1
    assert report.services[0].outcomes['NO_MATCH'] == 0
    assert report.services[0].attempts == 1 and sink.record.call_count == 0


def test_additional_factor_required_is_inconclusive(monkeypatch, sink):
    findings, report, made = ssh_run(monkeypatch, sink, [dell()], lambda i: FakeTransport(on_auth=partial))
    assert report.services[0].details['ADDITIONAL_AUTH_REQUIRED'] == 1
    assert report.services[0].outcomes['NO_MATCH'] == 0 and sink.record.call_count == 0


def test_connection_dropped_during_auth_is_error_not_refusal(monkeypatch, sink):
    findings, report, made = ssh_run(monkeypatch, sink, [dell(), ssh('admin', 'x')],
                                     lambda i: FakeTransport(on_auth=drop))
    assert report.services[0].details['CONNECTION_CLOSED_DURING_AUTH'] == 1
    assert report.services[0].outcomes['NO_MATCH'] == 0
    assert report.services[0].attempts == 1 and report.services[0].skipped['STOPPED'] == 1


def test_protocol_error_text_never_leaves_memory(monkeypatch, sink, capsys):
    findings, report, made = ssh_run(monkeypatch, sink, [dell()], lambda i: FakeTransport(on_auth=protocol_error))
    assert report.services[0].details['PROTOCOL_ERROR'] == 1
    assert CANARY not in repr(report) and CANARY not in capsys.readouterr().out


def test_lockout_wording_stops_all_checks(monkeypatch, sink):
    findings, report, made = ssh_run(monkeypatch, sink, [dell(), ssh('admin', 'x')],
                                     lambda i: FakeTransport(on_auth=locked))
    assert report.services[0].details['ACCOUNT_RESTRICTION'] == 1
    assert len(made) == 1 and report.services[0].skipped['STOPPED'] == 1


# --- Timeouts, retries and budgets -------------------------------------------------------------

def test_timeout_before_password_is_retried_at_most_three_times(monkeypatch, sink):
    findings, report, made = ssh_run(monkeypatch, sink, [dell(), ssh('admin', 'x')],
                                     lambda i: FakeTransport(negotiate=False))
    svc = report.services[0]
    assert len(made) == 3 and svc.attempts == 3                      # one candidate, three network attempts
    assert svc.candidates_tested == 1
    assert svc.outcomes['TIMEOUT'] == 3 and svc.details['TIMEOUT_BEFORE_PASSWORD'] == 3
    assert all(t.auth_calls == [] for t in made)                     # no password ever sent
    assert svc.skipped['TIMEOUT_STOP'] == 1                          # the service stops on this device
    assert sink.record.call_count == 0


def test_negotiation_finishing_after_the_attempt_deadline_sends_no_password(monkeypatch, sink, isolated):
    late = FakeTransport(on_auth=accept, on_start=lambda: setattr(isolated, 'now', isolated.now + 60))
    findings, report, made = ssh_run(monkeypatch, sink, [dell()], lambda i: late)
    assert made[0].auth_calls == []                                  # the 10 s attempt budget was already spent
    assert report.services[0].details['TIMEOUT_BEFORE_PASSWORD'] >= 1
    assert sink.record.call_count == 0


def test_socket_timeout_on_connect_is_retried_before_password(monkeypatch, sink):
    def timeout_connect(target_ip, timeout):
        raise socket.timeout()

    monkeypatch.setattr(dc, '_open_ssh_transport', timeout_connect)
    report = dc.CheckReport()
    dc.check_default_creds(HOST, SESSION, candidates=[dell()], recorder=sink, report=report, services=('ssh',))
    assert report.services[0].attempts == 3
    assert report.services[0].details['TIMEOUT_BEFORE_PASSWORD'] == 3


def test_timeout_after_password_is_never_resubmitted(monkeypatch, sink):
    findings, report, made = ssh_run(monkeypatch, sink, [dell(), ssh('admin', 'x')],
                                     lambda i: FakeTransport(on_auth=silent))
    svc = report.services[0]
    assert svc.attempts == 1 and svc.details['TIMEOUT_AFTER_PASSWORD'] == 1
    assert sum(len(t.auth_calls) for t in made) == 1                 # the same password was not sent again
    assert svc.skipped['TIMEOUT_STOP'] == 1
    assert sink.record.call_count == 0


@pytest.mark.parametrize('late', [accept, refuse], ids=['accepted', 'refused'])
def test_auth_answer_observed_after_the_deadline_is_a_timeout_not_a_result(monkeypatch, sink, isolated, late):
    # paramiko sets the event after the attempt deadline: neither SUCCESS nor NO_MATCH may be reported.
    def answer_too_late(t, event):
        isolated.now += 60
        late(t, event)

    findings, report, made = ssh_run(monkeypatch, sink, [dell(), ssh('admin', 'x')],
                                     lambda i: FakeTransport(on_auth=answer_too_late))
    svc = report.services[0]
    assert svc.outcomes['TIMEOUT'] == 1 and svc.details['TIMEOUT_AFTER_PASSWORD'] == 1
    assert svc.outcomes.get('SUCCESS', 0) == 0 and svc.outcomes.get('NO_MATCH', 0) == 0
    assert made[0].auth_calls == [('root', CANARY)]                  # the password was sent once, never again
    assert svc.skipped['TIMEOUT_STOP'] == 1
    assert sink.record.call_count == 0                               # nothing saved from a late answer


def test_expiry_before_password_wins_over_a_closed_transport(monkeypatch, sink, isolated):
    # The transport is already closed and no event ever fires, and the deadline passes first: a timeout, not an error.
    class ClosedWithoutAnswer(FakeTransport):
        def start_client(self, event=None):
            isolated.now += 60          # the attempt deadline passes while the wait is still running
            self.active = False         # the transport ended without SERVICE_ACCEPT

    findings, report, made = ssh_run(monkeypatch, sink, [dell(), ssh('admin', 'x')],
                                     lambda i: ClosedWithoutAnswer())
    svc = report.services[0]
    assert svc.outcomes['TIMEOUT'] == 1 and svc.details['TIMEOUT_BEFORE_PASSWORD'] == 1   # classified as expiry
    assert svc.outcomes.get('ERROR', 0) == 0 and svc.outcomes.get('NO_MATCH', 0) == 0
    assert all(t.auth_calls == [] for t in made)
    assert sink.record.call_count == 0


def test_wait_order_checks_the_deadline_before_a_closed_transport(isolated):
    # Direct check of the ordering: no event, closed transport, deadline already passed -> timeout.
    closed = SimpleNamespace(is_active=lambda: False)
    assert dc._ssh_wait(threading.Event(), closed, isolated.now) == 'timeout'
    # A closed transport before the deadline is still reported as closed.
    assert dc._ssh_wait(threading.Event(), closed, isolated.now + 100) == 'inactive'


def test_transport_closed_before_the_deadline_during_negotiation_is_an_error(monkeypatch, sink):
    class ClosedEarly(FakeTransport):
        def start_client(self, event=None):
            self.active = False         # ended at once, well before the deadline: a real closure, not an expiry

    findings, report, made = ssh_run(monkeypatch, sink, [dell(), ssh('admin', 'x')], lambda i: ClosedEarly())
    svc = report.services[0]
    assert svc.details['SSH_NEGOTIATION_FAILED'] == 1 and svc.outcomes['ERROR'] == 1
    assert svc.attempts == 1 and svc.skipped['STOPPED'] == 1         # an error stops the service, no retry
    assert all(t.auth_calls == [] for t in made)
    assert sink.record.call_count == 0


def test_expiry_after_password_wins_over_a_closed_transport(monkeypatch, sink, isolated):
    # The password was sent, the transport closes and no answer arrives before the deadline: timeout, never retried.
    def close_late(t, event):
        isolated.now += 60
        t.active = False            # no event is set

    findings, report, made = ssh_run(monkeypatch, sink, [dell(), ssh('admin', 'x')],
                                     lambda i: FakeTransport(on_auth=close_late))
    svc = report.services[0]
    assert svc.outcomes['TIMEOUT'] == 1 and svc.details['TIMEOUT_AFTER_PASSWORD'] == 1
    assert svc.outcomes.get('ERROR', 0) == 0 and svc.outcomes.get('NO_MATCH', 0) == 0
    assert made[0].auth_calls == [('root', CANARY)]                  # the password was sent once, never again
    assert svc.skipped['TIMEOUT_STOP'] == 1
    assert sink.record.call_count == 0


def test_refused_tcp_connection_is_inaccessible(monkeypatch, sink):
    def refused(target_ip, timeout):
        raise ConnectionRefusedError()

    monkeypatch.setattr(dc, '_open_ssh_transport', refused)
    report = dc.CheckReport()
    dc.check_default_creds(HOST, SESSION, candidates=[dell()], recorder=sink, report=report, services=('ssh',))
    assert report.services[0].outcomes['INACCESSIBLE'] == 1
    assert report.services[0].details['CONNECTION_FAILED'] == 1


def test_missing_paramiko_is_explicit_error(monkeypatch):
    monkeypatch.setitem(sys.modules, 'paramiko', None)
    result, learned = dc._try_ssh_login(HOST, 'root', CANARY)
    assert (result.status, result.detail, learned) == (dc.ERROR, 'SSH_DEPENDENCY_MISSING', False)


# --- Case: result identity is exact, budget identity is case-folded -------------------------------

def test_admin_and_admin_are_distinct_results_but_share_the_account_budget(monkeypatch, sink):
    upper, lower = ssh('Admin', 'p1'), ssh('admin', 'p2')
    assert upper.identity() != lower.identity()
    assert upper.budget_identity() == lower.budget_identity()
    findings, report, made = ssh_run(monkeypatch, sink, [upper, lower], lambda i: FakeTransport(on_auth=refuse))
    assert report.services[0].candidates_tested == 2                 # not de-duplicated
    findings, report, made = ssh_run(monkeypatch, sink, [upper, lower, ssh('ADMIN', 'p3')],
                                     lambda i: FakeTransport(on_auth=refuse))
    assert report.services[0].candidates_tested == 2
    assert report.services[0].skipped['BUDGET'] == 1                 # MAX_ACCOUNT=2 holds across casings


def test_success_for_one_casing_does_not_hide_the_other(monkeypatch, sink):
    upper, lower = ssh('Admin', 'p1'), ssh('admin', 'p2')
    findings, report, made = ssh_run(monkeypatch, sink, [upper, lower],
                                     lambda i: FakeTransport(on_auth=accept if i == 0 else refuse))
    assert report.services[0].candidates_tested == 2
    assert report.services[0].outcomes['SUCCESS'] == 1 and report.services[0].outcomes['NO_MATCH'] == 1


# --- Structure: no channel, no terminal, no command, no agent or key ------------------------

def test_no_channel_terminal_command_agent_or_key_in_ssh_path():
    source = inspect.getsource(dc._ssh_session) + inspect.getsource(dc._try_ssh_login) + inspect.getsource(dc._open_ssh_transport)
    for forbidden in ('open_session', 'open_channel', 'invoke_shell', 'exec_command', 'get_pty', 'SSHClient',
                      'AgentClient', 'allow_agent', 'look_for_keys', 'load_system_host_keys', 'auth_publickey',
                      'auth_none', 'auth_interactive', 'connect('):
        assert forbidden not in source, forbidden


def test_password_only_path_records_no_channel_access(monkeypatch, sink):
    findings, report, made = ssh_run(monkeypatch, sink, [dell(), ssh('a', 'b')], lambda i: FakeTransport(on_auth=accept))
    assert all(t.forbidden_access == [] for t in made)


# --- Secrets ---------------------------------------------------------------------------------------

def test_no_secret_in_report_findings_or_output(monkeypatch, sink, capsys):
    findings, report, made = ssh_run(monkeypatch, sink, [dell()], lambda i: FakeTransport(on_auth=accept))
    assert findings and CANARY not in json.dumps(findings[0].to_dict())
    assert CANARY not in repr(report) and CANARY not in str(report.services[0].details)
    captured = capsys.readouterr()
    assert CANARY not in captured.out + captured.err
    assert CANARY not in trust_file().read_text(encoding='utf-8')  # the trust file holds keys, never passwords


# --- FTP and SNMP unchanged; default services; catalogue ----------------------------------------

def test_ftp_and_snmp_never_call_the_ssh_probe(monkeypatch, sink):
    monkeypatch.setattr(dc, '_try_ssh_login', Mock(side_effect=AssertionError('SSH must not run')))
    monkeypatch.setattr(dc, '_try_ftp_login', Mock(return_value=dc.CredentialProbeResult('ftp', dc.NO_MATCH, 'AUTH_REJECTED')))
    monkeypatch.setattr(dc, '_try_snmp_community', Mock(return_value=dc.CredentialProbeResult('snmp', dc.NO_MATCH, 'X')))
    report = dc.CheckReport()
    dc.check_default_creds(HOST, SESSION, candidates=[Candidate('ftp', 'u', 'p'), Candidate('snmp', community='public')],
                           recorder=sink, report=report)
    assert [s.service for s in report.services] == ['ftp', 'snmp']


def test_default_services_stay_ftp_and_snmp():
    selected = prepare_candidates(None, (), None)[1]
    assert selected == ('ftp', 'snmp')


def test_ssh_without_candidates_is_an_explicit_error():
    with pytest.raises(DictionaryError, match='no compatible candidates'):
        prepare_candidates(None, ('ssh',), None)  # built-in legacy catalogue has no SSH candidate


def test_ssh_without_candidates_in_check_is_not_a_success(monkeypatch, sink):
    report = dc.CheckReport()
    findings = dc.check_default_creds(HOST, SESSION, candidates=[Candidate('ftp', 'u', 'p')],
                                      recorder=sink, report=report, services=('ssh',))
    assert findings == [] and report.services[0].reason == 'NO_COMPATIBLE_CANDIDATE'
    assert report.services[0].state == 'not_tested' and sink.record.call_count == 0


def test_telnet_remains_outside_v1_and_smb_needs_an_explicit_dictionary():
    with pytest.raises(ValueError, match='Unsupported service'):
        dc.check_default_creds(HOST, SESSION, candidates=[], recorder=Mock(ready=True), services=('telnet',))
    with pytest.raises(DictionaryError, match='no built-in candidates'):
        prepare_candidates(None, ('smb',), None)


def test_dictionary_accepts_ssh_rows_and_rejects_non_ascii(tmp_path):
    good = tmp_path / 'good.jsonl'
    good.write_text(json.dumps(dict(service='ssh', username='root', password='pw')) + '\n', encoding='utf-8')
    assert load_dictionary(good)[0].service == 'ssh'
    bad = tmp_path / 'bad.jsonl'
    bad.write_text(json.dumps(dict(service='ssh', username='rôot', password='pw')) + '\n', encoding='utf-8')
    with pytest.raises(DictionaryError):
        load_dictionary(bad)


def test_paramiko_api_used_exists():
    assert hasattr(paramiko.Transport, 'start_client')
    assert hasattr(paramiko.Transport, 'auth_password')
    assert hasattr(paramiko.Transport, 'get_remote_server_key')
    assert hasattr(paramiko.Transport, 'get_exception') and hasattr(paramiko.Transport, 'is_authenticated')
    assert issubclass(PartialAuthentication, paramiko.AuthenticationException)
    assert issubclass(BadAuthenticationType, paramiko.AuthenticationException)


# --- CLI contract -------------------------------------------------------------------------------

def test_cli_help_lists_ssh_and_smb_as_explicit_services_only():
    result = runner.invoke(cli.app, ['creds_check', '--help'])
    # Rich wraps the option help inside a box: drop the border characters before comparing words.
    text = ' '.join(re.sub(r'[│╭╮╰╯─]', ' ', result.output).split())
    assert result.exit_code == 0
    assert 'ftp, snmp, ssh (password only) or smb (--dict only' in text
    assert 'telnet' not in text.lower() and 'rdp' not in text.lower()


def test_cli_ssh_run_uses_explicit_profile_and_shows_tofu_notice(tmp_path, monkeypatch):
    from core.credential_vault import open_vault
    path = tmp_path / 'private' / 'vault.enc'
    monkeypatch.setattr(cli, '_open_credential_vault',
                        lambda writable=False: open_vault(path, 'Synthetic passphrase for SSH tests 1!', create=writable, writable=writable))
    monkeypatch.setattr(dc, '_open_ssh_transport', lambda ip, timeout: (FakeSock(), FakeTransport(on_auth=refuse)))
    result = runner.invoke(cli.app, ['creds_check', '-t', HOST, '--service', 'ssh', '--profile', 'dell-idrac-legacy-root'],
                           input='y\n')
    assert result.exit_code == 0, result.output
    text = ' '.join(result.output.split())
    assert 'ssh:' in text and 'NO_MATCH' in result.output
    assert 'password only' in text and "does not verify the server's identity" in text
    assert CANARY not in result.output


def test_cli_default_run_is_ftp_and_snmp_only(tmp_path, monkeypatch):
    from core.credential_vault import open_vault
    path = tmp_path / 'private' / 'vault.enc'
    monkeypatch.setattr(cli, '_open_credential_vault',
                        lambda writable=False: open_vault(path, 'Synthetic passphrase for SSH tests 2!', create=writable, writable=writable))
    dictionary = tmp_path / 'ftp-only.jsonl'
    dictionary.write_text(json.dumps(dict(service='ftp', username='u', password='p')) + '\n', encoding='utf-8')
    monkeypatch.setattr(dc, '_try_ftp_login', Mock(return_value=dc.CredentialProbeResult('ftp', dc.NO_MATCH, 'AUTH_REJECTED')))
    monkeypatch.setattr(dc, '_try_ssh_login', Mock(side_effect=AssertionError('SSH must not run by default')))
    result = runner.invoke(cli.app, ['creds_check', '-t', HOST, '--dict', str(dictionary)], input='y\n')
    assert result.exit_code == 0, result.output
    assert 'FTP and SNMP are checked' in ' '.join(result.output.split())
    assert 'ssh:' not in result.output


# --- R1: applicability limits travel with the SSH Finding only -----------------------------

def test_ssh_finding_carries_the_applicability_conditions_without_identifiers(monkeypatch, sink):
    findings, report, made = ssh_run(monkeypatch, sink, [dell()], lambda i: FakeTransport(on_auth=accept))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.HIGH and finding.confidence == Confidence.CONFIRMED   # unchanged
    assert finding.target_port == 22
    raw = finding.evidence.raw
    entry = json.loads(raw)['provenance'][0]
    assert entry['profile_id'] == 'Profil Dell iDRAC Legacy'          # title replaces the raw profile id
    assert entry['applicability'] == load_catalog('dell-idrac-legacy-root')[0].provenance.applicability
    assert 'Legacy' in entry['applicability'] and 'SSH' in entry['applicability']
    # no account name, catalogue password, raw profile id or test secret in the serialised evidence
    for forbidden in ('root', 'calvin', 'dell-idrac-legacy-root', CANARY):
        assert forbidden not in raw, forbidden
    assert '"username"' not in raw and '"password"' not in raw


def test_dell_descriptive_catalogue_texts_name_no_identifier():
    profile = json.load(open(CATALOG, encoding='utf-8'))['profiles']['dell-idrac-legacy-root']
    texts = [profile[k] for k in ('title', 'applicability', 'description', 'limits')] + [profile['source']['section']]
    for text in texts:
        assert 'root' not in text and 'calvin' not in text, text


def test_non_ssh_provenance_keeps_its_evidence_shape():
    assert set(load_catalog('cisco-wlc-7.4')[0].provenance.as_evidence()) == {'profile_id', 'catalog_version', 'documentation'}


# --- R4: concurrent trust-file updates (real processes, fork) -----------------------------

class Key:
    """A host key with a chosen value: two checks of one host can present different keys."""
    def __init__(self, b64):
        self.b64 = b64

    def get_name(self):
        return 'ssh-ed25519'

    def get_base64(self):
        return self.b64


NEEDS_FORK = pytest.mark.skipif(sys.platform == 'win32' or 'fork' not in multiprocessing.get_all_start_methods(),
                                reason='process test uses fork')


def _trust_lines(path):
    return [line.split() for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def _concurrent_checks(runs, paused):
    """runs: {role: (target_ip, key_b64)}; each role is a separate process running a real check_default_creds.
    The paused role stops just before it publishes the trust file, after its own read, until the other roles
    have finished or a grace period ends. Returns {role: (outcomes, details)}."""
    ctx = multiprocessing.get_context('fork')
    results, others_done = ctx.Queue(), ctx.Event()

    def child(role, target_ip, key_b64, is_paused):
        try:
            dc.time = SimpleNamespace(monotonic=lambda: 1000.0, sleep=lambda seconds: None)  # no deadline effects
            dc._SSH_POLL_SECONDS = 0
            dc._open_ssh_transport = lambda ip, timeout: (FakeSock(), FakeTransport(key=Key(key_b64), on_auth=refuse))
            if is_paused:
                real_replace = os.replace

                def delayed_publish(src, dst, *args, **kwargs):
                    if str(dst).endswith(dc.SSH_TRUST_FILE):
                        others_done.wait(timeout=1.0)
                    return real_replace(src, dst, *args, **kwargs)
                os.replace = delayed_publish
            report = dc.CheckReport()
            dc.check_default_creds(target_ip, SESSION, candidates=[ssh('admin', 'x')],
                                   recorder=Mock(ready=True, record=Mock(return_value=True)),
                                   report=report, services=('ssh',))
            svc = report.services[0]
            results.put((role, dict(svc.outcomes), dict(svc.details)))
        except BaseException as exc:  # reported to the parent, never silently dropped
            results.put((role, {'CHILD_ERROR': 1}, {type(exc).__name__: 1}))
        finally:
            if not is_paused:
                others_done.set()

    procs = [ctx.Process(target=child, args=(role, ip, key, role == paused)) for role, (ip, key) in runs.items()]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(30)
    assert not any(proc.is_alive() for proc in procs), 'a concurrent check did not finish'
    out = {}
    for _ in procs:
        role, outcomes, details = results.get(timeout=5)
        out[role] = (outcomes, details)
    return out


@NEEDS_FORK
def test_concurrent_first_contacts_for_distinct_hosts_keep_every_entry(isolated):
    out = _concurrent_checks({'A': ('192.0.2.10', 'AAAAKEY1'), 'B': ('192.0.2.11', 'AAAAKEY2')}, paused='A')
    assert out['A'][0] == {'NO_MATCH': 1} and out['B'][0] == {'NO_MATCH': 1}   # both learned, both authenticated
    assert {line[0] for line in _trust_lines(dc.ssh_trust_path())} == {'[192.0.2.10]:22', '[192.0.2.11]:22'}


@NEEDS_FORK
def test_concurrent_first_contacts_for_one_host_with_different_keys_never_both_learn(isolated):
    out = _concurrent_checks({'A': (HOST, 'AAAAKEY1'), 'B': (HOST, 'AAAAKEY2')}, paused='A')
    learned = [role for role, (outcomes, _) in out.items() if outcomes == {'NO_MATCH': 1}]
    blocked = [role for role, (outcomes, details) in out.items() if details == {'SSH_HOST_KEY_CHANGED': 1}]
    assert len(learned) == 1 and len(blocked) == 1 and learned[0] != blocked[0], out
    assert out[blocked[0]][0] == {'ERROR': 1}                 # blocked before any password
    lines = _trust_lines(dc.ssh_trust_path())
    assert len(lines) == 1 and lines[0][0] == f'[{HOST}]:22'  # one entry, never overwritten silently
    assert lines[0][2] == ('AAAAKEY1' if learned[0] == 'A' else 'AAAAKEY2')


def test_trust_lock_file_that_is_a_link_is_refused_without_password(monkeypatch, sink, personal):
    lock = dc.ssh_trust_path().parent / 'ssh_known_hosts.lock'
    lock.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.symlink(personal.path, lock)
    findings, report, made = ssh_run(monkeypatch, sink, [dell(), ssh('admin', 'x')], lambda i: FakeTransport(on_auth=accept))
    assert report.services[0].details == {'SSH_TRUST_FILE_UNSAFE': 1}
    assert all(t.auth_calls == [] for t in made)
    assert sink.record.call_count == 0
    assert_personal_untouched(personal)
