"""T22 SMB (session authentication only): deterministic tests. No network, no real host.

smbprotocol is replaced by scripted stand-ins that follow the behaviour measured on loopback:
closing the transport unblocks a pending wait with an exception. The test-only ATTEMPT_SECONDS
override is short; the production budgets are not changed.
"""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import inspect
import logging
import socket
import sys
import threading
import time

import pytest
from typer.testing import CliRunner

import cli
import detect.default_creds as dc
from detect.credential_dictionary import Candidate, DictionaryError, KNOWN, SUPPORTED, load_catalog, load_dictionary, prepare_candidates
from smbprotocol.exceptions import SMBAuthenticationError, SMBConnectionClosed, SMBException, SMBResponseException
from smbprotocol.header import SMB2HeaderResponse

HOST, SESSION = '192.0.2.20', 'test-smb'
CANARY = 'SYNTHETIC_SMB_SECRET_41'
runner = CliRunner()

# Per-test script for the stand-ins below.
SCRIPT = {}
CREATED = {'connections': [], 'sessions': [], 'connect_timeouts': []}


class FakeSocket:
    """Stands in for the socket behind Tcp._sock: shutdown() releases whoever waits on the transport."""

    def __init__(self, transport):
        self._transport = transport
        self.shutdown_calls = 0

    def shutdown(self, how):
        self.shutdown_calls += 1
        self._transport.closed.set()


class FakeTransport:
    """As in smbprotocol: a blocking write holds _sock_lock, and close() waits for that lock."""

    def __init__(self):
        self.closed = threading.Event()
        self.close_calls = 0
        self._sock = FakeSocket(self)
        self._sock_lock = threading.Lock()

    def close(self):
        with self._sock_lock:
            self.close_calls += 1
            self.closed.set()


def _block_until_closed(transport, safety=5.0):
    """Like the library's wait: returns only when the transport is closed (or after a safety limit)."""
    if transport.closed.wait(safety):
        raise SMBConnectionClosed('SMB socket was closed, cannot send or receive any more data')
    raise socket.timeout('safety limit: the test would otherwise hang')


class FakeConnection:
    def __init__(self, guid, server_name, port):
        self.server_name, self.port = server_name, port
        self.transport = None
        self.disconnect_calls = 0
        self.disconnect_close_flags = []
        self.disconnect_timeouts = []
        self.session_table = {}
        self.logoff_sent = 0
        CREATED['connections'].append(self)

    def connect(self, dialect=None, timeout=60, **kwargs):
        CREATED['connect_timeouts'].append(timeout)
        self.transport = FakeTransport()
        mode = SCRIPT.get('connect', 'ok')
        if mode == 'refused':
            raise ConnectionRefusedError()
        if mode == 'not_smb':
            raise SMBException('negotiation rejected')
        if mode == 'hang':
            _block_until_closed(self.transport)
        if mode == 'slow_then_ok':
            time.sleep(SCRIPT['connect_sleep'])
        self.dialect = 0x0202

    def disconnect(self, close=True, timeout=None):
        self.disconnect_calls += 1
        self.disconnect_close_flags.append(close)
        self.disconnect_timeouts.append(timeout)
        if close and self.session_table:
            self._logoff(timeout)
        if self.transport is not None:
            self.transport.close()

    def _logoff(self, timeout):
        """LOGOFF behaviour from SCRIPT['logoff']: 'ok' (replies), 'silent', 'blocked' or 'error'."""
        self.logoff_sent += 1
        mode = SCRIPT.get('logoff', 'ok')
        if mode == 'silent':
            # As in the library: no reply ends the wait with an exception at the timeout.
            if self.transport.closed.wait(timeout):
                raise SMBConnectionClosed('closed during LOGOFF')
            raise SMBException('Connection timeout while waiting for a LOGOFF response')
        if mode == 'blocked':
            # The write holds the transport lock, like Tcp.send(): only shutdown() releases it.
            with self.transport._sock_lock:
                _block_until_closed(self.transport, safety=5.0)
        if mode == 'error':
            raise smb_status(0xC000006D)


class FakeSession:
    def __init__(self, connection, username=None, password=None, require_encryption=True,
                 hostname_override=None, auth_protocol='negotiate'):
        self.connection = connection
        self.username, self.password = username, password
        self.require_encryption, self.auth_protocol = require_encryption, auth_protocol
        self.session_key = None
        CREATED['sessions'].append(self)

    def connect(self):
        mode = SCRIPT.get('session', 'ok')
        if mode == 'ok':
            time.sleep(SCRIPT.get('session_sleep', 0))
            self.session_key = b'k' * 16
            self.connection.session_table[1] = self  # registered before the library's own checks
        elif mode == 'guest':
            self.session_key = None  # smbprotocol clears the key for guest and null sessions
            self.connection.session_table[1] = self
        elif mode == 'raise':
            raise SCRIPT['session_exc']
        elif mode == 'stall':
            _block_until_closed(self.connection.transport)
        elif mode == 'registered_stall':
            # Session registered and keyed before the deadline, then the library's own checks stall.
            self.session_key = b'k' * 16
            self.connection.session_table[1] = self
            _block_until_closed(self.connection.transport)
        elif mode == 'late_ok':
            time.sleep(SCRIPT['late_delay'])
            self.session_key = b'k' * 16  # answer observed after the deadline: never a result
            self.connection.session_table[1] = self


def smb_status(code):
    header = SMB2HeaderResponse()
    header['status'] = code
    return SMBResponseException(header)


@pytest.fixture
def smb(monkeypatch):
    """Scripted library, short test-only attempt window, no sleep between attempts."""
    import smbprotocol.connection
    import smbprotocol.session
    SCRIPT.clear()
    for key in CREATED:
        CREATED[key].clear()
    monkeypatch.setattr(smbprotocol.connection, 'Connection', FakeConnection)
    monkeypatch.setattr(smbprotocol.session, 'Session', FakeSession)
    monkeypatch.setattr(dc, 'ATTEMPT_SECONDS', 0.3)
    monkeypatch.setattr(dc, 'INTERVAL_SECONDS', 0)
    monkeypatch.setattr(dc.typer, 'confirm', lambda *a, **k: True)
    return SCRIPT


def _probe(username='bob', password='p', domain=''):
    return dc._try_smb_login(HOST, username, password, domain)


# --- contract -----------------------------------------------------------------------------------

def test_smb_is_a_supported_service_on_port_445_with_its_own_context():
    assert 'smb' in SUPPORTED and 'smb' in KNOWN
    assert dc.SERVICE_PORTS['smb'] == 445
    assert dc.SERVICE_CONTEXT['smb'] == 'smb-password'


def test_default_services_stay_ftp_and_snmp():
    assert inspect.signature(dc.check_default_creds).parameters['services'].default == ('ftp', 'snmp')
    _, selected = prepare_candidates(None, (), None)
    assert selected == ('ftp', 'snmp')


def test_smb_without_a_dictionary_is_an_explicit_refusal_and_the_catalogue_has_no_smb_candidate():
    assert not any(c.service == 'smb' for c in load_catalog())
    with pytest.raises(DictionaryError, match='no built-in candidates'):
        prepare_candidates(None, ('smb',), None)


def test_smb_dictionary_rows_accept_an_optional_domain_and_reject_backslashes(tmp_path):
    good = tmp_path / 'good.jsonl'
    good.write_text('\n'.join([
        '{"service": "smb", "username": "bob", "password": "p"}',
        '{"service": "smb", "username": "bob", "password": "p", "domain": "CORP"}',
    ]) + '\n', encoding='utf-8')
    rows = load_dictionary(good)
    assert [(c.domain, c.username) for c in rows] == [('', 'bob'), ('CORP', 'bob')]
    for bad_row in ('{"service": "smb", "username": "CORP\\\\bob", "password": "p"}',
                    '{"service": "smb", "username": "bob", "password": "p", "domain": "CORP\\\\"}',
                    '{"service": "smb", "community": "public"}'):
        bad = tmp_path / 'bad.jsonl'
        bad.write_text(bad_row + '\n', encoding='utf-8')
        with pytest.raises(DictionaryError):
            load_dictionary(bad)


def test_budget_identity_includes_the_domain_and_stays_case_folded_on_each_part():
    assert Candidate('smb', 'Admin', 'p', domain='CORP').budget_identity() == ('account', 'corp', 'admin')
    assert Candidate('smb', 'admin', 'p', domain='corp').budget_identity() == Candidate('smb', 'ADMIN', 'p', domain='CORP').budget_identity()
    assert Candidate('smb', 'bob', 'p', domain='CORP').budget_identity() != Candidate('smb', 'bob', 'p').budget_identity()


def test_domain_is_sent_as_domain_backslash_user_and_empty_domain_sends_the_plain_user(smb):
    smb['session'] = 'ok'
    _probe(domain='CORP')
    _probe(domain='')
    assert [s.username for s in CREATED['sessions']] == ['CORP\\bob', 'bob']
    assert all(s.auth_protocol == 'ntlm' and s.require_encryption is False for s in CREATED['sessions'])


def test_one_isolated_connection_per_attempt_with_the_attempt_limit_as_timeout(smb):
    smb['session'] = 'ok'
    _probe()
    _probe()
    assert len(CREATED['connections']) == 2
    assert CREATED['connect_timeouts'] == [dc.ATTEMPT_SECONDS, dc.ATTEMPT_SECONDS]
    # Each successful attempt: one LOGOFF, then the closing call; the socket is always closed last.
    assert all(c.logoff_sent == 1 and c.disconnect_close_flags == [True, False] for c in CREATED['connections'])


def test_library_loggers_do_not_propagate_protocol_debug(smb):
    smb['session'] = 'ok'
    _probe()
    for name in ('smbprotocol', 'spnego'):
        logger = logging.getLogger(name)
        assert logger.propagate is False and logger.handlers


def test_missing_dependency_is_an_explicit_error_not_a_refusal(monkeypatch):
    monkeypatch.setitem(sys.modules, 'smbprotocol.connection', None)
    result = _probe()
    assert (result.status, result.detail) == ('ERROR', 'SMB_DEPENDENCY_MISSING')


# --- result classification ----------------------------------------------------------------------

def test_accepted_session_is_success_and_is_closed(smb):
    smb['session'] = 'ok'
    result = _probe()
    assert (result.status, result.detail) == ('SUCCESS', 'AUTHENTICATED')
    assert CREATED['connections'][0].transport.close_calls >= 1


def test_guest_or_null_session_is_inconclusive_never_a_success_nor_a_refusal(smb):
    smb['session'] = 'guest'
    result = _probe()
    assert (result.status, result.detail) == ('INCONCLUSIVE', 'GUEST_OR_NULL_SESSION')


@pytest.mark.parametrize('code', [0xC000006D, 0xC000006A, 0xC0000064])
def test_refused_pair_is_no_match(smb, code):
    smb['session'], smb['session_exc'] = 'raise', smb_status(code)
    result = _probe()
    assert (result.status, result.detail) == ('NO_MATCH', 'AUTH_REJECTED')


def test_locked_account_is_locked_and_stops_the_run_later(smb):
    smb['session'], smb['session_exc'] = 'raise', smb_status(0xC0000234)
    assert (_probe().status, _probe().detail) == ('LOCKED', 'ACCOUNT_RESTRICTION')


def test_expired_or_disabled_account_is_inconclusive_not_a_refusal(smb):
    smb['session'], smb['session_exc'] = 'raise', smb_status(0xC0000071)
    result = _probe()
    assert (result.status, result.detail) == ('INCONCLUSIVE', 'ACCOUNT_STATE')


def test_unknown_status_is_an_error(smb):
    smb['session'], smb['session_exc'] = 'raise', smb_status(0xC0000001)
    assert _probe().status == 'ERROR'


def test_failed_ntlm_exchange_is_an_error_not_a_refusal(smb):
    smb['session'], smb['session_exc'] = 'raise', SMBAuthenticationError('Failed to authenticate with server')
    result = _probe()
    assert (result.status, result.detail) == ('ERROR', 'SMB_AUTH_NEGOTIATION_FAILED')


def test_negotiation_failure_is_an_error_not_a_refusal(smb):
    smb['connect'] = 'not_smb'
    result = _probe()
    assert (result.status, result.detail) == ('ERROR', 'SMB_NEGOTIATION_FAILED')
    assert CREATED['sessions'] == []


def test_refused_socket_is_inaccessible(smb):
    smb['connect'] = 'refused'
    result = _probe()
    assert (result.status, result.detail) == ('INACCESSIBLE', 'CONNECTION_FAILED')


def test_negotiation_hang_is_bounded_before_any_password(smb):
    smb['connect'] = 'hang'
    started = time.monotonic()
    result = _probe()
    elapsed = time.monotonic() - started
    assert (result.status, result.detail) == ('TIMEOUT', 'TIMEOUT_BEFORE_PASSWORD')
    assert elapsed < dc.ATTEMPT_SECONDS + 1.5
    assert CREATED['sessions'] == [] and CREATED['connections'][0].transport.close_calls >= 1


def test_authentication_stall_is_bounded_and_after_password_with_no_retry_inside(smb):
    smb['session'] = 'stall'
    started = time.monotonic()
    result = _probe()
    elapsed = time.monotonic() - started
    assert (result.status, result.detail) == ('TIMEOUT', 'TIMEOUT_AFTER_PASSWORD')
    assert elapsed < dc.ATTEMPT_SECONDS + 1.5
    assert len(CREATED['sessions']) == 1  # one session.connect() call only
    assert CREATED['connections'][0].transport.close_calls >= 1


def test_answer_observed_after_the_deadline_is_never_a_success_or_refusal(smb):
    smb['session'], smb['late_delay'] = 'late_ok', dc.ATTEMPT_SECONDS + 0.4
    result = _probe()
    assert (result.status, result.detail) == ('TIMEOUT', 'TIMEOUT_AFTER_PASSWORD')


def test_connection_established_after_the_deadline_never_starts_a_session(smb):
    smb['connect'], smb['connect_sleep'] = 'slow_then_ok', dc.ATTEMPT_SECONDS + 0.4
    result = _probe()
    assert (result.status, result.detail) == ('TIMEOUT', 'TIMEOUT_BEFORE_PASSWORD')
    assert CREATED['sessions'] == []


def test_error_text_containing_the_secret_never_reaches_the_result(smb):
    smb['session'], smb['session_exc'] = 'raise', SMBException(f'server said {CANARY}')
    result = _probe(password=CANARY)
    assert CANARY not in repr(result) and CANARY not in result.detail
    assert (result.status, result.detail) == ('ERROR', 'PROTOCOL_ERROR')


# --- orchestration through check_default_creds --------------------------------------------------

def _run(candidates, recorder=None, report=None):
    recorder = recorder if recorder is not None else Mock(ready=True, record=Mock(return_value=True))
    report = report if report is not None else dc.CheckReport()
    findings = dc.check_default_creds(HOST, SESSION, candidates=candidates, services=('smb',),
                                      recorder=recorder, report=report)
    return findings, report, recorder


def test_success_is_recorded_in_the_vault_only_and_produces_no_finding(smb):
    smb['session'] = 'ok'
    findings, report, recorder = _run([Candidate('smb', 'bob', 'p', domain='CORP')])
    assert findings == []
    kwargs = recorder.record.call_args.kwargs
    assert (kwargs['service'], kwargs['kind'], kwargs['context'], kwargs['proof']) == \
        ('smb', 'password', 'smb-password', 'AUTHENTICATED')
    assert kwargs['endpoint'] == f'{HOST}:445' and kwargs['domain'] == 'CORP'


def test_timeout_before_password_is_repeated_up_to_three_network_attempts_then_stops(smb):
    smb['connect'] = 'hang'
    findings, report, _ = _run([Candidate('smb', 'bob', 'p1'), Candidate('smb', 'bob', 'p2')])
    service = report.services[0]
    assert findings == []
    assert service.attempts == dc.MAX_CONTROL_TRIES == 3
    assert service.candidates_tested == 1 and service.outcomes['TIMEOUT'] == 3
    assert service.reason == 'TIMEOUT_STOP'


def test_timeout_after_password_is_never_repeated(smb):
    smb['session'] = 'stall'
    _, report, _ = _run([Candidate('smb', 'bob', 'p1'), Candidate('smb', 'carol', 'p2')])
    service = report.services[0]
    assert service.attempts == 1 and service.outcomes['TIMEOUT'] == 1
    assert service.reason == 'TIMEOUT_STOP'


def test_account_budget_is_two_attempts_per_account_and_domain_is_part_of_the_account(smb):
    smb['session'], smb['session_exc'] = 'raise', smb_status(0xC000006D)
    candidates = [Candidate('smb', 'bob', 'p1', domain='CORP'), Candidate('smb', 'bob', 'p2', domain='CORP'),
                  Candidate('smb', 'bob', 'p3', domain='CORP'), Candidate('smb', 'bob', 'p4')]
    _, report, _ = _run(candidates)
    service = report.services[0]
    assert service.attempts == 3  # CORP\bob twice, then the empty-domain bob is a separate account
    assert service.skipped['BUDGET'] == 1
    assert service.outcomes['NO_MATCH'] == 3


def test_locked_account_stops_the_remaining_smb_candidates(smb):
    smb['session'], smb['session_exc'] = 'raise', smb_status(0xC0000234)
    _, report, _ = _run([Candidate('smb', 'bob', 'p1'), Candidate('smb', 'carol', 'p2')])
    assert report.services[0].attempts == 1
    assert report.services[0].skipped['STOPPED'] == 1


def test_cli_smb_without_dictionary_refuses_before_the_vault_is_opened(monkeypatch):
    opened = Mock(side_effect=AssertionError('vault must not be opened'))
    monkeypatch.setattr(cli, '_open_credential_vault', opened)
    result = runner.invoke(cli.app, ['creds_check', '--target', HOST, '--service', 'smb'])
    assert result.exit_code != 0
    assert 'SMB has no built-in candidates' in result.output
    assert opened.call_count == 0


# --- deadline mechanism -----------------------------------------------------------------------------

def _writer(tcp, outcome):
    """Writes more than the socket buffers hold: with no reader on the peer, the write blocks."""
    try:
        tcp.send(b'x' * tcp.MAX_SIZE)
        outcome['result'] = 'returned'
    except OSError as exc:
        outcome['result'] = type(exc).__name__


def test_blocked_socket_write_is_released_at_the_deadline_with_the_real_transport():
    """Real smbprotocol Tcp class over a local socket pair (no network). The peer never reads."""
    from smbprotocol.transport import Tcp
    tcp = Tcp(HOST, 445, 1)
    local, peer = socket.socketpair()
    tcp._sock, tcp.connected = local, True
    deadline = dc._SmbDeadline(0.3, SimpleNamespace(transport=tcp))
    outcome = {}
    deadline.start()
    started = time.monotonic()
    writer = threading.Thread(target=_writer, args=(tcp, outcome), daemon=True)
    writer.start()
    try:
        time.sleep(0.1)
        assert writer.is_alive(), 'the write must be blocked before the deadline for this test to mean anything'
        writer.join(3)
        assert not writer.is_alive(), 'the blocked write was not released'
        assert time.monotonic() - started < 0.3 + 1.0
        assert outcome['result'] in ('BrokenPipeError', 'ConnectionResetError', 'OSError')
        assert deadline.expired and deadline.finish() is False
    finally:
        deadline.finish()
        peer.close()
        local.close()


def test_socket_created_after_the_limit_is_still_released_by_the_next_poll():
    """The TCP connect can outlast the limit: the socket appears later and must not escape the deadline."""
    from smbprotocol.transport import Tcp
    tcp = Tcp(HOST, 445, 1)
    deadline = dc._SmbDeadline(0.2, SimpleNamespace(transport=tcp))
    deadline.start()
    time.sleep(0.3)
    local, peer = socket.socketpair()
    tcp._sock, tcp.connected = local, True
    outcome = {}
    writer = threading.Thread(target=_writer, args=(tcp, outcome), daemon=True)
    writer.start()
    try:
        writer.join(2)
        assert not writer.is_alive(), 'a socket created after the limit was not released'
    finally:
        deadline.finish()
        peer.close()
        local.close()


def test_the_deadline_thread_is_stopped_after_every_outcome(smb):
    scenarios = [('ok', {}), ('guest', {}), ('stall', {}), ('late_ok', {'late_delay': dc.ATTEMPT_SECONDS + 0.4})]
    for session_mode, extra in scenarios:
        SCRIPT.clear()
        SCRIPT.update({'session': session_mode, **extra})
        _probe()
        assert not any(t.name == 'smb-attempt-deadline' for t in threading.enumerate()), session_mode
    SCRIPT.clear()
    SCRIPT['connect'] = 'hang'
    _probe()
    assert not any(t.name == 'smb-attempt-deadline' for t in threading.enumerate())


def test_no_logoff_is_written_after_a_timeout_and_a_logoff_follows_a_decided_result(smb):
    smb['session'] = 'stall'
    _probe()
    assert CREATED['connections'][0].disconnect_close_flags == [False]
    SCRIPT.clear()
    SCRIPT['session'] = 'ok'
    _probe()
    # LOGOFF (close=True) then the socket close and receiver join (close=False)
    assert CREATED['connections'][1].disconnect_close_flags == [True, False]


def test_smbprotocol_contract_the_deadline_relies_on():
    """Pins the internals used by _SmbDeadline and the absence of a deadline in Session.connect (smbprotocol 1.17)."""
    import inspect
    from smbprotocol.connection import Connection
    from smbprotocol.session import Session
    from smbprotocol.transport import Tcp
    assert 'timeout' in inspect.signature(Connection.connect).parameters
    assert set(inspect.signature(Session.connect).parameters) == {'self'}
    tcp = Tcp(HOST, 445, 1)
    assert hasattr(tcp, '_sock') and hasattr(tcp, '_sock_lock') and callable(tcp.close) and callable(tcp.send)


def test_guest_outcome_is_rendered_as_inconclusive_in_the_run_summary(smb, capsys):
    smb['session'] = 'guest'
    _, report, recorder = _run([Candidate('smb', 'bob', 'p')])
    assert recorder.record.call_count == 0
    cli._render_credential_summary(report)
    out = capsys.readouterr().out
    assert 'INCONCLUSIVE' in out and 'GUEST_OR_NULL_SESSION' in out
    assert 'NO_MATCH' not in out and 'confirmed=0' in out


# --- cleanup after a decided result (LOGOFF) ----------------------------------------------------

REQUIREMENTS = Path(__file__).resolve().parent.parent / 'requirements.txt'


def _attempt_threads():
    return [t.name for t in threading.enumerate() if t.name == 'smb-attempt-deadline']


def test_requirements_pin_smbprotocol_1_17_0_and_the_installed_version_matches():
    from importlib.metadata import version
    lines = [line.strip() for line in REQUIREMENTS.read_text(encoding='utf-8').splitlines()]
    assert 'smbprotocol==1.17.0' in lines
    assert version('smbprotocol') == '1.17.0'


def test_successful_session_logoff_without_reply_is_bounded_and_keeps_the_success(smb, monkeypatch):
    monkeypatch.setattr(dc, 'SMB_LOGOFF_SECONDS', 0.1)
    smb['session'], smb['logoff'] = 'ok', 'silent'
    started = time.monotonic()
    result = _probe()
    elapsed = time.monotonic() - started
    connection = CREATED['connections'][0]
    assert (result.status, result.detail) == ('SUCCESS', 'AUTHENTICATED')
    assert connection.logoff_sent == 1
    assert connection.disconnect_timeouts[0] == pytest.approx(0.1)
    assert 0.09 <= elapsed < 0.6, elapsed  # measured return: the LOGOFF budget, nothing more
    assert _attempt_threads() == []


def test_guest_session_logoff_without_reply_keeps_the_inconclusive_result(smb, monkeypatch):
    monkeypatch.setattr(dc, 'SMB_LOGOFF_SECONDS', 0.1)
    smb['session'], smb['logoff'] = 'guest', 'silent'
    result = _probe()
    assert (result.status, result.detail) == ('INCONCLUSIVE', 'GUEST_OR_NULL_SESSION')
    assert CREATED['connections'][0].logoff_sent == 1
    assert _attempt_threads() == []


def test_blocked_logoff_write_is_released_by_the_guard_within_its_budget(smb, monkeypatch):
    monkeypatch.setattr(dc, 'SMB_LOGOFF_SECONDS', 0.1)
    smb['session'], smb['logoff'] = 'ok', 'blocked'
    started = time.monotonic()
    result = _probe()
    elapsed = time.monotonic() - started
    connection = CREATED['connections'][0]
    assert (result.status, result.detail) == ('SUCCESS', 'AUTHENTICATED')
    assert connection.transport._sock.shutdown_calls >= 1  # released by shutdown, never by a lock wait
    assert elapsed < 1.0, elapsed  # the safety limit of the fake is 5 s: the guard acted first
    assert _attempt_threads() == []


def test_logoff_error_reply_never_changes_a_decided_result(smb):
    smb['session'], smb['logoff'] = 'ok', 'error'
    result = _probe()
    assert (result.status, result.detail) == ('SUCCESS', 'AUTHENTICATED')


def test_logoff_budget_never_exceeds_what_the_attempt_has_left(smb):
    # The session takes 0.25 of the 0.3 s attempt: about 0.05 s is left for the LOGOFF.
    smb['session'], smb['session_sleep'], smb['logoff'] = 'ok', dc.ATTEMPT_SECONDS - 0.05, 'silent'
    started = time.monotonic()
    result = _probe()
    elapsed = time.monotonic() - started
    timeouts = CREATED['connections'][0].disconnect_timeouts
    assert (result.status, result.detail) == ('SUCCESS', 'AUTHENTICATED')
    assert timeouts[0] <= 0.07, timeouts  # SMB_LOGOFF_SECONDS (2 s) is capped by the ~0.05 s left
    assert elapsed < dc.ATTEMPT_SECONDS + 0.1, elapsed


def test_no_logoff_after_an_authentication_timeout_even_when_the_session_was_registered(smb, monkeypatch):
    # The session is in the table before the deadline. Cleanup is spied on: the flag must be False, whatever
    # time is left (the budget cap alone would also stop it, so the flag itself is what this test pins).
    smb['session'] = 'registered_stall'
    flags = []
    original = dc._smb_cleanup

    def spy(connection, logoff, budget):
        flags.append(logoff)
        return original(connection, logoff=logoff, budget=budget)

    monkeypatch.setattr(dc, '_smb_cleanup', spy)
    result = _probe()
    connection = CREATED['connections'][0]
    assert (result.status, result.detail) == ('TIMEOUT', 'TIMEOUT_AFTER_PASSWORD')
    assert connection.session_table and connection.logoff_sent == 0
    assert flags == [False]
    assert connection.disconnect_close_flags == [False]


def test_no_session_means_no_logoff(smb):
    smb['session'], smb['session_exc'] = 'raise', smb_status(0xC000006D)
    result = _probe()
    assert (result.status, result.detail) == ('NO_MATCH', 'AUTH_REJECTED')
    assert CREATED['connections'][0].logoff_sent == 0


def test_no_attempt_thread_remains_after_any_logoff_outcome(smb, monkeypatch):
    monkeypatch.setattr(dc, 'SMB_LOGOFF_SECONDS', 0.1)
    for logoff in ('ok', 'silent', 'blocked', 'error'):
        SCRIPT.clear()
        SCRIPT.update({'session': 'ok', 'logoff': logoff})
        _probe()
        assert _attempt_threads() == [], logoff
