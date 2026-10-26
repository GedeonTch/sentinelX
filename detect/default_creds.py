"""Explicit bounded FTP/SNMP/SSH (password only) checks, with mandatory ready secret sink.

No session DB, scoring, transcripts or credentials in Findings. The public scan
still returns List[Finding]; the CLI supplies a vault and an assainised report.
"""
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
import errno
import ftplib
import ipaddress
import json
import os
from pathlib import Path
import socket
import stat
import threading
import time
from typing import Iterator, List, Optional, Protocol, Sequence

import typer
from core.finding import Category, Confidence, Evidence, Exposure, Finding, Severity
from core.credential_vault import VaultError, VaultWriteUncertain
from core.logger import display
from detect.credential_dictionary import Candidate, SUPPORTED, load_catalog
from detect.credential_snmp import build_get, classify_response, InvalidResponse, new_request_id

MODULE_NAME = 'default_creds'
RULE_ID = 'default_creds_found'
PROBE_TIMEOUT_SECONDS = 5
SUCCESS, NO_MATCH, TIMEOUT, INACCESSIBLE, ERROR = 'SUCCESS', 'NO_MATCH', 'TIMEOUT', 'INACCESSIBLE', 'ERROR'
INCONCLUSIVE, LOCKED, ANONYMOUS = 'INCONCLUSIVE', 'LOCKED', 'ANONYMOUS_ACCESS'
# SNMP agent answered (noSuchName) but read access was not demonstrated: distinct, never a success.
READ_UNPROVEN = 'READ_UNPROVEN'
MAX_SERVICE, MAX_ACCOUNT, MAX_TOTAL = 3, 2, 10
ATTEMPT_SECONDS, SERVICE_SECONDS, INTERVAL_SECONDS = 10, 35, 2
# Network attempts for one control (one candidate on one service of one device), first included.
MAX_CONTROL_TRIES = 3
# Only these timeouts are repeated: FTP before any password was sent, SNMP with no answer at all.
# Any other TIMEOUT (e.g. FTP after PASS) is never repeated and stops the service on this device.
TIMEOUT_BEFORE_PASSWORD, TIMEOUT_AFTER_PASSWORD, SNMP_NO_RESPONSE = 'TIMEOUT_BEFORE_PASSWORD', 'TIMEOUT_AFTER_PASSWORD', 'NO_RESPONSE'
RETRIABLE_TIMEOUTS = frozenset({TIMEOUT_BEFORE_PASSWORD, SNMP_NO_RESPONSE})
SERVICE_PORTS = {'ftp': 21, 'snmp': 161, 'ssh': 22}
SERVICE_CONTEXT = {'ftp': 'ftp-password', 'snmp': 'snmpv1-sysDescr', 'ssh': 'ssh-password'}
# SSH host keys: a SentinelX-owned file, never ~/.ssh/known_hosts (which is not modified).
SSH_TRUST_FILE = 'ssh_known_hosts'
SSH_HOST_KEY_LEARNED, SSH_HOST_KEY_CHANGED = 'SSH_HOST_KEY_LEARNED', 'SSH_HOST_KEY_CHANGED'
# Poll step while waiting on paramiko events. Tests set it to 0 and drive a fake clock.
_SSH_POLL_SECONDS = 0.1


class Recorder(Protocol):
    ready: bool

    def record(self, *, service: str, endpoint: str, context: str, username: str,
               domain: str, secret: str, kind: str, proof: str) -> bool: ...


@dataclass(frozen=True)
class CredentialProbeResult:
    protocol: str
    status: str
    detail: str = ''  # controlled codes only, never backend exception text


@dataclass
class ServiceReport:
    service: str
    candidates: int
    state: str = 'not_tested'
    reason: str = ''
    attempts: int = 0
    outcomes: Counter = field(default_factory=Counter)
    details: Counter = field(default_factory=Counter)
    created: int = 0
    updated: int = 0
    save_failures: int = 0
    save_uncertain: int = 0
    skipped: Counter = field(default_factory=Counter)
    # Candidates that started a control (one per candidate, however many network attempts it used).
    candidates_tested: int = 0
    # Repetitions cut short by a budget or deadline (never counted as observed timeouts).
    retry_stopped: Counter = field(default_factory=Counter)
    # SSH only: host keys accepted on first contact and saved (trust on first use, not identity proof).
    host_keys_learned: int = 0


@dataclass
class CheckReport:
    services: list[ServiceReport] = field(default_factory=list)
    interrupted: bool = False


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise socket.timeout()
    return min(PROBE_TIMEOUT_SECONDS, remaining)


class _BoundedFTP(ftplib.FTP):
    """Enforce a wall-clock deadline even for trickling/multiline replies."""
    def __init__(self, deadline: float) -> None:
        super().__init__()
        self.deadline = deadline

    def getline(self) -> str:
        data = bytearray()
        while len(data) <= self.maxline:
            self.sock.settimeout(_remaining(self.deadline))
            byte = self.sock.recv(1)
            if not byte:
                raise EOFError
            data.extend(byte)
            if byte == b'\n':
                return bytes(data).decode('ascii', errors='strict').rstrip('\r\n')
        raise ftplib.Error('FTP response exceeds line limit')

    def getmultiline(self) -> str:
        line = self.getline()
        lines = [line]
        if line[3:4] == '-':
            code = line[:3]
            for _ in range(15):
                following = self.getline()
                lines.append(following)
                if sum(len(item) for item in lines) > 16384:
                    raise ftplib.Error('FTP response exceeds total limit')
                if following[:3] == code and following[3:4] != '-':
                    break
            else:
                raise ftplib.Error('FTP response exceeds multiline limit')
        return '\n'.join(lines)


def _ftp_reply_code(response: str) -> str:
    last = response.split('\n')[-1]
    if len(last) >= 3 and last[:3].isdigit() and (len(last) == 3 or last[3] == ' '):
        return last[:3]
    return ''


def _ftp_anonymous_reply(response: str) -> bool:
    """Positive server labels only; their absence is NOT proof of password use."""
    import re
    return re.search(r'\b(?:guest|anonymous)\b', response, re.IGNORECASE) is not None


def _try_ftp_login(target_ip: str, username: str, password: str) -> CredentialProbeResult:
    """Bound each control operation; no automatic login retry or ACCT fallback."""
    ftp = None
    phase = 'connect'
    deadline = time.monotonic() + ATTEMPT_SECONDS
    try:
        ftp = _BoundedFTP(deadline)
        ftp.connect(target_ip, 21, timeout=_remaining(deadline))
        phase = 'user'
        ftp.sock.settimeout(_remaining(deadline))
        response = ftp.sendcmd('USER ' + username)
        if _ftp_reply_code(response) == '230':
            # No password was checked. A server label identifies access, not a pair.
            status = ANONYMOUS if _ftp_anonymous_reply(response) else INCONCLUSIVE
            return CredentialProbeResult('ftp', status, 'PASSWORD_NOT_CHECKED')
        if _ftp_reply_code(response) != '331':
            return CredentialProbeResult('ftp', INCONCLUSIVE, 'UNEXPECTED_USER_REPLY')
        user_reply = response
        ftp.sock.settimeout(_remaining(deadline))
        # Set just before PASS is sent: a timeout while still preparing the send is 'before password'.
        phase = 'password'
        response = ftp.sendcmd('PASS ' + password)
        if _ftp_reply_code(response) == '230':
            if _ftp_anonymous_reply(user_reply) or _ftp_anonymous_reply(response):
                return CredentialProbeResult('ftp', ANONYMOUS, 'SERVER_REPORTED_ANONYMOUS_ACCESS')
            # ftp is a documented anonymous alias (e.g. IIS). Even a 331/230
            # exchange does not prove this password was checked. Preserve the
            # historical probe, but never save/qualify its ambiguous success.
            if username.strip().casefold() in ('ftp', 'anonymous', 'guest', 'ftp-anonymous'):
                return CredentialProbeResult('ftp', INCONCLUSIVE, 'ANONYMOUS_ALIAS_PASSWORD_UNPROVEN')
            return CredentialProbeResult('ftp', SUCCESS, 'AUTHENTICATED')
        return CredentialProbeResult('ftp', INCONCLUSIVE, 'ADDITIONAL_AUTH_REQUIRED')
    except ftplib.error_perm as exc:
        # Inspect only in memory. Never copy server text to any result/log.
        code = str(exc)[:3]
        if any(word in str(exc).lower() for word in ('locked', 'lockout', 'too many')):
            return CredentialProbeResult('ftp', LOCKED, 'ACCOUNT_RESTRICTION')
        if phase in ('user', 'password') and code == '530':
            return CredentialProbeResult('ftp', NO_MATCH, 'AUTH_REJECTED')
        return CredentialProbeResult('ftp', INACCESSIBLE if phase == 'connect' else ERROR, 'PERMANENT_PROTOCOL_ERROR')
    except ftplib.error_temp as exc:
        restricted = any(word in str(exc).lower() for word in ('locked', 'lockout', 'too many'))
        return CredentialProbeResult('ftp', LOCKED if restricted else ERROR, 'TEMPORARY_RESTRICTION')
    except socket.timeout:
        # The phase decides retry safety. 'password' is set before PASS is sent, so a timeout
        # there may already have reached the server: it is treated as possibly submitted.
        detail = TIMEOUT_AFTER_PASSWORD if phase == 'password' else TIMEOUT_BEFORE_PASSWORD
        return CredentialProbeResult('ftp', TIMEOUT, detail)
    except (ConnectionRefusedError, ConnectionResetError):
        return CredentialProbeResult('ftp', INACCESSIBLE, 'CONNECTION_FAILED')
    except (OSError, EOFError, UnicodeError, ftplib.Error):
        return CredentialProbeResult('ftp', ERROR, 'PROTOCOL_ERROR')
    finally:
        if ftp is not None:
            # close(), not QUIT: no extra operation outside the deadline.
            try:
                ftp.close()
            except Exception:
                pass


def ssh_trust_path() -> Path:
    """SentinelX-owned trust file (Path.home() / '.netlab'); ~/.ssh/known_hosts is never read or written."""
    return Path.home() / '.netlab' / SSH_TRUST_FILE


class TrustFileUnsafe(OSError):
    """The trust directory or file is a link or not a plain object, or someone else can change it."""


def _ssh_owner_mode_ok(st: os.stat_result, what: str) -> None:
    """POSIX: owned by the current user and not writable by group or others. Never repaired automatically."""
    if not hasattr(os, 'getuid'):
        return  # Windows has no POSIX owner/mode bits; the link checks still apply
    if st.st_uid != os.getuid():
        raise TrustFileUnsafe(f'SSH trust {what} is not owned by the current user')
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise TrustFileUnsafe(f'SSH trust {what} is writable by group or others')


def _ssh_check_directory(st: os.stat_result) -> None:
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise TrustFileUnsafe('SSH trust directory is a link or not a directory')
    _ssh_owner_mode_ok(st, 'directory')


def _ssh_check_file(st: os.stat_result) -> None:
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise TrustFileUnsafe('SSH trust file is a link or not a regular file')
    _ssh_owner_mode_ok(st, 'file')


def _ssh_read_trust(path: Path) -> Optional[bytes]:
    """Raw content, or None when the directory or the file is absent. Never follows a link."""
    try:
        directory = os.lstat(path.parent)
    except FileNotFoundError:
        return None
    _ssh_check_directory(directory)
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        return None
    _ssh_check_file(before)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:  # O_NOFOLLOW refused a link swapped in after the lstat above
            raise TrustFileUnsafe('SSH trust file is a symbolic link') from None
        raise
    with os.fdopen(descriptor, 'rb') as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise TrustFileUnsafe('SSH trust file changed while being checked')
        _ssh_check_file(opened)
        return handle.read()


def _ssh_load_trust(path: Path, host_id: str, name: str, key_b64: str) -> str:
    """Return 'unknown', 'known' or 'changed'. Read or parse problems raise, which blocks the check."""
    raw = _ssh_read_trust(path)
    if raw is None:
        return 'unknown'
    stored = []
    for line in raw.decode('utf-8').splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        fields = line.split()
        if len(fields) != 3:
            raise ValueError('Malformed trust file line')
        if fields[0] == host_id:
            stored.append((fields[1], fields[2]))
    if not stored:
        return 'unknown'
    return 'known' if (name, key_b64) in stored else 'changed'


def _ssh_store_trust(path: Path, host_id: str, name: str, key_b64: str) -> None:
    """Append one entry: temp file 0600, fsync, atomic replace, then read back. Any failure raises."""
    try:
        os.lstat(path.parent)
    except FileNotFoundError:
        path.parent.mkdir(mode=0o700, parents=True)  # created by us: 0700; an existing directory keeps its mode
    existing = _ssh_read_trust(path) or b''          # refuses unsafe directory or file before any write
    if existing and not existing.endswith(b'\n'):
        existing += b'\n'
    content = existing + f'{host_id} {name} {key_b64}\n'.encode('ascii')
    temp = path.with_name(f'.{path.name}.{os.getpid()}.tmp')
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)  # replaces a name, never writes through one
    except BaseException:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise
    if _ssh_load_trust(path, host_id, name, key_b64) != 'known':
        raise OSError('Trust file read-back failed')


@contextmanager
def _ssh_trust_lock(path: Path) -> Iterator[None]:
    """Exclusive blocking lock on '<trust file>.lock', held only for local file work (no network inside).
    The lock file is never unlinked, never followed, and gets the same link/owner/mode checks as the trust file."""
    import portalocker
    lock = path.with_name(path.name + '.lock')
    try:
        os.lstat(path.parent)
    except FileNotFoundError:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)  # created by us: 0700
    _ssh_check_directory(os.lstat(path.parent))
    try:
        before = os.lstat(lock)
    except FileNotFoundError:
        before = None
    if before is not None:
        _ssh_check_file(before)
    try:
        descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    except OSError as exc:
        if exc.errno == errno.ELOOP:  # O_NOFOLLOW refused a link swapped in after the lstat above
            raise TrustFileUnsafe('SSH trust lock is a symbolic link') from None
        raise
    with os.fdopen(descriptor, 'r+b') as handle:
        opened = os.fstat(handle.fileno())
        if before is not None and (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise TrustFileUnsafe('SSH trust lock changed while being checked')
        _ssh_check_file(opened)
        portalocker.lock(handle, portalocker.LOCK_EX)
        try:
            yield
        finally:
            portalocker.unlock(handle)


def _ssh_trust_decision(path: Path, host_id: str, name: str, key_b64: str) -> str:
    """Return 'known', 'learned' or 'changed'. Under the lock: re-read, decide, store only if unknown, read back.
    A changed key is never stored over the existing entry."""
    with _ssh_trust_lock(path):
        trust = _ssh_load_trust(path, host_id, name, key_b64)
        if trust == 'unknown':
            _ssh_store_trust(path, host_id, name, key_b64)
            return 'learned'
        return trust


def _open_ssh_transport(target_ip: str, timeout: float):
    import paramiko
    sock = socket.create_connection((target_ip, SERVICE_PORTS['ssh']), timeout=timeout)
    try:
        return sock, paramiko.Transport(sock)
    except BaseException:
        sock.close()
        raise


def _ssh_left(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise socket.timeout()
    return left


def _ssh_wait(event, transport, deadline: float) -> str:
    """'set' when the event fires before the deadline, 'inactive' if the transport ended before the deadline,
    'timeout' once the deadline has passed.

    The deadline is checked before the transport state, so an expiry is never reported as a closed connection.
    An event observed after the deadline is a timeout: it may be a late answer, so it is never accepted as a result.
    """
    while True:
        if event.wait(_SSH_POLL_SECONDS) or event.is_set():
            return 'set' if time.monotonic() < deadline else 'timeout'
        if time.monotonic() >= deadline:
            return 'timeout'
        if not transport.is_active():
            return 'inactive'


def _ssh_session(paramiko, target_ip: str, username: str, password: str, deadline: float,
                 state: dict) -> CredentialProbeResult:
    """Password-only exchange. state['phase'] is 'password' from the auth_password call onward:
    paramiko sends the password only after SERVICE_ACCEPT, so any later timeout counts as possibly submitted."""
    # PartialAuthentication is not exported at paramiko's top level; import it from its module explicitly.
    from paramiko.ssh_exception import BadAuthenticationType, PartialAuthentication
    sock, transport = _open_ssh_transport(target_ip, _ssh_left(deadline))
    state['sock'], state['transport'] = sock, transport
    negotiated = threading.Event()
    transport.start_client(event=negotiated)
    waited = _ssh_wait(negotiated, transport, deadline)
    if waited == 'timeout':
        return CredentialProbeResult('ssh', TIMEOUT, TIMEOUT_BEFORE_PASSWORD)
    if waited != 'set' or not transport.is_active():
        return CredentialProbeResult('ssh', ERROR, 'SSH_NEGOTIATION_FAILED')
    try:
        host_key = transport.get_remote_server_key()
        name, key_b64 = host_key.get_name(), host_key.get_base64()
    except paramiko.SSHException:
        return CredentialProbeResult('ssh', ERROR, 'SSH_HOST_KEY_UNAVAILABLE')
    # Trust decision BEFORE any password is sent. Unknown key: accept and save (TOFU). Changed key: block.
    host_id, path = f'[{target_ip}]:{SERVICE_PORTS["ssh"]}', ssh_trust_path()
    try:
        trust = _ssh_trust_decision(path, host_id, name, key_b64)
        if trust == 'changed':
            return CredentialProbeResult('ssh', ERROR, SSH_HOST_KEY_CHANGED)
        if trust == 'learned':
            state['learned'] = True
    except TrustFileUnsafe:
        return CredentialProbeResult('ssh', ERROR, 'SSH_TRUST_FILE_UNSAFE')
    except (OSError, ValueError, RuntimeError):
        return CredentialProbeResult('ssh', ERROR, 'SSH_TRUST_STORE_UNAVAILABLE')
    if deadline - time.monotonic() <= 0:
        return CredentialProbeResult('ssh', TIMEOUT, TIMEOUT_BEFORE_PASSWORD)
    authenticated = threading.Event()
    state['phase'] = 'password'
    transport.auth_password(username, password, event=authenticated)
    waited = _ssh_wait(authenticated, transport, deadline)
    if waited == 'timeout':
        return CredentialProbeResult('ssh', TIMEOUT, TIMEOUT_AFTER_PASSWORD)
    if waited != 'set':
        return CredentialProbeResult('ssh', ERROR, 'CONNECTION_CLOSED_DURING_AUTH')
    if transport.is_authenticated():
        # Authenticated only: no channel, no command, no further action.
        return CredentialProbeResult('ssh', SUCCESS, 'AUTHENTICATED')
    exc = transport.get_exception()
    if isinstance(exc, PartialAuthentication):
        return CredentialProbeResult('ssh', INCONCLUSIVE, 'ADDITIONAL_AUTH_REQUIRED')
    if isinstance(exc, BadAuthenticationType):
        return CredentialProbeResult('ssh', INCONCLUSIVE, 'PASSWORD_METHOD_UNAVAILABLE')
    if exc is None:
        # paramiko reports an explicit password refusal through the event alone, with the transport still up.
        if transport.is_active():
            return CredentialProbeResult('ssh', NO_MATCH, 'AUTH_REJECTED')
        return CredentialProbeResult('ssh', ERROR, 'CONNECTION_CLOSED_DURING_AUTH')
    # Inspect only in memory. Never copy server text to any result, log or exception.
    if any(word in str(exc).lower() for word in ('locked', 'lockout', 'too many')):
        return CredentialProbeResult('ssh', LOCKED, 'ACCOUNT_RESTRICTION')
    return CredentialProbeResult('ssh', ERROR, 'PROTOCOL_ERROR')


def _try_ssh_login(target_ip: str, username: str, password: str) -> tuple[CredentialProbeResult, bool]:
    """Returns (result, host_key_learned). Never opens a channel, agent, key, command or terminal."""
    try:
        import paramiko
    except ImportError:
        return CredentialProbeResult('ssh', ERROR, 'SSH_DEPENDENCY_MISSING'), False
    deadline = time.monotonic() + ATTEMPT_SECONDS
    state = {'phase': 'connect', 'learned': False}
    try:
        return _ssh_session(paramiko, target_ip, username, password, deadline, state), state['learned']
    except socket.timeout:
        detail = TIMEOUT_AFTER_PASSWORD if state['phase'] == 'password' else TIMEOUT_BEFORE_PASSWORD
        return CredentialProbeResult('ssh', TIMEOUT, detail), state['learned']
    except (ConnectionRefusedError, ConnectionResetError):
        return CredentialProbeResult('ssh', INACCESSIBLE, 'CONNECTION_FAILED'), state['learned']
    except (OSError, EOFError, paramiko.SSHException):
        return CredentialProbeResult('ssh', ERROR, 'PROTOCOL_ERROR'), state['learned']
    finally:
        # close() only: no QUIT, no channel, nothing sent after the decision.
        for key in ('transport', 'sock'):
            handle = state.get(key)
            if handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass


def _probe(target_ip: str, candidate: Candidate) -> tuple[CredentialProbeResult, bool]:
    if candidate.service == 'ftp':
        return _try_ftp_login(target_ip, candidate.username, candidate.password), False
    if candidate.service == 'snmp':
        return _try_snmp_community(target_ip, candidate.community), False
    return _try_ssh_login(target_ip, candidate.username, candidate.password)


def _build_snmp_v1_get(community: str, request_id: int = 1) -> bytes:
    return build_get(community, request_id)


def _try_snmp_community(target_ip: str, community: str) -> CredentialProbeResult:
    request_id = new_request_id()
    packet = build_get(community, request_id)
    deadline = time.monotonic() + PROBE_TIMEOUT_SECONDS
    received = False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(_remaining(deadline))
            sock.sendto(packet, (target_ip, 161))
            for _ in range(16):
                sock.settimeout(_remaining(deadline))
                data, source = sock.recvfrom(4097)
                received = True
                if source != (target_ip, 161):
                    continue
                try:
                    outcome = classify_response(data, community, request_id)
                except InvalidResponse:
                    continue
                if outcome == 'READ_OK':
                    return CredentialProbeResult('snmp', SUCCESS, outcome)
                if outcome == 'OID_UNAVAILABLE':
                    # Agent answered, but the requested read was not demonstrated.
                    return CredentialProbeResult('snmp', READ_UNPROVEN, outcome)
                return CredentialProbeResult('snmp', INCONCLUSIVE, 'STRUCTURED_SNMP_ERROR')
        return CredentialProbeResult('snmp', INCONCLUSIVE, 'PACKET_LIMIT')
    except socket.timeout:
        return CredentialProbeResult('snmp', INCONCLUSIVE if received else TIMEOUT,
                                     'NO_CORRELATED_RESPONSE' if received else SNMP_NO_RESPONSE)
    except (ConnectionRefusedError, ConnectionResetError):
        return CredentialProbeResult('snmp', INACCESSIBLE, 'CONNECTION_FAILED')
    except OSError:
        return CredentialProbeResult('snmp', ERROR, 'TRANSPORT_ERROR')


def _make_finding(session_id: str, target_ip: str, service: str, count: int, proofs: Counter, provenance: list[dict]) -> Finding:
    return Finding(session_id=session_id, module=MODULE_NAME, target_ip=target_ip,
        target_port=SERVICE_PORTS[service], target_service=RULE_ID,
        category=Category.CREDENTIAL, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
        exposure=Exposure.INTERNAL,
        evidence=Evidence(raw=json.dumps({'service': service, 'authentication': 'confirmed',
            'qualified_success_count': count, 'qualified_proofs': dict(proofs), 'provenance': provenance, 'proof_scope': 'protocol_observation_not_cryptographic_attestation'}),
            command=f'{service.upper()} credential check; authentication material omitted'),
        explanation=None, risk_score=None)


def check_default_creds(target_ip: str, session_id: str, *,
                        candidates: Optional[Sequence[Candidate]] = None,
                        services: Sequence[str] = ('ftp', 'snmp'),
                        recorder: Optional[Recorder] = None,
                        report: Optional[CheckReport] = None) -> List[Finding]:
    """One prompt per service, one Finding per qualified service; no secret output."""
    # IPv4 only in this first lot: no DNS or endpoint expansion from candidate data.
    try:
        target_ip = str(ipaddress.IPv4Address(target_ip))
    except ValueError:
        raise ValueError('A single IPv4 target is required') from None
    if recorder is None or not recorder.ready:
        raise VaultError('A write-verified vault is required before testing')
    if any(s not in SUPPORTED for s in services):
        raise ValueError('Unsupported service')
    items = tuple(dict.fromkeys(candidates if candidates is not None else load_catalog()))
    report = report if report is not None else CheckReport()
    selected = tuple(dict.fromkeys(services))
    report.services.extend(ServiceReport(s, sum(c.service == s for c in items)) for s in selected)
    findings = []
    account_attempts = Counter()
    total, last_attempt = 0, None
    stop_all = False
    try:
        for result in report.services:
            pool = [c for c in items if c.service == result.service]
            if not pool:
                result.reason = 'NO_COMPATIBLE_CANDIDATE'
                continue
            if stop_all:
                result.reason = 'GLOBAL_STOP'
                result.skipped['GLOBAL_STOP'] += len(pool)
                continue
            if not typer.confirm(f'[default_creds] Test {result.service.upper()} on {target_ip} '
                                 f'({len(pool)} candidates; maximum 3 attempts; lockout risk)?'):
                result.state, result.reason = 'cancelled', 'USER_REFUSED'
                result.skipped['USER_REFUSED'] += len(pool)
                continue
            result.state = 'tested'
            deadline = time.monotonic() + SERVICE_SECONDS
            authenticated = set()
            qualified = 0
            qualified_proofs = Counter()
            qualified_provenance = {}
            stop_service = False
            stop_timeout = False
            for candidate in pool:
                # Result identity (exact for SSH) versus budget key (case-folded): see Candidate.
                identity = candidate.identity()
                account = (target_ip, *candidate.budget_identity())
                reason = None
                if stop_all:
                    reason = 'STOPPED'
                elif stop_service:
                    reason = 'TIMEOUT_STOP' if stop_timeout else 'STOPPED'
                elif identity in authenticated:
                    reason = 'IDENTITY_ALREADY_AUTHENTICATED'
                elif result.attempts >= MAX_SERVICE or total >= MAX_TOTAL or account_attempts[account] >= (1 if candidate.service == 'snmp' else MAX_ACCOUNT):
                    reason = 'BUDGET'
                elif deadline - time.monotonic() < ATTEMPT_SECONDS:
                    reason = 'SERVICE_DEADLINE'
                if reason:
                    result.skipped[reason] += 1
                    continue
                if last_attempt is not None:
                    delay = max(0, INTERVAL_SECONDS - (time.monotonic() - last_attempt))
                    if deadline - time.monotonic() < delay + ATTEMPT_SECONDS:
                        result.skipped['SERVICE_DEADLINE'] += 1
                        continue
                    time.sleep(delay)
                # One control per candidate: its repetitions are network attempts, not new candidates.
                result.candidates_tested += 1
                account_attempts[account] += 1
                tries = 0
                while True:
                    tries += 1
                    result.attempts += 1
                    total += 1
                    last_attempt = time.monotonic()
                    learned = False
                    try:
                        outcome, learned = _probe(target_ip, candidate)
                    except (KeyboardInterrupt, typer.Abort):
                        result.outcomes['CANCELLED'] += 1
                        raise
                    except Exception:
                        # Do not expose arbitrary backend exceptions with credentials.
                        outcome = CredentialProbeResult(candidate.service, ERROR, 'UNEXPECTED_BACKEND_ERROR')
                    result.host_keys_learned += int(learned)
                    result.outcomes[outcome.status] += 1
                    result.details[outcome.detail] += 1
                    if outcome.status != TIMEOUT or outcome.detail not in RETRIABLE_TIMEOUTS or tries >= MAX_CONTROL_TRIES:
                        break
                    # Repeat the same candidate; every network attempt passes the same budget and deadline gates.
                    if result.attempts >= MAX_SERVICE or total >= MAX_TOTAL:
                        result.retry_stopped['BUDGET'] += 1
                        break
                    delay = max(0, INTERVAL_SECONDS - (time.monotonic() - last_attempt))
                    if deadline - time.monotonic() < delay + ATTEMPT_SECONDS:
                        result.retry_stopped['SERVICE_DEADLINE'] += 1
                        break
                    time.sleep(delay)
                if outcome.status == TIMEOUT and outcome.detail in RETRIABLE_TIMEOUTS:
                    # No password was submitted and no SNMP answer came back: not counted against MAX_ACCOUNT.
                    account_attempts[account] -= 1
                if outcome.status == SUCCESS:
                    authenticated.add(identity)
                    if candidate.qualified and candidate.provenance is not None:
                        qualified += 1
                        qualified_proofs[outcome.detail] += 1
                        evidence = candidate.provenance.as_evidence()
                        if candidate.service == 'ssh':
                            # SSH only: the catalogue's applicability text travels with the Finding.
                            evidence.update(candidate.provenance.applicability_evidence())
                        qualified_provenance[candidate.provenance] = evidence
                    try:
                        created = recorder.record(service=candidate.service,
                            endpoint=f'{target_ip}:{SERVICE_PORTS[candidate.service]}',
                            context=SERVICE_CONTEXT[candidate.service],
                            username=candidate.username, domain=candidate.domain,
                            secret=candidate.secret(), kind='community' if candidate.service == 'snmp' else 'password',
                            proof=outcome.detail)
                        result.created += int(created)
                        result.updated += int(not created)
                    except VaultWriteUncertain as exc:
                        result.save_uncertain += 1
                        stop_all = True
                        if exc.interrupted:
                            raise KeyboardInterrupt from None
                    except VaultError:
                        # The vault positively reports a pre-replacement failure.
                        result.save_failures += 1
                        stop_all = True
                    except Exception:
                        # An arbitrary sink exception does not prove absence on disk.
                        result.save_uncertain += 1
                        stop_all = True
                elif outcome.status == LOCKED:
                    stop_all = True  # server restriction scope is not reliably known
                elif outcome.status in (ERROR, INACCESSIBLE):
                    stop_service = True
                elif outcome.status == TIMEOUT and (outcome.detail not in RETRIABLE_TIMEOUTS or tries >= MAX_CONTROL_TRIES):
                    # Third timeout on a repeatable control, or a timeout after PASS: stop this service on this device only.
                    stop_service = stop_timeout = True
                    if not result.reason:
                        result.reason = 'TIMEOUT_STOP'
            if qualified:
                findings.append(_make_finding(session_id, target_ip, result.service, qualified, qualified_proofs, list(qualified_provenance.values())))
    except (KeyboardInterrupt, typer.Abort):
        report.interrupted = True
        raise
    finally:
        for result in report.services:
            # Candidates, not network attempts: a repeated candidate must not be counted twice.
            missing = result.candidates - result.candidates_tested - sum(result.skipped.values())
            if missing > 0:
                result.skipped['INTERRUPTED' if report.interrupted else 'NOT_TESTED'] += missing
            if result.state == 'tested' and (result.save_failures or result.save_uncertain or
                    any(v for k, v in result.skipped.items() if k != 'IDENTITY_ALREADY_AUTHENTICATED') or
                    any(v for k, v in result.outcomes.items() if k not in (SUCCESS, NO_MATCH))):
                result.state = 'partial'
            if report.interrupted and result.state == 'not_tested' and not result.reason:
                result.reason = 'INTERRUPTED'
    return findings
