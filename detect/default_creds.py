"""Explicit bounded FTP/SNMP checks, with mandatory ready secret sink.

No session DB, scoring, transcripts or credentials in Findings. The public scan
still returns List[Finding]; the CLI supplies a vault and an assainised report.
"""
from collections import Counter
from dataclasses import dataclass, field
import ftplib
import ipaddress
import json
import socket
import time
from typing import List, Optional, Protocol, Sequence

import typer
from core.finding import Category, Confidence, Evidence, Exposure, Finding, Severity
from core.credential_vault import VaultError, VaultWriteUncertain
from core.logger import display
from detect.credential_dictionary import Candidate, load_catalog
from detect.credential_snmp import build_get, classify_response, InvalidResponse, new_request_id

MODULE_NAME = 'default_creds'
RULE_ID = 'default_creds_found'
PROBE_TIMEOUT_SECONDS = 5
SUCCESS, NO_MATCH, TIMEOUT, INACCESSIBLE, ERROR = 'SUCCESS', 'NO_MATCH', 'TIMEOUT', 'INACCESSIBLE', 'ERROR'
INCONCLUSIVE, LOCKED, ANONYMOUS = 'INCONCLUSIVE', 'LOCKED', 'ANONYMOUS_ACCESS'
MAX_SERVICE, MAX_ACCOUNT, MAX_TOTAL = 3, 2, 10
ATTEMPT_SECONDS, SERVICE_SECONDS, INTERVAL_SECONDS = 10, 30, 2


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
        phase = 'password'
        ftp.sock.settimeout(_remaining(deadline))
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
        return CredentialProbeResult('ftp', TIMEOUT, 'DEADLINE')
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
                if outcome in ('READ_OK', 'OID_UNAVAILABLE'):
                    return CredentialProbeResult('snmp', SUCCESS, outcome)
                return CredentialProbeResult('snmp', INCONCLUSIVE, 'STRUCTURED_SNMP_ERROR')
        return CredentialProbeResult('snmp', INCONCLUSIVE, 'PACKET_LIMIT')
    except socket.timeout:
        return CredentialProbeResult('snmp', INCONCLUSIVE if received else TIMEOUT,
                                     'NO_CORRELATED_RESPONSE' if received else 'NO_RESPONSE')
    except (ConnectionRefusedError, ConnectionResetError):
        return CredentialProbeResult('snmp', INACCESSIBLE, 'CONNECTION_FAILED')
    except OSError:
        return CredentialProbeResult('snmp', ERROR, 'TRANSPORT_ERROR')


def _make_finding(session_id: str, target_ip: str, service: str, count: int, proofs: Counter, provenance: list[dict]) -> Finding:
    return Finding(session_id=session_id, module=MODULE_NAME, target_ip=target_ip,
        target_port=21 if service == 'ftp' else 161, target_service=RULE_ID,
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
    if any(s not in ('ftp', 'snmp') for s in services):
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
            for candidate in pool:
                identity = candidate.identity()
                account = (target_ip, *identity)
                reason = None
                if stop_all or stop_service:
                    reason = 'STOPPED'
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
                result.attempts += 1
                total += 1
                account_attempts[account] += 1
                last_attempt = time.monotonic()
                try:
                    outcome = (_try_ftp_login(target_ip, candidate.username, candidate.password)
                               if candidate.service == 'ftp' else _try_snmp_community(target_ip, candidate.community))
                except (KeyboardInterrupt, typer.Abort):
                    result.outcomes['CANCELLED'] += 1
                    raise
                except Exception:
                    # Do not expose arbitrary backend exceptions with credentials.
                    outcome = CredentialProbeResult(candidate.service, ERROR, 'UNEXPECTED_BACKEND_ERROR')
                result.outcomes[outcome.status] += 1
                result.details[outcome.detail] += 1
                if outcome.status == SUCCESS:
                    authenticated.add(identity)
                    if candidate.qualified and candidate.provenance is not None:
                        qualified += 1
                        qualified_proofs[outcome.detail] += 1
                        qualified_provenance[candidate.provenance] = candidate.provenance.as_evidence()
                    try:
                        created = recorder.record(service=candidate.service,
                            endpoint=f'{target_ip}:{21 if candidate.service == "ftp" else 161}',
                            context='ftp-password' if candidate.service == 'ftp' else 'snmpv1-sysDescr',
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
            if qualified:
                findings.append(_make_finding(session_id, target_ip, result.service, qualified, qualified_proofs, list(qualified_provenance.values())))
    except (KeyboardInterrupt, typer.Abort):
        report.interrupted = True
        raise
    finally:
        for result in report.services:
            missing = result.candidates - result.attempts - sum(result.skipped.values())
            if missing:
                result.skipped['INTERRUPTED' if report.interrupted else 'NOT_TESTED'] += missing
            if result.state == 'tested' and (result.save_failures or result.save_uncertain or
                    any(v for k, v in result.skipped.items() if k != 'IDENTITY_ALREADY_AUTHENTICATED') or
                    any(v for k, v in result.outcomes.items() if k not in (SUCCESS, NO_MATCH))):
                result.state = 'partial'
            if report.interrupted and result.state == 'not_tested' and not result.reason:
                result.reason = 'INTERRUPTED'
    return findings
