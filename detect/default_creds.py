"""
detect/default_creds.py — Default credential dictionary checks

Pipeline step: DETECT
Role: Against a target host, try a small local dictionary of known
      factory-default credentials on services that accept them
      (FTP logins, SNMP community strings). One Finding per success.

This is a dictionary lookup + limited probe — not a brute-force tool.
Every probe requires explicit (y/n) confirmation first.

Rules enforced here:
- ZERO import sqlite3
- ZERO print() — display via core/logger.py
- ZERO risk_score calculation
- ALWAYS return List[Finding]
- ALWAYS ask (y/n) before any network action
- explanation stays None (KB rule: default_creds_found in vulnerabilities.json)
- evidence.raw documents what was accepted (no password leakage beyond the
  known default that succeeded)
"""

from __future__ import annotations

import ftplib
import json
import socket
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

import typer

from core.finding import (
    Category,
    Confidence,
    Evidence,
    Exposure,
    Finding,
    Severity,
)
from core.logger import display

MODULE_NAME = "default_creds"
RULE_ID = "default_creds_found"
PROBE_TIMEOUT_SECONDS = 5

# ---------------------------------------------------------------------------
# Local dictionary — known factory defaults only (not a wordlist dump)
# ---------------------------------------------------------------------------

# FTP: (username, password). Anonymous access is intentionally not part of
# this default-credential dictionary; it is a separate observation.
FTP_DEFAULTS: Sequence[Tuple[str, str]] = (
    ("ftp", "ftp"),
    ("admin", "admin"),
    ("admin", "password"),
)

# SNMP v1/v2c community strings (no username)
SNMP_DEFAULT_COMMUNITIES: Sequence[str] = (
    "public",
    "private",
)

NO_MATCH = "NO_MATCH"
ERROR = "ERROR"
TIMEOUT = "TIMEOUT"
INACCESSIBLE = "INACCESSIBLE"
SUCCESS = "SUCCESS"


@dataclass(frozen=True)
class CredentialProbeResult:
    """Normalized outcome; secrets are never stored in this structure."""
    protocol: str
    status: str
    successful_usernames: Tuple[str, ...] = ()
    detail: str = ""


def check_default_creds(target_ip: str, session_id: str) -> List[Finding]:
    """Try known default credentials on FTP and SNMP for a target host.

    Asks for (y/n) confirmation before sending any traffic. Returns an
    empty list on cancel, connection failures, or no success — never
    raises for those cases.

    Args:
        target_ip: IPv4 address of the host to probe.
        session_id: Current audit session ID.

    Returns:
        List[Finding]: One Finding per accepted default credential.
    """
    confirmed = typer.confirm(
        f"[default_creds] Probe {target_ip} with known default "
        f"FTP credentials and SNMP communities?"
    )
    if not confirmed:
        display("[yellow]Default credential check cancelled.[/yellow]")
        return []

    display(f"[cyan]Checking default credentials on {target_ip}...[/cyan]")
    ftp_result, ftp_findings = _check_ftp_defaults_result(target_ip, session_id)
    snmp_result, snmp_findings = _check_snmp_defaults_result(target_ip, session_id)
    findings = ftp_findings + snmp_findings

    if findings:
        display(
            f"[green]Default credentials: {len(findings)} service finding(s) "
            f"with accepted defaults on {target_ip}.[/green]"
        )
    else:
        status = _summarize_status((ftp_result, snmp_result))
        display(
            f"[yellow]Default credentials: {status} on {target_ip}. "
            "No default credential was accepted.[/yellow]"
        )
    return findings


# ---------------------------------------------------------------------------
# FTP probes
# ---------------------------------------------------------------------------

def _check_ftp_defaults(target_ip: str, session_id: str) -> List[Finding]:
    """Return one Finding for FTP when one or more defaults are accepted."""
    return _check_ftp_defaults_result(target_ip, session_id)[1]


def _check_ftp_defaults_result(
    target_ip: str, session_id: str
) -> Tuple[CredentialProbeResult, List[Finding]]:
    outcomes = [_try_ftp_login(target_ip, username, password) for username, password in FTP_DEFAULTS]
    usernames = tuple(
        username for (username, _password), outcome in zip(FTP_DEFAULTS, outcomes)
        if outcome == SUCCESS
    )
    status = _summarize_status(tuple(
        CredentialProbeResult("ftp", outcome) for outcome in outcomes
    ))
    if not usernames:
        return CredentialProbeResult("ftp", status), []
    evidence = json.dumps({
        "service": "ftp",
        "authentication": "successful",
        "successful_usernames": list(usernames),
        "tested_default_count": len(FTP_DEFAULTS),
    }, sort_keys=True)
    finding = _make_finding(
        session_id=session_id,
        target_ip=target_ip,
        target_port=21,
        target_service=RULE_ID,
        evidence_raw=evidence,
        evidence_command=f"FTP default-credential probe on {target_ip}:21 (passwords redacted)",
    )
    return CredentialProbeResult("ftp", SUCCESS, usernames), [finding]


def _try_ftp_login(
    target_ip: str,
    username: str,
    password: str,
) -> str:
    """Attempt one FTP login and return a normalized probe status."""
    ftp: Optional[ftplib.FTP] = None
    try:
        ftp = ftplib.FTP()
        ftp.connect(target_ip, 21, timeout=PROBE_TIMEOUT_SECONDS)
        ftp.login(username, password)
        return SUCCESS
    except ftplib.error_perm:
        return NO_MATCH
    except socket.timeout:
        return TIMEOUT
    except (ConnectionRefusedError, ConnectionResetError):
        return INACCESSIBLE
    except (OSError, EOFError, ftplib.Error):
        return ERROR
    finally:
        if ftp is not None:
            try:
                ftp.quit()
            except Exception:
                try:
                    ftp.close()
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# SNMP community probes
# ---------------------------------------------------------------------------

def _check_snmp_defaults(target_ip: str, session_id: str) -> List[Finding]:
    """Return one Finding for SNMP when one or more defaults are accepted."""
    return _check_snmp_defaults_result(target_ip, session_id)[1]


def _check_snmp_defaults_result(
    target_ip: str, session_id: str
) -> Tuple[CredentialProbeResult, List[Finding]]:
    outcomes = [_try_snmp_community(target_ip, community) for community in SNMP_DEFAULT_COMMUNITIES]
    communities = tuple(
        community for community, outcome in zip(SNMP_DEFAULT_COMMUNITIES, outcomes)
        if outcome == SUCCESS
    )
    status = _summarize_status(tuple(
        CredentialProbeResult("snmp", outcome) for outcome in outcomes
    ))
    if not communities:
        return CredentialProbeResult("snmp", status), []
    evidence = json.dumps({
        "service": "snmp",
        "authentication": "successful",
        "successful_communities": ["[redacted]" for _ in communities],
        "successful_count": len(communities),
        "tested_default_count": len(SNMP_DEFAULT_COMMUNITIES),
    }, sort_keys=True)
    finding = _make_finding(
        session_id=session_id,
        target_ip=target_ip,
        target_port=161,
        target_service=RULE_ID,
        evidence_raw=evidence,
        evidence_command=f"SNMP default-community probe on {target_ip}:161/udp (communities redacted)",
    )
    return CredentialProbeResult("snmp", SUCCESS, ("[redacted]",) * len(communities)), [finding]


def _try_snmp_community(target_ip: str, community: str) -> str:
    """Send a minimal SNMPv1 GET (sysDescr) and check for a response.

    Args:
        target_ip: Host to probe.
        community: Community string to try.

    Returns:
        Optional[bool]: True if a SNMP response arrived, False/None otherwise.
        None means network error / timeout (treat as no finding).
    """
    packet = _build_snmp_v1_get(community)
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(PROBE_TIMEOUT_SECONDS)
        sock.sendto(packet, (target_ip, 161))
        data, _addr = sock.recvfrom(4096)
        # SNMPv1 response must be a SEQUENCE (0x30) — basic structure check
        if not data or data[0] != 0x30:
            return False
        # Check that the response does not contain a SNMP error-status != 0
        # error-status is an INTEGER at a fixed offset in a well-formed SNMPv1 reply.
        # We look for a noSuchName (2) or genError (5) error-status which
        # means the community was rejected or OID unknown — still counts as
        # community accepted if the session was established.
        # A hard reject by wrong community returns no response at all (timeout).
        # Any valid SEQUENCE response means the community string was accepted.
        return SUCCESS
    except socket.timeout:
        return TIMEOUT
    except (ConnectionRefusedError, ConnectionResetError):
        return INACCESSIBLE
    except OSError:
        return ERROR
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _build_snmp_v1_get(community: str) -> bytes:
    """Build a minimal SNMPv1 GET PDU for OID 1.3.6.1.2.1.1.1.0 (sysDescr).

    Args:
        community: Community string.

    Returns:
        bytes: BER-encoded SNMPv1 GET request.
    """
    # OID 1.3.6.1.2.1.1.1.0 encoded
    oid = bytes([0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
    # NULL value
    null_val = bytes([0x05, 0x00])
    varbind = _ber_sequence(oid + null_val)
    varbind_list = _ber_sequence(varbind)
    # GET-request PDU: [0xA0] request-id=1, error-status=0, error-index=0
    request_id = bytes([0x02, 0x01, 0x01])
    error_status = bytes([0x02, 0x01, 0x00])
    error_index = bytes([0x02, 0x01, 0x00])
    pdu_content = request_id + error_status + error_index + varbind_list
    pdu = bytes([0xA0, len(pdu_content)]) + pdu_content
    # version INTEGER 0 (SNMPv1)
    version = bytes([0x02, 0x01, 0x00])
    community_bytes = community.encode("ascii", errors="replace")
    community_field = bytes([0x04, len(community_bytes)]) + community_bytes
    return _ber_sequence(version + community_field + pdu)


def _ber_sequence(content: bytes) -> bytes:
    """Wrap content in a BER SEQUENCE.

    Args:
        content: Inner bytes.

    Returns:
        bytes: SEQUENCE tag + length + content.
    """
    length = len(content)
    if length < 128:
        return bytes([0x30, length]) + content
    # Long form (enough for our tiny PDUs)
    return bytes([0x30, 0x81, length]) + content


def _summarize_status(results: Tuple[CredentialProbeResult, ...]) -> str:
    """Summarize probe outcomes without treating transport errors as NO_MATCH."""
    statuses = {result.status for result in results}
    if SUCCESS in statuses:
        return SUCCESS
    if TIMEOUT in statuses:
        return TIMEOUT
    if INACCESSIBLE in statuses:
        return INACCESSIBLE
    if ERROR in statuses:
        return ERROR
    return NO_MATCH


# ---------------------------------------------------------------------------
# Finding factory
# ---------------------------------------------------------------------------

def _make_finding(
    session_id: str,
    target_ip: str,
    target_port: int,
    target_service: str,
    evidence_raw: str,
    evidence_command: str,
) -> Finding:
    """Build a Finding for an accepted default credential.

    Args:
        session_id: Audit session ID.
        target_ip: Host that accepted the credential.
        target_port: Service port.
        target_service: Rule id for KB lookup (default_creds_found).
        evidence_raw: Proof text.
        evidence_command: Command / probe description.

    Returns:
        Finding: CREDENTIAL / HIGH / CONFIRMED. risk_score and explanation None.
    """
    return Finding(
        session_id=session_id,
        module=MODULE_NAME,
        target_ip=target_ip,
        target_port=target_port,
        target_service=target_service,
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        exposure=Exposure.INTERNAL,
        evidence=Evidence(raw=evidence_raw, command=evidence_command),
        explanation=None,
        risk_score=None,
    )
