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
import socket
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

# FTP: (username, password)
FTP_DEFAULTS: Sequence[Tuple[str, str]] = (
    ("anonymous", ""),
    ("anonymous", "anonymous"),
    ("ftp", "ftp"),
    ("admin", "admin"),
    ("admin", "password"),
)

# SNMP v1/v2c community strings (no username)
SNMP_DEFAULT_COMMUNITIES: Sequence[str] = (
    "public",
    "private",
)


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
    findings: List[Finding] = []

    findings.extend(_check_ftp_defaults(target_ip, session_id))
    findings.extend(_check_snmp_defaults(target_ip, session_id))

    if findings:
        display(
            f"[green]Default credentials: {len(findings)} success(es) "
            f"on {target_ip}.[/green]"
        )
    else:
        display(
            f"[yellow]Default credentials: no known defaults accepted "
            f"on {target_ip}.[/yellow]"
        )
    return findings


# ---------------------------------------------------------------------------
# FTP probes
# ---------------------------------------------------------------------------

def _check_ftp_defaults(target_ip: str, session_id: str) -> List[Finding]:
    """Try FTP_DEFAULTS against port 21. Stops after first success per pair.

    Args:
        target_ip: Host to probe.
        session_id: Audit session ID.

    Returns:
        List[Finding]: Findings for accepted FTP logins.
    """
    findings: List[Finding] = []
    for username, password in FTP_DEFAULTS:
        accepted = _try_ftp_login(target_ip, username, password)
        if accepted is True:
            display_pw = password if password else "(empty)"
            findings.append(
                _make_finding(
                    session_id=session_id,
                    target_ip=target_ip,
                    target_port=21,
                    target_service=RULE_ID,
                    evidence_raw=(
                        f"FTP login accepted on {target_ip}:21\n"
                        f"username={username} password={display_pw}\n"
                        f"Dictionary entry matched a factory default."
                    ),
                    evidence_command=(
                        f"ftp_login {target_ip} user={username} "
                        f"(default dictionary)"
                    ),
                )
            )
            # One Finding per accepted pair; continue to report other pairs
        # accepted is False or None (port closed / error) → skip that pair
    return findings


def _try_ftp_login(
    target_ip: str,
    username: str,
    password: str,
) -> Optional[bool]:
    """Attempt one FTP login. Returns True if accepted, False if rejected.

    Returns None when the service is unreachable (not a credential result).

    Args:
        target_ip: Host to probe.
        username: FTP username.
        password: FTP password.

    Returns:
        Optional[bool]: True accepted, False rejected, None unreachable.
    """
    ftp: Optional[ftplib.FTP] = None
    try:
        ftp = ftplib.FTP()
        ftp.connect(target_ip, 21, timeout=PROBE_TIMEOUT_SECONDS)
        ftp.login(username, password)
        return True
    except ftplib.error_perm:
        return False
    except (OSError, EOFError, ftplib.Error):
        return None
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
    """Try SNMP_DEFAULT_COMMUNITIES against UDP/161.

    Args:
        target_ip: Host to probe.
        session_id: Audit session ID.

    Returns:
        List[Finding]: Findings for communities that returned a response.
    """
    findings: List[Finding] = []
    for community in SNMP_DEFAULT_COMMUNITIES:
        ok = _try_snmp_community(target_ip, community)
        if ok is True:
            findings.append(
                _make_finding(
                    session_id=session_id,
                    target_ip=target_ip,
                    target_port=161,
                    target_service=RULE_ID,
                    evidence_raw=(
                        f"SNMPv1 GET accepted on {target_ip}:161/udp\n"
                        f"community={community}\n"
                        f"Dictionary entry matched a factory default."
                    ),
                    evidence_command=(
                        f"snmpget -v1 -c {community} {target_ip} "
                        f"sysDescr.0 (default dictionary)"
                    ),
                )
            )
    return findings


def _try_snmp_community(target_ip: str, community: str) -> Optional[bool]:
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
        # SNMPv1 response starts with SEQUENCE; crude but enough for V1 lab
        if data and data[0] == 0x30:
            return True
        return False
    except (OSError, socket.timeout):
        return None
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
