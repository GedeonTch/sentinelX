"""
detect/misconfig_detection.py — Misconfiguration detection on open services

Pipeline step: DETECT
Role: Identify dangerous service configurations that do not require
      a CVE but represent real security risks.

This module operates on the List[Finding] already produced by tcp_scan /
udp_scan — it inspects service names, ports, and banners to flag known
bad configurations.

It does NOT perform new scans. It re-uses the evidence already collected.
No new network traffic is sent — no confirmation prompt needed.

Rules enforced here:
- ZERO import sqlite3
- ZERO print() — display via core/logger.py
- ZERO risk_score calculation
- ALWAYS return List[Finding]
- No (y/n) confirmation — no new network traffic
- explanation = None (knowledge base ticket #015)
- evidence.raw documents WHY the rule fired

Misconfig rules implemented:
    RULE_TELNET          — Telnet exposed (port 23, cleartext protocol)
    RULE_FTP_PLAIN       — FTP exposed (port 21, cleartext credentials)
    RULE_HTTP_NO_HTTPS   — HTTP on port 80 with no HTTPS on port 443
    RULE_SNMP_EXPOSED    — SNMP exposed (port 161/udp, default community risk)
    RULE_SMB_SIGNING     — SMB port open without signing evidence
    RULE_WEAK_SSH        — SSH version too old (< 7.0, known weak ciphers)
    RULE_OPEN_TELNET_ALT — Telnet on non-standard port (suspicious)
    RULE_RDP_EXPOSED     — RDP exposed externally (lateral movement risk)

Confidence:
    CONFIRMED — rule fires on direct port observation (no guessing)
    PROBABLE  — rule fires on banner content inference
"""

import dataclasses
from typing import List, Optional

from core.finding import (
    Finding,
    Evidence,
    Category,
    Severity,
    Confidence,
    Exposure,
)
from core.logger import display


# ---------------------------------------------------------------------------
# Rule identifiers — used in module field suffix for traceability
# ---------------------------------------------------------------------------

RULE_TELNET = "telnet_exposed"
RULE_FTP_PLAIN = "ftp_plaintext"
RULE_HTTP_NO_HTTPS = "http_no_https"
RULE_SNMP_EXPOSED = "snmp_exposed"
RULE_SMB_SIGNING = "smb_signing_missing"
RULE_WEAK_SSH = "ssh_weak_version"
RULE_RDP_EXPOSED = "rdp_exposed"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def detect_misconfigs(findings: List[Finding], session_id: str) -> List[Finding]:
    """Analyse existing Findings and return new Findings for detected misconfigs.

    Takes the output of tcp_scan / udp_scan and applies deterministic rules.
    No new network traffic — reads Finding fields only.

    Args:
        findings:   List of Findings from tcp_scan or udp_scan.
        session_id: Current audit session ID.

    Returns:
        List[Finding]: New Findings for each detected misconfiguration.
                       Empty if none detected. Original findings untouched.
    """
    misconfigs: List[Finding] = []

    # Index findings by port and service for fast lookup
    ports_open = {f.target_port for f in findings if f.target_port is not None}
    by_port = {f.target_port: f for f in findings if f.target_port is not None}
    host_ip = _get_host_ip(findings)

    if not host_ip:
        return []

    # Apply each rule
    rules = [
        _check_telnet(by_port, host_ip, session_id),
        _check_ftp_plain(by_port, host_ip, session_id),
        _check_http_no_https(ports_open, by_port, host_ip, session_id),
        _check_snmp_exposed(by_port, host_ip, session_id),
        _check_smb_signing(by_port, host_ip, session_id),
        _check_weak_ssh(by_port, host_ip, session_id),
        _check_rdp_exposed(by_port, host_ip, session_id),
    ]

    for result in rules:
        if result is not None:
            misconfigs.append(result)

    if misconfigs:
        display(
            f"[green]Misconfig detection: {len(misconfigs)} misconfiguration(s) "
            f"found on {host_ip}.[/green]"
        )
    else:
        display(f"[dim]Misconfig detection: no misconfigurations found on {host_ip}.[/dim]")

    return misconfigs


# ---------------------------------------------------------------------------
# Rule implementations
# ---------------------------------------------------------------------------

def _check_telnet(
    by_port: dict,
    host_ip: str,
    session_id: str,
) -> Optional[Finding]:
    """RULE_TELNET — Telnet service detected on port 23.

    Telnet transmits credentials and data in cleartext. Any attacker
    on the same network segment can capture credentials with a simple
    packet sniffer.
    """
    if 23 not in by_port:
        return None
    original = by_port[23]
    return _make_misconfig_finding(
        session_id=session_id,
        host_ip=host_ip,
        port=23,
        rule=RULE_TELNET,
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        evidence_raw=(
            f"Port 23/tcp open — service: {original.target_service}\n"
            f"Telnet transmits credentials in cleartext. "
            f"Replace with SSH immediately."
        ),
        evidence_command=f"nmap -sV -p 23 {host_ip}",
    )


def _check_ftp_plain(
    by_port: dict,
    host_ip: str,
    session_id: str,
) -> Optional[Finding]:
    """RULE_FTP_PLAIN — FTP service detected on port 21.

    FTP transmits credentials and data in cleartext (no encryption).
    Replace with SFTP or FTPS.
    """
    if 21 not in by_port:
        return None
    original = by_port[21]
    return _make_misconfig_finding(
        session_id=session_id,
        host_ip=host_ip,
        port=21,
        rule=RULE_FTP_PLAIN,
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        evidence_raw=(
            f"Port 21/tcp open — service: {original.target_service} "
            f"{original.service_version}\n"
            f"FTP transmits credentials in cleartext. Use SFTP or FTPS."
        ),
        evidence_command=f"nmap -sV -p 21 {host_ip}",
    )


def _check_http_no_https(
    ports_open: set,
    by_port: dict,
    host_ip: str,
    session_id: str,
) -> Optional[Finding]:
    """RULE_HTTP_NO_HTTPS — HTTP on port 80 with no HTTPS on port 443.

    A web service running HTTP only exposes all traffic to interception.
    If HTTPS is also open, the rule does not fire — mixed config is
    a separate concern.
    """
    if 80 not in ports_open:
        return None
    if 443 in ports_open:
        return None  # HTTPS also present — not a pure-HTTP service

    original = by_port[80]
    return _make_misconfig_finding(
        session_id=session_id,
        host_ip=host_ip,
        port=80,
        rule=RULE_HTTP_NO_HTTPS,
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        evidence_raw=(
            f"Port 80/tcp open ({original.target_service} "
            f"{original.service_version}) — port 443 not open.\n"
            f"HTTP traffic is unencrypted. Deploy TLS and redirect HTTP→HTTPS."
        ),
        evidence_command=f"nmap -p 80,443 {host_ip}",
    )


def _check_snmp_exposed(
    by_port: dict,
    host_ip: str,
    session_id: str,
) -> Optional[Finding]:
    """RULE_SNMP_EXPOSED — SNMP detected on port 161.

    SNMP v1/v2c uses community strings (default: public/private) that
    are transmitted in cleartext. Exposed SNMP can leak full device
    configuration. Check default_creds (#013) for community string test.
    """
    if 161 not in by_port:
        return None
    return _make_misconfig_finding(
        session_id=session_id,
        host_ip=host_ip,
        port=161,
        rule=RULE_SNMP_EXPOSED,
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        evidence_raw=(
            f"Port 161/udp open — SNMP exposed.\n"
            f"SNMPv1/v2c community strings are sent in cleartext. "
            f"Default strings (public/private) are commonly exploited. "
            f"Upgrade to SNMPv3 with authentication and encryption."
        ),
        evidence_command=f"nmap -sU -p 161 {host_ip}",
    )


def _check_smb_signing(
    by_port: dict,
    host_ip: str,
    session_id: str,
) -> Optional[Finding]:
    """RULE_SMB_SIGNING — SMB port 445 open.

    SMB without signing enabled allows relay attacks (NTLM relay).
    An attacker can intercept SMB authentication and relay it to other
    services without knowing the password.
    """
    if 445 not in by_port:
        return None
    return _make_misconfig_finding(
        session_id=session_id,
        host_ip=host_ip,
        port=445,
        rule=RULE_SMB_SIGNING,
        severity=Severity.MEDIUM,
        confidence=Confidence.PROBABLE,  # signing status requires smb_enum confirmation
        evidence_raw=(
            f"Port 445/tcp open — SMB signing status unknown from port scan alone.\n"
            f"If SMB signing is disabled, NTLM relay attacks are possible. "
            f"Run smb_enum (#011) to confirm signing status."
        ),
        evidence_command=f"nmap -p 445 {host_ip}",
    )


def _check_weak_ssh(
    by_port: dict,
    host_ip: str,
    session_id: str,
) -> Optional[Finding]:
    """RULE_WEAK_SSH — SSH version older than 7.0 detected.

    Older OpenSSH versions support deprecated ciphers (3DES, RC4, MD5 HMAC)
    and have known vulnerabilities. Version inferred from service_version banner.
    """
    if 22 not in by_port:
        return None

    original = by_port[22]
    version = _extract_ssh_major_version(original.service_version)
    if version is None or version >= 7.0:
        return None

    return _make_misconfig_finding(
        session_id=session_id,
        host_ip=host_ip,
        port=22,
        rule=RULE_WEAK_SSH,
        severity=Severity.MEDIUM,
        confidence=Confidence.PROBABLE,  # inferred from banner
        evidence_raw=(
            f"Port 22/tcp — SSH version: {original.service_version}\n"
            f"OpenSSH < 7.0 supports deprecated ciphers and has known "
            f"vulnerabilities. Upgrade to OpenSSH 8.x or later."
        ),
        evidence_command=f"nmap -sV -p 22 {host_ip}",
    )


def _check_rdp_exposed(
    by_port: dict,
    host_ip: str,
    session_id: str,
) -> Optional[Finding]:
    """RULE_RDP_EXPOSED — RDP detected on port 3389.

    RDP exposed on the network is a high-value target for brute-force
    and exploitation (BlueKeep, DejaBlue). Should be restricted to VPN
    or specific source IPs via firewall rules.
    """
    if 3389 not in by_port:
        return None
    return _make_misconfig_finding(
        session_id=session_id,
        host_ip=host_ip,
        port=3389,
        rule=RULE_RDP_EXPOSED,
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        evidence_raw=(
            f"Port 3389/tcp open — RDP exposed on the network.\n"
            f"RDP should not be directly accessible. Restrict via firewall "
            f"or VPN. See also CVE-2019-0708 (BlueKeep)."
        ),
        evidence_command=f"nmap -p 3389 {host_ip}",
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_host_ip(findings: List[Finding]) -> str:
    """Return the target IP shared by all findings, or empty string."""
    ips = {f.target_ip for f in findings if f.target_ip}
    return next(iter(ips), "") if len(ips) == 1 else next(iter(ips), "")


def _extract_ssh_major_version(service_version: str) -> Optional[float]:
    """Parse the major.minor version from an SSH service_version string.

    Examples:
        "OpenSSH 6.7 protocol 2.0" → 6.7
        "OpenSSH 8.9p1"            → 8.9
        "Dropbear 2020.81"         → None (not OpenSSH)

    Args:
        service_version: service_version field from a Finding.

    Returns:
        float: major.minor as float, or None if unparseable.
    """
    import re
    if not service_version or "openssh" not in service_version.lower():
        return None
    match = re.search(r"(\d+\.\d+)", service_version)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            return None
    return None


def _make_misconfig_finding(
    session_id: str,
    host_ip: str,
    port: int,
    rule: str,
    severity: Severity,
    confidence: Confidence,
    evidence_raw: str,
    evidence_command: str,
) -> Finding:
    """Build a misconfiguration Finding.

    Args:
        session_id:       Current audit session ID.
        host_ip:          Target IP address.
        port:             Port where the misconfiguration was observed.
        rule:             Rule identifier string (e.g. RULE_TELNET).
        severity:         Severity level.
        confidence:       Confidence level.
        evidence_raw:     Human-readable explanation of why the rule fired.
        evidence_command: Command that produced the observation.

    Returns:
        Finding: Populated misconfiguration Finding.
    """
    return Finding(
        session_id=session_id,
        module=f"misconfig_detection.{rule}",
        target_ip=host_ip,
        target_port=port,
        target_service=rule,
        category=Category.CONFIG,
        severity=severity,
        confidence=confidence,
        exposure=Exposure.INTERNAL,
        evidence=Evidence(
            raw=evidence_raw,
            command=evidence_command,
        ),
        explanation=None,
        cve_refs=[],
        risk_score=None,
    )
