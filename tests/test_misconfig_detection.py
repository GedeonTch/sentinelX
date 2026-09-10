"""
tests/test_misconfig_detection.py — Unit tests for detect/misconfig_detection.py

Strategy:
- All tests use Finding objects built in memory — no network, no DB
- One test class per rule
- Each rule tested: fires when port present, does NOT fire when absent
- Invariants: risk_score=None, explanation=None, category=CONFIG
- detect_misconfigs() integration: multiple rules at once
"""

import pytest
from core.finding import (
    Finding,
    Evidence,
    Category,
    Severity,
    Confidence,
    Exposure,
    FindingStatus,
)
from detect.misconfig_detection import (
    detect_misconfigs,
    _check_telnet,
    _check_ftp_plain,
    _check_http_no_https,
    _check_snmp_exposed,
    _check_smb_signing,
    _check_weak_ssh,
    _check_rdp_exposed,
    _extract_ssh_major_version,
    RULE_TELNET,
    RULE_FTP_PLAIN,
    RULE_HTTP_NO_HTTPS,
    RULE_SNMP_EXPOSED,
    RULE_SMB_SIGNING,
    RULE_WEAK_SSH,
    RULE_RDP_EXPOSED,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_port_finding(
    port: int,
    service: str = "unknown",
    service_version: str = "",
    target_ip: str = "192.168.1.10",
    session_id: str = "session-test",
) -> Finding:
    return Finding(
        session_id=session_id,
        module="tcp_scan",
        target_ip=target_ip,
        target_port=port,
        target_service=service,
        service_version=service_version,
        category=Category.SERVICE,
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        evidence=Evidence(raw=f"PORT {port}/tcp open", command=f"nmap {target_ip}"),
    )


def by_port_from(findings: list) -> dict:
    return {f.target_port: f for f in findings if f.target_port is not None}


HOST = "192.168.1.10"
SESSION = "session-test"


# ---------------------------------------------------------------------------
# RULE_TELNET
# ---------------------------------------------------------------------------

class TestTelnet:
    def test_fires_when_port_23_open(self):
        bp = by_port_from([make_port_finding(23, "telnet")])
        result = _check_telnet(bp, HOST, SESSION)
        assert result is not None
        assert result.target_port == 23
        assert result.severity == Severity.HIGH
        assert result.confidence == Confidence.CONFIRMED
        assert result.category == Category.CONFIG
        assert RULE_TELNET in result.module

    def test_does_not_fire_when_port_23_absent(self):
        bp = by_port_from([make_port_finding(22, "ssh")])
        assert _check_telnet(bp, HOST, SESSION) is None

    def test_evidence_mentions_cleartext(self):
        bp = by_port_from([make_port_finding(23, "telnet")])
        result = _check_telnet(bp, HOST, SESSION)
        assert "cleartext" in result.evidence.raw.lower()

    def test_risk_score_is_none(self):
        bp = by_port_from([make_port_finding(23, "telnet")])
        assert _check_telnet(bp, HOST, SESSION).risk_score is None

    def test_explanation_is_none(self):
        bp = by_port_from([make_port_finding(23, "telnet")])
        assert _check_telnet(bp, HOST, SESSION).explanation is None


# ---------------------------------------------------------------------------
# RULE_FTP_PLAIN
# ---------------------------------------------------------------------------

class TestFtpPlain:
    def test_fires_when_port_21_open(self):
        bp = by_port_from([make_port_finding(21, "ftp", "vsftpd 3.0.3")])
        result = _check_ftp_plain(bp, HOST, SESSION)
        assert result is not None
        assert result.target_port == 21
        assert result.severity == Severity.MEDIUM
        assert result.confidence == Confidence.CONFIRMED
        assert RULE_FTP_PLAIN in result.module

    def test_does_not_fire_when_port_21_absent(self):
        bp = by_port_from([make_port_finding(22, "ssh")])
        assert _check_ftp_plain(bp, HOST, SESSION) is None

    def test_evidence_mentions_cleartext(self):
        bp = by_port_from([make_port_finding(21, "ftp")])
        result = _check_ftp_plain(bp, HOST, SESSION)
        assert "cleartext" in result.evidence.raw.lower()


# ---------------------------------------------------------------------------
# RULE_HTTP_NO_HTTPS
# ---------------------------------------------------------------------------

class TestHttpNoHttps:
    def test_fires_when_80_open_and_443_absent(self):
        ports = {80}
        bp = by_port_from([make_port_finding(80, "http", "nginx 1.18.0")])
        result = _check_http_no_https(ports, bp, HOST, SESSION)
        assert result is not None
        assert result.target_port == 80
        assert result.severity == Severity.MEDIUM
        assert RULE_HTTP_NO_HTTPS in result.module

    def test_does_not_fire_when_443_also_open(self):
        """If HTTPS is present alongside HTTP, rule must NOT fire."""
        ports = {80, 443}
        bp = by_port_from([
            make_port_finding(80, "http"),
            make_port_finding(443, "https"),
        ])
        assert _check_http_no_https(ports, bp, HOST, SESSION) is None

    def test_does_not_fire_when_80_absent(self):
        ports = {443}
        bp = by_port_from([make_port_finding(443, "https")])
        assert _check_http_no_https(ports, bp, HOST, SESSION) is None

    def test_evidence_mentions_tls(self):
        ports = {80}
        bp = by_port_from([make_port_finding(80, "http")])
        result = _check_http_no_https(ports, bp, HOST, SESSION)
        assert "tls" in result.evidence.raw.lower() or "https" in result.evidence.raw.lower()


# ---------------------------------------------------------------------------
# RULE_SNMP_EXPOSED
# ---------------------------------------------------------------------------

class TestSnmpExposed:
    def test_fires_when_port_161_open(self):
        bp = by_port_from([make_port_finding(161, "snmp")])
        result = _check_snmp_exposed(bp, HOST, SESSION)
        assert result is not None
        assert result.target_port == 161
        assert result.severity == Severity.MEDIUM
        assert result.confidence == Confidence.CONFIRMED
        assert RULE_SNMP_EXPOSED in result.module

    def test_does_not_fire_when_port_161_absent(self):
        bp = by_port_from([make_port_finding(22, "ssh")])
        assert _check_snmp_exposed(bp, HOST, SESSION) is None

    def test_evidence_mentions_community_string(self):
        bp = by_port_from([make_port_finding(161, "snmp")])
        result = _check_snmp_exposed(bp, HOST, SESSION)
        assert "community" in result.evidence.raw.lower()


# ---------------------------------------------------------------------------
# RULE_SMB_SIGNING
# ---------------------------------------------------------------------------

class TestSmbSigning:
    def test_fires_when_port_445_open(self):
        bp = by_port_from([make_port_finding(445, "microsoft-ds")])
        result = _check_smb_signing(bp, HOST, SESSION)
        assert result is not None
        assert result.target_port == 445
        assert result.severity == Severity.MEDIUM
        assert result.confidence == Confidence.PROBABLE
        assert RULE_SMB_SIGNING in result.module

    def test_does_not_fire_when_port_445_absent(self):
        bp = by_port_from([make_port_finding(22, "ssh")])
        assert _check_smb_signing(bp, HOST, SESSION) is None

    def test_evidence_mentions_relay(self):
        bp = by_port_from([make_port_finding(445, "microsoft-ds")])
        result = _check_smb_signing(bp, HOST, SESSION)
        assert "relay" in result.evidence.raw.lower()


# ---------------------------------------------------------------------------
# RULE_WEAK_SSH
# ---------------------------------------------------------------------------

class TestWeakSsh:
    def test_fires_for_openssh_below_7(self):
        bp = by_port_from([make_port_finding(22, "ssh", "OpenSSH 6.7 protocol 2.0")])
        result = _check_weak_ssh(bp, HOST, SESSION)
        assert result is not None
        assert result.severity == Severity.MEDIUM
        assert result.confidence == Confidence.PROBABLE
        assert RULE_WEAK_SSH in result.module

    def test_does_not_fire_for_openssh_7_or_higher(self):
        bp = by_port_from([make_port_finding(22, "ssh", "OpenSSH 8.9 protocol 2.0")])
        assert _check_weak_ssh(bp, HOST, SESSION) is None

    def test_does_not_fire_for_openssh_exactly_7(self):
        bp = by_port_from([make_port_finding(22, "ssh", "OpenSSH 7.0")])
        assert _check_weak_ssh(bp, HOST, SESSION) is None

    def test_does_not_fire_when_port_22_absent(self):
        bp = by_port_from([make_port_finding(80, "http")])
        assert _check_weak_ssh(bp, HOST, SESSION) is None

    def test_does_not_fire_for_non_openssh(self):
        """Dropbear SSH should not trigger this rule."""
        bp = by_port_from([make_port_finding(22, "ssh", "Dropbear 2020.81")])
        assert _check_weak_ssh(bp, HOST, SESSION) is None

    def test_does_not_fire_when_version_unknown(self):
        bp = by_port_from([make_port_finding(22, "ssh", "")])
        assert _check_weak_ssh(bp, HOST, SESSION) is None


# ---------------------------------------------------------------------------
# RULE_RDP_EXPOSED
# ---------------------------------------------------------------------------

class TestRdpExposed:
    def test_fires_when_port_3389_open(self):
        bp = by_port_from([make_port_finding(3389, "ms-wbt-server")])
        result = _check_rdp_exposed(bp, HOST, SESSION)
        assert result is not None
        assert result.target_port == 3389
        assert result.severity == Severity.HIGH
        assert result.confidence == Confidence.CONFIRMED
        assert RULE_RDP_EXPOSED in result.module

    def test_does_not_fire_when_port_3389_absent(self):
        bp = by_port_from([make_port_finding(22, "ssh")])
        assert _check_rdp_exposed(bp, HOST, SESSION) is None

    def test_evidence_mentions_vpn_or_firewall(self):
        bp = by_port_from([make_port_finding(3389, "ms-wbt-server")])
        result = _check_rdp_exposed(bp, HOST, SESSION)
        assert "vpn" in result.evidence.raw.lower() or "firewall" in result.evidence.raw.lower()


# ---------------------------------------------------------------------------
# _extract_ssh_major_version
# ---------------------------------------------------------------------------

class TestExtractSshVersion:
    def test_extracts_6_7(self):
        assert _extract_ssh_major_version("OpenSSH 6.7 protocol 2.0") == 6.7

    def test_extracts_8_9(self):
        assert _extract_ssh_major_version("OpenSSH 8.9p1 Ubuntu") == 8.9

    def test_returns_none_for_non_openssh(self):
        assert _extract_ssh_major_version("Dropbear 2020.81") is None

    def test_returns_none_for_empty_string(self):
        assert _extract_ssh_major_version("") is None

    def test_returns_none_for_no_version(self):
        assert _extract_ssh_major_version("OpenSSH") is None


# ---------------------------------------------------------------------------
# detect_misconfigs() — integration
# ---------------------------------------------------------------------------

class TestDetectMisconfigs:
    def test_detects_multiple_misconfigs(self):
        """Multiple misconfigs on the same host — all detected."""
        findings = [
            make_port_finding(23, "telnet"),
            make_port_finding(21, "ftp"),
            make_port_finding(445, "microsoft-ds"),
        ]
        results = detect_misconfigs(findings, SESSION)
        rules = [r.target_service for r in results]
        assert RULE_TELNET in rules
        assert RULE_FTP_PLAIN in rules
        assert RULE_SMB_SIGNING in rules

    def test_returns_empty_for_clean_host(self):
        """A host with only SSH open should trigger no misconfigs."""
        findings = [make_port_finding(22, "ssh", "OpenSSH 9.0")]
        results = detect_misconfigs(findings, SESSION)
        assert results == []

    def test_returns_empty_for_empty_findings(self):
        assert detect_misconfigs([], SESSION) == []

    def test_all_results_risk_score_none(self):
        findings = [
            make_port_finding(23, "telnet"),
            make_port_finding(3389, "ms-wbt-server"),
        ]
        results = detect_misconfigs(findings, SESSION)
        assert all(r.risk_score is None for r in results)

    def test_all_results_explanation_none(self):
        findings = [make_port_finding(23, "telnet")]
        results = detect_misconfigs(findings, SESSION)
        assert all(r.explanation is None for r in results)

    def test_all_results_category_config(self):
        findings = [make_port_finding(21, "ftp")]
        results = detect_misconfigs(findings, SESSION)
        assert all(r.category == Category.CONFIG for r in results)

    def test_all_results_have_session_id(self):
        findings = [make_port_finding(23, "telnet", session_id="session-xyz")]
        results = detect_misconfigs(findings, "session-xyz")
        assert all(r.session_id == "session-xyz" for r in results)

    def test_original_findings_not_mutated(self):
        """detect_misconfigs must not modify the input Findings."""
        f = make_port_finding(23, "telnet")
        original_severity = f.severity
        detect_misconfigs([f], SESSION)
        assert f.severity == original_severity

    def test_http_no_https_fires_when_443_absent(self):
        findings = [make_port_finding(80, "http", "nginx 1.18.0")]
        results = detect_misconfigs(findings, SESSION)
        assert any(RULE_HTTP_NO_HTTPS in r.module for r in results)

    def test_http_no_https_does_not_fire_when_443_present(self):
        findings = [
            make_port_finding(80, "http"),
            make_port_finding(443, "https"),
        ]
        results = detect_misconfigs(findings, SESSION)
        assert not any(RULE_HTTP_NO_HTTPS in r.module for r in results)

    def test_windows_host_with_445_and_3389(self):
        """Realistic Windows host — SMB signing + RDP both flagged."""
        findings = [
            make_port_finding(135, "msrpc"),
            make_port_finding(139, "netbios-ssn"),
            make_port_finding(445, "microsoft-ds"),
            make_port_finding(3389, "ms-wbt-server"),
        ]
        results = detect_misconfigs(findings, SESSION)
        rules = [r.target_service for r in results]
        assert RULE_SMB_SIGNING in rules
        assert RULE_RDP_EXPOSED in rules
