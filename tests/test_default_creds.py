"""
tests/test_default_creds.py — Unit tests for detect/default_creds.py

Strategy:
- ZERO real network — FTP and SNMP probes always mocked
- Nominal: accepted default → CREDENTIAL / HIGH / CONFIRMED
- Edge: user cancel → []
- Edge: all probes fail / unreachable → []
- Invariants: explanation=None, risk_score=None, target_service=default_creds_found
"""

from unittest.mock import patch

from core.finding import Category, Confidence, FindingStatus, Severity

from detect.default_creds import (
    RULE_ID,
    _check_ftp_defaults,
    _check_snmp_defaults,
    check_default_creds,
)


SESSION = "session-test"
HOST = "192.168.1.50"


class TestNominalFtp:
    def test_accepted_ftp_default_produces_credential_finding(self):
        with patch("detect.default_creds._try_ftp_login", return_value=True):
            findings = _check_ftp_defaults(HOST, SESSION)
        assert len(findings) >= 1
        f = findings[0]
        assert f.category == Category.CREDENTIAL
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.CONFIRMED
        assert f.module == "default_creds"
        assert f.target_service == RULE_ID
        assert f.target_port == 21
        assert f.session_id == SESSION
        assert f.target_ip == HOST

    def test_rejected_ftp_produces_no_finding(self):
        with patch("detect.default_creds._try_ftp_login", return_value=False):
            assert _check_ftp_defaults(HOST, SESSION) == []

    def test_unreachable_ftp_produces_no_finding(self):
        with patch("detect.default_creds._try_ftp_login", return_value=None):
            assert _check_ftp_defaults(HOST, SESSION) == []


class TestNominalSnmp:
    def test_accepted_community_produces_finding(self):
        with patch("detect.default_creds._try_snmp_community", return_value=True):
            findings = _check_snmp_defaults(HOST, SESSION)
        assert len(findings) >= 1
        f = findings[0]
        assert f.category == Category.CREDENTIAL
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.CONFIRMED
        assert f.target_port == 161
        assert f.target_service == RULE_ID
        assert "community=" in f.evidence.raw

    def test_snmp_timeout_produces_no_finding(self):
        with patch("detect.default_creds._try_snmp_community", return_value=None):
            assert _check_snmp_defaults(HOST, SESSION) == []


class TestInvariants:
    def test_risk_score_and_explanation_none(self):
        with patch("detect.default_creds._try_ftp_login", side_effect=[True] + [False] * 10):
            findings = _check_ftp_defaults(HOST, SESSION)
        assert findings
        assert all(f.risk_score is None for f in findings)
        assert all(f.explanation is None for f in findings)
        assert all(f.status == FindingStatus.OPEN for f in findings)
        assert all(f.evidence.raw for f in findings)


class TestCheckDefaultCredsEdges:
    def test_user_cancel_returns_empty_without_probe(self):
        with patch("detect.default_creds.typer.confirm", return_value=False), \
             patch("detect.default_creds._check_ftp_defaults") as mock_ftp, \
             patch("detect.default_creds._check_snmp_defaults") as mock_snmp:
            result = check_default_creds(HOST, SESSION)
        assert result == []
        mock_ftp.assert_not_called()
        mock_snmp.assert_not_called()

    def test_no_success_returns_empty(self):
        with patch("detect.default_creds.typer.confirm", return_value=True), \
             patch("detect.default_creds._try_ftp_login", return_value=False), \
             patch("detect.default_creds._try_snmp_community", return_value=None):
            result = check_default_creds(HOST, SESSION)
        assert result == []

    def test_combined_successes(self):
        with patch("detect.default_creds.typer.confirm", return_value=True), \
             patch("detect.default_creds._try_ftp_login", side_effect=[True] + [False] * 10), \
             patch("detect.default_creds._try_snmp_community", side_effect=[True, False]):
            result = check_default_creds(HOST, SESSION)
        assert len(result) >= 2
        ports = {f.target_port for f in result}
        assert 21 in ports
        assert 161 in ports


class TestSnmpPacketBuilder:
    def test_build_snmp_packet_is_sequence(self):
        from detect.default_creds import _build_snmp_v1_get

        packet = _build_snmp_v1_get("public")
        assert packet[0] == 0x30
        assert b"public" in packet
