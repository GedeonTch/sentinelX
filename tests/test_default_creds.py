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
    ERROR,
    INACCESSIBLE,
    NO_MATCH,
    RULE_ID,
    SUCCESS,
    TIMEOUT,
    _check_ftp_defaults,
    _check_snmp_defaults,
    _check_ftp_defaults_result,
    _check_snmp_defaults_result,
    FTP_DEFAULTS,
    check_default_creds,
)


SESSION = "session-test"
HOST = "192.168.1.50"


class TestNominalFtp:
    def test_accepted_ftp_default_produces_credential_finding(self):
        with patch("detect.default_creds._try_ftp_login", return_value=SUCCESS):
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

    def test_multiple_valid_ftp_credentials_produce_one_finding(self):
        with patch("detect.default_creds._try_ftp_login", side_effect=[SUCCESS, SUCCESS, NO_MATCH]):
            findings = _check_ftp_defaults(HOST, SESSION)
        assert len(findings) == 1
        assert "successful_usernames" in findings[0].evidence.raw
        assert "ftp" in findings[0].evidence.raw
        assert "admin" in findings[0].evidence.raw
        assert "password" not in findings[0].evidence.raw

    def test_rejected_ftp_produces_no_finding(self):
        with patch("detect.default_creds._try_ftp_login", return_value=NO_MATCH):
            assert _check_ftp_defaults(HOST, SESSION) == []

    def test_unreachable_ftp_produces_no_finding(self):
        with patch("detect.default_creds._try_ftp_login", return_value=INACCESSIBLE):
            assert _check_ftp_defaults(HOST, SESSION) == []


class TestNominalSnmp:
    def test_accepted_community_produces_finding(self):
        with patch("detect.default_creds._try_snmp_community", return_value=SUCCESS):
            findings = _check_snmp_defaults(HOST, SESSION)
        assert len(findings) >= 1
        f = findings[0]
        assert f.category == Category.CREDENTIAL
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.CONFIRMED
        assert f.target_port == 161
        assert f.target_service == RULE_ID
        assert "successful_communities" in f.evidence.raw
        assert "public" not in f.evidence.raw

    def test_snmp_timeout_produces_no_finding(self):
        with patch("detect.default_creds._try_snmp_community", return_value=TIMEOUT):
            assert _check_snmp_defaults(HOST, SESSION) == []


class TestInvariants:
    def test_risk_score_and_explanation_none(self):
        with patch("detect.default_creds._try_ftp_login", side_effect=[SUCCESS] + [NO_MATCH] * 2):
            findings = _check_ftp_defaults(HOST, SESSION)
        assert findings
        assert all(f.risk_score is None for f in findings)
        assert all(f.explanation is None for f in findings)
        assert all(f.status == FindingStatus.OPEN for f in findings)
        assert all(f.evidence.raw for f in findings)


class TestCheckDefaultCredsEdges:
    def test_anonymous_is_not_classified_as_default_credential(self):
        assert all(username != "anonymous" for username, _password in FTP_DEFAULTS)

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
             patch("detect.default_creds._try_ftp_login", return_value=NO_MATCH), \
             patch("detect.default_creds._try_snmp_community", return_value=TIMEOUT):
            result = check_default_creds(HOST, SESSION)
        assert result == []

    def test_combined_successes(self):
        with patch("detect.default_creds.typer.confirm", return_value=True), \
             patch("detect.default_creds._try_ftp_login", side_effect=[SUCCESS] + [NO_MATCH] * 2), \
             patch("detect.default_creds._try_snmp_community", side_effect=[SUCCESS, NO_MATCH]):
            result = check_default_creds(HOST, SESSION)
        assert len(result) >= 2
        ports = {f.target_port for f in result}
        assert 21 in ports
        assert 161 in ports


class TestNormalizedProbeStatuses:
    def test_ftp_timeout_is_distinct_from_no_match(self):
        with patch("detect.default_creds._try_ftp_login", return_value=TIMEOUT):
            result, findings = _check_ftp_defaults_result(HOST, SESSION)
        assert result.status == TIMEOUT
        assert findings == []

    def test_ftp_connection_error_is_distinct_from_no_match(self):
        with patch("detect.default_creds._try_ftp_login", return_value=ERROR):
            result, findings = _check_ftp_defaults_result(HOST, SESSION)
        assert result.status == ERROR
        assert findings == []

    def test_snmp_inaccessible_is_distinct_from_no_match(self):
        with patch("detect.default_creds._try_snmp_community", return_value=INACCESSIBLE):
            result, findings = _check_snmp_defaults_result(HOST, SESSION)
        assert result.status == INACCESSIBLE
        assert findings == []


class TestSnmpPacketBuilder:
    def test_build_snmp_packet_is_sequence(self):
        from detect.default_creds import _build_snmp_v1_get

        packet = _build_snmp_v1_get("public")
        assert packet[0] == 0x30
        assert b"public" in packet
