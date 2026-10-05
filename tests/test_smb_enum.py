"""
tests/test_smb_enum.py — Unit tests for detect/smb_enum.py

Covers:
- Nominal: ADMIN$ → CREDENTIAL, MEDIUM, CONFIRMED
- One Finding per share + optional domain Finding
- Edge: enum4linux missing → []
- Edge: user cancel → []
- Edge: empty output → []
- Error: timeout / OSError → [] without crash
- Invariants: explanation is None, risk_score is None, evidence.raw is raw output
"""

import json
import subprocess
from unittest.mock import MagicMock, patch

from core.finding import Category, Confidence, FindingStatus, Severity

from detect.smb_enum import (
    SmbEnumerationResult,
    _parse_enum4linux_output,
    normalize_smb_output,
    smb_enum,
)

ENUM4LINUX_ADMIN = """
Starting enum4linux v0.8.9

 ==========================
|    Target Information    |
 ==========================
Target ........... 192.168.1.26

 ==========================================
|    Share Enumeration on 192.168.1.26     |
 ==========================================
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC

 =============================
|    Users on 192.168.1.26    |
 =============================
index: 0x1 RID: 0x1f4 acb: 0x00000210 Account: Administrator

[+] Attempting to get domain SID
Domain Name: LAB
Domain Sid: S-1-5-21-1234567890-1234567890-1234567890
"""

ENUM4LINUX_ADMIN_ONLY = """
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
"""

ENUM4LINUX_NO_DOMAIN = """
Sharename       Type      Comment
---------       ----      -------
Public          Disk      Team files
"""


class TestParseAdminShare:
    def test_admin_share_is_credential_medium_confirmed(self):
        findings = _parse_enum4linux_output(
            ENUM4LINUX_ADMIN_ONLY, "192.168.1.26", "session-test"
        )
        admin = [f for f in findings if f.target_service.upper() == "ADMIN$"]
        assert len(admin) == 1
        finding = admin[0]
        assert finding.category == Category.CREDENTIAL
        assert finding.severity == Severity.MEDIUM
        assert finding.confidence == Confidence.CONFIRMED
        assert finding.module == "smb_enum"
        assert finding.target_ip == "192.168.1.26"
        assert finding.target_port == 445
        assert finding.session_id == "session-test"

    def test_one_finding_per_share_plus_domain(self):
        findings = _parse_enum4linux_output(
            ENUM4LINUX_ADMIN, "192.168.1.26", "session-test"
        )
        share_names = [f.target_service for f in findings]
        assert share_names.count("ADMIN$") == 1
        assert share_names.count("C$") == 1
        assert share_names.count("IPC$") == 1
        assert "LAB" in share_names
        assert len(findings) == 4

    def test_no_domain_finding_when_domain_absent(self):
        findings = _parse_enum4linux_output(
            ENUM4LINUX_NO_DOMAIN, "192.168.1.26", "session-test"
        )
        assert len(findings) == 1
        assert findings[0].target_service == "Public"
        assert findings[0].category == Category.SERVICE
        assert findings[0].severity == Severity.INFO


class TestParseInvariants:
    def test_risk_score_is_none(self):
        findings = _parse_enum4linux_output(
            ENUM4LINUX_ADMIN_ONLY, "192.168.1.26", "session-test"
        )
        assert all(f.risk_score is None for f in findings)

    def test_explanation_is_none(self):
        findings = _parse_enum4linux_output(
            ENUM4LINUX_ADMIN_ONLY, "192.168.1.26", "session-test"
        )
        assert all(f.explanation is None for f in findings)

    def test_evidence_raw_is_full_output(self):
        findings = _parse_enum4linux_output(
            ENUM4LINUX_ADMIN_ONLY, "192.168.1.26", "session-test"
        )
        assert findings[0].evidence.raw == ENUM4LINUX_ADMIN_ONLY
        assert "enum4linux -a 192.168.1.26" == findings[0].evidence.command

    def test_status_is_open(self):
        findings = _parse_enum4linux_output(
            ENUM4LINUX_ADMIN_ONLY, "192.168.1.26", "session-test"
        )
        assert all(f.status == FindingStatus.OPEN for f in findings)

    def test_empty_output_returns_empty_list(self):
        assert _parse_enum4linux_output("", "192.168.1.26", "session-test") == []


class TestSmbEnumEdges:
    def test_enum4linux_absent_returns_empty_without_crash(self):
        with patch("detect.smb_enum.shutil.which", return_value=None):
            result = smb_enum("192.168.1.26", "session-test")
        assert result == []

    def test_user_cancel_returns_empty(self):
        with patch("detect.smb_enum.shutil.which", return_value="/usr/bin/enum4linux"), \
             patch("detect.smb_enum.typer.confirm", return_value=False), \
             patch("detect.smb_enum._run_enum4linux") as mock_run:
            result = smb_enum("192.168.1.26", "session-test")
        assert result == []
        mock_run.assert_not_called()

    def test_empty_tool_output_returns_empty(self):
        with patch("detect.smb_enum.shutil.which", return_value="/usr/bin/enum4linux"), \
             patch("detect.smb_enum.typer.confirm", return_value=True), \
             patch("detect.smb_enum._run_enum4linux", return_value=None):
            result = smb_enum("192.168.1.26", "session-test")
        assert result == []


class TestSmbEnumErrors:
    def test_timeout_returns_empty_without_crash(self):
        with patch("detect.smb_enum.shutil.which", return_value="/usr/bin/enum4linux"), \
             patch("detect.smb_enum.typer.confirm", return_value=True), \
             patch(
                 "detect.smb_enum.subprocess.run",
                 side_effect=__import__("subprocess").TimeoutExpired(
                     cmd="enum4linux", timeout=120
                 ),
             ):
            result = smb_enum("192.168.1.26", "session-test")
        assert result == []

    def test_oserror_returns_empty_without_crash(self):
        with patch("detect.smb_enum.shutil.which", return_value="/usr/bin/enum4linux"), \
             patch("detect.smb_enum.typer.confirm", return_value=True), \
             patch("detect.smb_enum.subprocess.run", side_effect=OSError("denied")):
            result = smb_enum("192.168.1.26", "session-test")
        assert result == []


class TestSmbEnumNominalRun:
    def test_admin_share_from_smb_enum_entry_point(self):
        completed = MagicMock()
        completed.stdout = ENUM4LINUX_ADMIN_ONLY
        completed.stderr = ""
        with patch("detect.smb_enum.shutil.which", return_value="/usr/bin/enum4linux"), \
             patch("detect.smb_enum.typer.confirm", return_value=True), \
             patch("detect.smb_enum.subprocess.run", return_value=completed):
            result = smb_enum("192.168.1.26", "session-test")
        assert len(result) == 1
        assert result[0].category == Category.CREDENTIAL
        assert result[0].severity == Severity.MEDIUM
        assert result[0].confidence == Confidence.CONFIRMED
        assert result[0].target_service == "ADMIN$"


class TestNormalizedSmbResult:
    def _json(self, **overrides):
        document = {
            "target": "192.168.56.10",
            "hostname": "WIN2016",
            "os": "Windows Server 2016",
            "domain": "LAB",
            "sid": "S-1-5-21-1-2-3",
            "mac": "00:11:22:33:44:55",
            "dialects": ["SMB2", "SMB3"],
            "signing_required": True,
            "anonymous_session": False,
            "shares": [{"name": "Public", "accessible": True, "permissions": "READ"}],
            "users": ["Administrator"],
            "groups": ["Users"],
        }
        document.update(overrides)
        return json.dumps(document)

    def test_complete_json_is_normalized(self):
        result = normalize_smb_output(self._json(), "192.168.56.10")
        assert isinstance(result, SmbEnumerationResult)
        assert result.os == "Windows Server 2016"
        assert result.hostname == "WIN2016"
        assert result.domain == "LAB"
        assert result.sid == "S-1-5-21-1-2-3"
        assert result.mac == "00:11:22:33:44:55"
        assert result.dialects == ("SMB2", "SMB3")
        assert result.signing_required is True
        assert result.anonymous_session is False
        assert result.shares[0].accessible is True
        assert result.users == ("Administrator",)

    def test_partial_json_keeps_unknown_values_as_none(self):
        result = normalize_smb_output(json.dumps({"hostname": "metasploitable"}), "10.0.0.5")
        assert result.hostname == "metasploitable"
        assert result.os is None
        assert result.domain is None
        assert result.signing_required is None
        assert result.anonymous_session is None
        assert result.shares == ()

    def test_absent_and_explicit_unknown_values_are_not_invented(self):
        result = normalize_smb_output(
            json.dumps({"os": None, "signing": "unknown", "anonymous": "unknown"}),
            "10.0.0.5",
        )
        assert result.os is None
        assert result.signing_required is None
        assert result.anonymous_session is None

    def test_ansi_text_is_parsed_without_control_codes(self):
        raw = "\x1b[31mSharename       Type\x1b[0m\nPublic          Disk\n"
        result = normalize_smb_output(raw, "10.0.0.5")
        assert [share.name for share in result.shares] == ["Public"]
        assert "\\x1b" not in result.raw_output

    def test_invalid_json_falls_back_to_text(self):
        result = normalize_smb_output(ENUM4LINUX_NO_DOMAIN, "192.168.1.26")
        assert result.source_format == "text"
        assert result.shares[0].name == "Public"

    def test_metasploitable2_fixture(self):
        raw = json.dumps({
            "hostname": "metasploitable2",
            "os": "Linux Metasploitable 2",
            "workgroup": "WORKGROUP",
            "dialects": ["SMBv1"],
            "anonymous_session": True,
            "shares": [{"name": "tmp", "accessible": True, "permissions": "READ_WRITE"}],
            "signing_required": False,
        })
        result = normalize_smb_output(raw, "192.168.56.101")
        assert result.os == "Linux Metasploitable 2"
        assert result.domain == "WORKGROUP"
        assert result.anonymous_session is True
        assert result.anonymous_share_access is True
        assert result.dialects == ("SMBv1",)
        assert result.signing_required is False

    def test_windows_server_2016_fixture(self):
        result = normalize_smb_output(
            self._json(anonymous_session=False, signing_required=True),
            "192.168.56.10",
        )
        assert result.os == "Windows Server 2016"
        assert result.anonymous_session is False
        assert result.signing_required is True


class TestNormalizedFindings:
    def test_anonymous_refused_creates_no_anonymous_finding(self):
        raw = json.dumps({"anonymous_session": False})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-test")
        assert not any("anonymous" in finding.target_service for finding in findings)

    def test_anonymous_session_alone_is_observation_only(self):
        raw = json.dumps({"anonymous_session": True})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-test")
        assert not any("anonymous" in finding.target_service for finding in findings)

    def test_anonymous_session_and_access_creates_stronger_finding(self):
        raw = json.dumps({
            "anonymous_session": True,
            "shares": [{"name": "Public", "accessible": True}],
        })
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-test")
        assert any(f.target_service == "smb_anonymous_share_access" for f in findings)

    def test_smbv1_enabled_and_signing_not_required_are_distinct_findings(self):
        raw = json.dumps({"dialects": ["SMBv1"], "signing_required": False})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-test")
        services = {finding.target_service for finding in findings}
        assert "SMBv1" in services
        assert "smb_signing_not_required" in services

    def test_smbv1_disabled_and_signing_required_create_no_security_finding(self):
        raw = json.dumps({"dialects": ["SMB2", "SMB3"], "signing_required": True})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-test")
        assert not any(f.target_service in {"SMBv1", "smb_signing_not_required"} for f in findings)

    def test_unknown_protocol_and_signing_create_no_finding(self):
        raw = json.dumps({"dialects": ["unknown"], "signing_required": "unknown"})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-test")
        assert findings == []
