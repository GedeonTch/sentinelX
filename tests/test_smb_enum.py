"""
tests/test_smb_enum.py — Unit tests for detect/smb_enum.py

Covers:
- Nominal: ADMIN$ → CREDENTIAL, MEDIUM, CONFIRMED
- One Finding per share + optional domain Finding
- Edge: enum4linux missing → []
- Edge: user cancel → []
- Edge: empty output → []
- Error: timeout / OSError → [] without crash
- Invariants: explanation is None, risk_score is None, evidence.raw holds analysed fields only
"""

import json
import os
import stat
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from core.finding import Category, Confidence, FindingStatus, Severity

from detect.smb_enum import (
    ENUM4LINUX_TIMEOUT_SECONDS,
    SmbEnumerationResult,
    _parse_enum4linux_output,
    _run_enum4linux_ng,
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
        # Five findings: the text output names "Account: Administrator", which the
        # corrected user regex (C7) now reads and reports as smb_users_enumerated.
        assert "smb_users_enumerated" in share_names
        assert len(findings) == 5

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

    def test_evidence_raw_holds_analysed_fields_only(self):
        findings = _parse_enum4linux_output(
            ENUM4LINUX_ADMIN_ONLY, "192.168.1.26", "session-test"
        )
        assert findings[0].evidence.raw != ENUM4LINUX_ADMIN_ONLY
        assert "Remote Admin" not in findings[0].evidence.raw
        assert json.loads(findings[0].evidence.raw) == {
            "share": "ADMIN$",
            "source": "enum4linux-ng share listing",
        }
        assert "enum4linux-ng -A -oJ <json-base> 192.168.1.26" == findings[0].evidence.command
        assert "--json" not in findings[0].evidence.command

    def test_status_is_open(self):
        findings = _parse_enum4linux_output(
            ENUM4LINUX_ADMIN_ONLY, "192.168.1.26", "session-test"
        )
        assert all(f.status == FindingStatus.OPEN for f in findings)

    def test_empty_output_returns_empty_list(self):
        assert _parse_enum4linux_output("", "192.168.1.26", "session-test") == []


class TestSmbEnumEdges:
    def test_enum4linux_absent_returns_empty_without_crash(self):
        with patch("detect.smb_enum._resolve_tool_path", return_value=None):
            result = smb_enum("192.168.1.26", "session-test")
        assert result == []

    def test_user_cancel_returns_empty(self):
        with patch("detect.smb_enum._resolve_tool_path", return_value="/usr/bin/enum4linux-ng"), \
             patch("detect.smb_enum.typer.confirm", return_value=False), \
             patch("detect.smb_enum._run_enum4linux_ng") as mock_run:
            result = smb_enum("192.168.1.26", "session-test")
        assert result == []
        mock_run.assert_not_called()

    def test_empty_tool_output_returns_empty(self):
        with patch("detect.smb_enum._resolve_tool_path", return_value="/usr/bin/enum4linux-ng"), \
             patch("detect.smb_enum.typer.confirm", return_value=True), \
             patch("detect.smb_enum._run_enum4linux_ng", return_value=None):
            result = smb_enum("192.168.1.26", "session-test")
        assert result == []


class TestSmbEnumErrors:
    def test_timeout_returns_empty_without_crash(self):
        with patch("detect.smb_enum._resolve_tool_path", return_value="/usr/bin/enum4linux-ng"), \
             patch("detect.smb_enum.typer.confirm", return_value=True), \
             patch(
                 "detect.smb_enum.subprocess.run",
                 side_effect=__import__("subprocess").TimeoutExpired(
                     cmd="enum4linux-ng", timeout=120
                 ),
             ):
            result = smb_enum("192.168.1.26", "session-test")
        assert result == []

    def test_oserror_returns_empty_without_crash(self):
        with patch("detect.smb_enum._resolve_tool_path", return_value="/usr/bin/enum4linux-ng"), \
             patch("detect.smb_enum.typer.confirm", return_value=True), \
             patch("detect.smb_enum.subprocess.run", side_effect=OSError("denied")):
            result = smb_enum("192.168.1.26", "session-test")
        assert result == []


class TestSmbEnumNominalRun:
    def test_admin_share_from_smb_enum_entry_point(self):
        completed = MagicMock()
        completed.returncode = 0
        completed.stdout = ENUM4LINUX_ADMIN_ONLY
        completed.stderr = ""
        with patch("detect.smb_enum._resolve_tool_path", return_value="/usr/bin/enum4linux-ng"), \
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


# ---------------------------------------------------------------------------
# smb_access_refused — null session explicitly refused (T14-c)
# ---------------------------------------------------------------------------

class TestSmbAccessRefused:
    def test_null_session_refused_creates_access_refused_finding(self):
        """anonymous_session=False must produce a smb_access_refused finding."""
        raw = json.dumps({"anonymous_session": False})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-test")
        refused = [f for f in findings if f.target_service == "smb_access_refused"]
        assert len(refused) == 1

    def test_access_refused_is_info_network_confirmed(self):
        raw = json.dumps({"anonymous_session": False})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-test")
        f = next(f for f in findings if f.target_service == "smb_access_refused")
        assert f.category == Category.NETWORK
        assert f.severity == Severity.INFO
        assert f.confidence == Confidence.CONFIRMED

    def test_null_session_unknown_does_not_create_refused_finding(self):
        """anonymous_session=None (unknown) must not produce smb_access_refused."""
        raw = json.dumps({"hostname": "somehost"})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-test")
        assert not any(f.target_service == "smb_access_refused" for f in findings)

    def test_null_session_accepted_does_not_create_refused_finding(self):
        """anonymous_session=True must not produce smb_access_refused."""
        raw = json.dumps({"anonymous_session": True})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-test")
        assert not any(f.target_service == "smb_access_refused" for f in findings)

    def test_access_refused_and_shares_coexist(self):
        """Refused session + detected shares must both produce findings."""
        raw = json.dumps({
            "anonymous_session": False,
            "shares": [{"name": "ADMIN$", "accessible": False}],
        })
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-test")
        services = {f.target_service for f in findings}
        assert "smb_access_refused" in services
        assert "ADMIN$" in services

    def test_ng_json_fixture_windows_server_2016(self):
        """Simulate a real enum4linux-ng JSON output for Windows Server 2016."""
        raw = json.dumps({
            "target": "192.168.57.10",
            "hostname": "WIN-RJDEKLL104D",
            "os": "Windows Server 2016",
            "domain": "ULBU",
            "dialects": ["SMB2", "SMB3"],
            "signing_required": True,
            "sessions": {"null_session": False},
            "shares": [],
        })
        # normalize_smb_output must read null_session from sessions sub-dict
        result = normalize_smb_output(raw, "192.168.57.10")
        assert result.os == "Windows Server 2016"
        assert result.domain == "ULBU"
        assert result.signing_required is True

    def test_ng_json_fixture_metasploitable2(self):
        """Simulate a real enum4linux-ng JSON output for Metasploitable2."""
        raw = json.dumps({
            "target": "192.168.57.3",
            "hostname": "metasploitable",
            "os": "Unix",
            "workgroup": "WORKGROUP",
            "dialects": ["SMBv1"],
            "signing_required": False,
            "sessions": {"null_session": True},
            "shares": [
                {"name": "tmp", "accessible": True, "permissions": "READ_WRITE"},
                {"name": "IPC$", "type": "IPC"},
            ],
        })
        result = normalize_smb_output(raw, "192.168.57.3")
        assert result.domain == "WORKGROUP"
        assert result.anonymous_session is True
        assert result.signing_required is False
        share_names = [s.name for s in result.shares]
        assert "tmp" in share_names


# ---------------------------------------------------------------------------
# T19 — smb_share_writable, smb_users_enumerated, smb_weak_password_policy
# ---------------------------------------------------------------------------

class TestSmbShareWritable:
    """T19-a : writable share findings."""

    def test_writable_share_anonymous_is_high_probable(self):
        """READ_WRITE + anonymous session → HIGH / PROBABLE."""
        raw = json.dumps({
            "anonymous_session": True,
            "shares": [{"name": "tmp", "accessible": True, "permissions": "READ_WRITE"}],
        })
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-t19")
        writable = [f for f in findings if f.target_service == "smb_share_writable"]
        assert len(writable) == 1
        assert writable[0].severity == Severity.HIGH
        assert writable[0].confidence == Confidence.PROBABLE

    def test_writable_share_authenticated_is_medium_probable(self):
        """READ_WRITE + non-anonymous session → MEDIUM / PROBABLE."""
        raw = json.dumps({
            "anonymous_session": False,
            "shares": [{"name": "shared", "accessible": True, "permissions": "READ_WRITE"}],
        })
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-t19")
        writable = [f for f in findings if f.target_service == "smb_share_writable"]
        assert len(writable) == 1
        assert writable[0].severity == Severity.MEDIUM
        assert writable[0].confidence == Confidence.PROBABLE

    def test_readonly_share_produces_no_writable_finding(self):
        """READ permission only → no smb_share_writable finding."""
        raw = json.dumps({
            "anonymous_session": True,
            "shares": [{"name": "Public", "accessible": True, "permissions": "READ"}],
        })
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-t19")
        assert not any(f.target_service == "smb_share_writable" for f in findings)

    def test_share_without_permissions_field_produces_no_writable_finding(self):
        """No permissions field → cannot infer writability → no finding."""
        raw = json.dumps({
            "anonymous_session": True,
            "shares": [{"name": "tmp", "accessible": True}],
        })
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-t19")
        assert not any(f.target_service == "smb_share_writable" for f in findings)

    def test_multiple_writable_shares_produce_one_finding_each(self):
        """Two writable shares → two smb_share_writable findings."""
        raw = json.dumps({
            "anonymous_session": True,
            "shares": [
                {"name": "tmp", "accessible": True, "permissions": "READ_WRITE"},
                {"name": "data", "accessible": True, "permissions": "WRITE"},
            ],
        })
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-t19")
        writable = [f for f in findings if f.target_service == "smb_share_writable"]
        assert len(writable) == 2

    def test_writable_evidence_contains_share_name(self):
        """evidence.raw must include the share name for traceability."""
        raw = json.dumps({
            "anonymous_session": True,
            "shares": [{"name": "tmp", "accessible": True, "permissions": "READ_WRITE"}],
        })
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-t19")
        writable = [f for f in findings if f.target_service == "smb_share_writable"]
        assert "tmp" in writable[0].evidence.raw

    def test_writable_risk_score_is_none(self):
        raw = json.dumps({
            "anonymous_session": True,
            "shares": [{"name": "tmp", "accessible": True, "permissions": "WRITE"}],
        })
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-t19")
        writable = [f for f in findings if f.target_service == "smb_share_writable"]
        assert writable[0].risk_score is None

    def test_writable_does_not_interfere_with_existing_share_findings(self):
        """ADMIN$ and tmp both present → both classified independently."""
        raw = json.dumps({
            "anonymous_session": True,
            "shares": [
                {"name": "ADMIN$", "accessible": False},
                {"name": "tmp", "accessible": True, "permissions": "READ_WRITE"},
            ],
        })
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-t19")
        services = {f.target_service for f in findings}
        assert "ADMIN$" in services
        assert "smb_share_writable" in services


class TestSmbUsersEnumerated:
    """T19-a : users enumerated finding."""

    def test_users_present_creates_one_finding(self):
        """Users list non-empty → exactly 1 smb_users_enumerated finding."""
        raw = json.dumps({"users": ["Administrator", "Guest", "svcBackup"]})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-t19")
        users_f = [f for f in findings if f.target_service == "smb_users_enumerated"]
        assert len(users_f) == 1

    def test_users_finding_is_info_confirmed(self):
        raw = json.dumps({"users": ["Administrator"]})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-t19")
        f = next(f for f in findings if f.target_service == "smb_users_enumerated")
        assert f.severity == Severity.INFO
        assert f.confidence == Confidence.CONFIRMED

    def test_users_evidence_contains_user_list(self):
        raw = json.dumps({"users": ["Administrator", "Guest"]})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-t19")
        f = next(f for f in findings if f.target_service == "smb_users_enumerated")
        assert "Administrator" in f.evidence.raw

    def test_no_users_produces_no_finding(self):
        raw = json.dumps({"users": []})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-t19")
        assert not any(f.target_service == "smb_users_enumerated" for f in findings)

    def test_absent_users_key_produces_no_finding(self):
        raw = json.dumps({"hostname": "server"})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-t19")
        assert not any(f.target_service == "smb_users_enumerated" for f in findings)

    def test_users_risk_score_is_none(self):
        raw = json.dumps({"users": ["Administrator"]})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-t19")
        f = next(f for f in findings if f.target_service == "smb_users_enumerated")
        assert f.risk_score is None


class TestSmbWeakPasswordPolicy:
    """T19-a : password policy findings."""

    def test_min_len_below_8_is_medium_confirmed(self):
        raw = json.dumps({"passwordpolicy": {"minpasswdlength": 6, "lockoutthreshold": 5}})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-t19")
        policy_f = [f for f in findings if f.target_service == "smb_weak_password_policy"]
        assert len(policy_f) == 1
        assert policy_f[0].severity == Severity.MEDIUM
        assert policy_f[0].confidence == Confidence.CONFIRMED

    def test_no_lockout_is_high_confirmed(self):
        raw = json.dumps({"passwordpolicy": {"minpasswdlength": 10, "lockoutthreshold": 0}})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-t19")
        policy_f = [f for f in findings if f.target_service == "smb_weak_password_policy"]
        assert len(policy_f) == 1
        assert policy_f[0].severity == Severity.HIGH
        assert policy_f[0].confidence == Confidence.CONFIRMED

    def test_both_conditions_produces_one_high_finding(self):
        """Both min_len < 8 AND lockout = 0 → one finding HIGH (max severity)."""
        raw = json.dumps({"passwordpolicy": {"minpasswdlength": 4, "lockoutthreshold": 0}})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-t19")
        policy_f = [f for f in findings if f.target_service == "smb_weak_password_policy"]
        assert len(policy_f) == 1
        assert policy_f[0].severity == Severity.HIGH

    def test_strong_policy_produces_no_finding(self):
        """min_len=12, lockout=5 → no weakness finding."""
        raw = json.dumps({"passwordpolicy": {"minpasswdlength": 12, "lockoutthreshold": 5}})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-t19")
        assert not any(f.target_service == "smb_weak_password_policy" for f in findings)

    def test_exactly_8_chars_produces_no_finding(self):
        """min_len=8 is the threshold — not weak."""
        raw = json.dumps({"passwordpolicy": {"minpasswdlength": 8, "lockoutthreshold": 3}})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-t19")
        assert not any(f.target_service == "smb_weak_password_policy" for f in findings)

    def test_absent_policy_produces_no_finding(self):
        raw = json.dumps({"hostname": "server"})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-t19")
        assert not any(f.target_service == "smb_weak_password_policy" for f in findings)

    def test_policy_evidence_contains_values(self):
        raw = json.dumps({"passwordpolicy": {"minpasswdlength": 6, "lockoutthreshold": 0}})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-t19")
        f = next(f for f in findings if f.target_service == "smb_weak_password_policy")
        assert "min_password_length" in f.evidence.raw
        assert "lockout_threshold" in f.evidence.raw

    def test_policy_risk_score_is_none(self):
        raw = json.dumps({"passwordpolicy": {"minpasswdlength": 6, "lockoutthreshold": 0}})
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-t19")
        f = next(f for f in findings if f.target_service == "smb_weak_password_policy")
        assert f.risk_score is None


class TestPasswordPolicyExtraction:
    """T19-b : _extract_password_policy helper and SmbEnumerationResult.password_policy."""

    def test_policy_extracted_from_json_output(self):
        raw = json.dumps({
            "passwordpolicy": {"minpasswdlength": 7, "lockoutthreshold": 0}
        })
        result = normalize_smb_output(raw, "10.0.0.5")
        assert result.password_policy is not None
        assert result.password_policy["min_password_length"] == 7
        assert result.password_policy["lockout_threshold"] == 0

    def test_absent_policy_is_none(self):
        raw = json.dumps({"hostname": "server"})
        result = normalize_smb_output(raw, "10.0.0.5")
        assert result.password_policy is None

    def test_text_output_policy_is_none(self):
        """Text fallback never extracts password_policy."""
        result = normalize_smb_output("Domain Name: WORKGROUP", "10.0.0.5")
        assert result.password_policy is None


class TestVulnerabilitiesJsonT19:
    """T19-c : KB rules for new findings are present and complete."""

    def test_smb_share_writable_rule_present(self):
        from knowledge.knowledge_base import _load_vulnerabilities
        rules = _load_vulnerabilities()
        assert "smb_share_writable" in rules

    def test_smb_users_enumerated_rule_present(self):
        from knowledge.knowledge_base import _load_vulnerabilities
        rules = _load_vulnerabilities()
        assert "smb_users_enumerated" in rules

    def test_smb_weak_password_policy_rule_present(self):
        from knowledge.knowledge_base import _load_vulnerabilities
        rules = _load_vulnerabilities()
        assert "smb_weak_password_policy" in rules

    def test_all_new_rules_have_what_attack_defense(self):
        from knowledge.knowledge_base import _load_vulnerabilities
        rules = _load_vulnerabilities()
        for rule_id in ["smb_share_writable", "smb_users_enumerated", "smb_weak_password_policy"]:
            r = rules[rule_id]
            assert r.get("what"), f"{rule_id} missing 'what'"
            assert r.get("attack"), f"{rule_id} missing 'attack'"
            assert r.get("defense"), f"{rule_id} missing 'defense'"


# ---------------------------------------------------------------------------
# SMB-01 — échec d'énumération explicite, export JSON privé, preuves analysées
# ---------------------------------------------------------------------------

IP = "192.168.1.26"


def _fake_enum_run(*, rc=0, stdout="", stderr="", export=None, record=None):
    """Fake subprocess.run. Writes <base>.json when `export` is given, as -oJ does."""
    def _run(command, **kwargs):
        base = command[command.index("-oJ") + 1]
        export_dir = os.path.dirname(base)
        if record is not None:
            record["command"] = list(command)
            record["kwargs"] = dict(kwargs)
            record["export_dir"] = export_dir
            record["export_dir_mode"] = stat.S_IMODE(os.stat(export_dir).st_mode)
        if export is not None:
            with open(base + ".json", "w", encoding="utf-8") as handle:
                handle.write(export)
        return subprocess.CompletedProcess(command, rc, stdout=stdout, stderr=stderr)
    return _run


def _run_entry(fake_run, target=IP):
    """Call the public entry point with the tool present and the user confirming."""
    with patch("detect.smb_enum._resolve_tool_path", return_value="/usr/bin/enum4linux-ng"), \
         patch("detect.smb_enum.typer.confirm", return_value=True), \
         patch("detect.smb_enum.subprocess.run", side_effect=fake_run):
        return smb_enum(target, "session-smb01")


@pytest.fixture
def shown():
    """Capture every message sent to display()."""
    with patch("detect.smb_enum.display") as mock_display:
        yield mock_display


def _messages(mock_display):
    return [str(call.args[0]) for call in mock_display.call_args_list]


class TestRunContract:
    def test_command_uses_json_export_and_no_json_flag(self, shown):
        record = {}
        with patch("detect.smb_enum.subprocess.run",
                   side_effect=_fake_enum_run(export="{}", record=record)):
            _run_enum4linux_ng(IP)
        command = record["command"]
        assert "-oJ" in command
        assert "--json" not in command
        assert "-A" in command
        assert command[-1] == IP
        assert record["kwargs"]["check"] is False
        assert record["kwargs"]["capture_output"] is True
        assert record["kwargs"]["timeout"] == ENUM4LINUX_TIMEOUT_SECONDS

    def test_export_dir_is_private_during_run_and_removed_after(self, shown):
        record = {}
        with patch("detect.smb_enum.subprocess.run",
                   side_effect=_fake_enum_run(export="{}", record=record)):
            _run_enum4linux_ng(IP)
        assert record["export_dir_mode"] == 0o700
        assert not os.path.exists(record["export_dir"])

    def test_export_dir_removed_after_failure(self, shown):
        record = {}
        with patch("detect.smb_enum.subprocess.run",
                   side_effect=_fake_enum_run(rc=2, stderr="usage", record=record)):
            assert _run_enum4linux_ng(IP) is None
        assert not os.path.exists(record["export_dir"])

    def test_nominal_export_is_read_and_analysed(self, shown):
        export = json.dumps({"shares": [{"name": "Public", "accessible": True}], "domain": "LAB"})
        findings = _run_entry(_fake_enum_run(export=export))
        assert {f.target_service for f in findings} == {"Public", "LAB"}
        assert not any("FAILED" in m for m in _messages(shown))

    def test_nonzero_rc_is_failure_even_with_valid_export(self, shown):
        export = json.dumps({"shares": [{"name": "ADMIN$"}]})
        findings = _run_entry(_fake_enum_run(rc=2, stderr="usage: enum4linux-ng", export=export))
        assert findings == []
        messages = _messages(shown)
        assert any("FAILED" in m and "exit code 2" in m for m in messages)
        assert not any("no shares" in m for m in messages)

    def test_nonzero_rc_never_falls_back_to_text(self, shown):
        findings = _run_entry(_fake_enum_run(rc=1, stdout=ENUM4LINUX_ADMIN_ONLY))
        assert findings == []

    def test_rc0_empty_stdout_and_no_export_is_failure(self, shown):
        findings = _run_entry(_fake_enum_run(rc=0, stdout="  \n"))
        assert findings == []
        assert any("FAILED" in m for m in _messages(shown))

    def test_rc0_without_export_uses_text_fallback_and_reads_account(self, shown):
        findings = _run_entry(_fake_enum_run(rc=0, stdout="index: 0x1 Account: alice\n"))
        users = [f for f in findings if f.target_service == "smb_users_enumerated"]
        assert len(users) == 1
        assert json.loads(users[0].evidence.raw)["users"] == ["alice"]

    def test_rc0_malformed_export_is_failure_without_fallback(self, shown):
        findings = _run_entry(_fake_enum_run(rc=0, stdout=ENUM4LINUX_ADMIN_ONLY, export="{not json"))
        assert findings == []
        assert any("FAILED" in m and "malformed" in m for m in _messages(shown))

    def test_rc0_export_that_is_not_an_object_is_failure(self, shown):
        findings = _run_entry(_fake_enum_run(rc=0, stdout=ENUM4LINUX_ADMIN_ONLY, export="[1, 2]"))
        assert findings == []
        assert any("FAILED" in m for m in _messages(shown))

    def test_timeout_is_explicit_failure(self, shown):
        def boom(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd="enum4linux-ng", timeout=120)
        assert _run_entry(boom) == []
        assert any("FAILED" in m and "timed out" in m for m in _messages(shown))

    def test_oserror_is_explicit_failure(self, shown):
        def boom(*args, **kwargs):
            raise OSError("denied")
        assert _run_entry(boom) == []
        assert any("FAILED" in m and "OSError" in m for m in _messages(shown))

    def test_missing_binary_is_explicit_failure(self, shown):
        def boom(*args, **kwargs):
            raise FileNotFoundError("enum4linux-ng")
        assert _run_entry(boom) == []
        assert any("FAILED" in m and "not found" in m for m in _messages(shown))

    def test_stderr_is_redacted_ansi_free_and_not_parsed(self, shown):
        stderr = "\x1b[31mERROR\x1b[0m login failed password: Hunter2-SECRET\n"
        findings = _run_entry(_fake_enum_run(rc=1, stderr=stderr))
        assert findings == []
        joined = "\n".join(_messages(shown))
        assert "Hunter2-SECRET" not in joined
        assert "\x1b" not in joined
        assert "[redacted]" in joined


class TestFailureVisibility:
    def test_successful_empty_analysis_keeps_no_shares_message(self, shown):
        findings = _run_entry(_fake_enum_run(export="{}"))
        assert findings == []
        messages = _messages(shown)
        assert any("no shares or domain info" in m for m in messages)
        assert not any("FAILED" in m for m in messages)

    def test_failure_message_is_distinct_from_empty_result(self, shown):
        _run_entry(_fake_enum_run(rc=2, stderr="usage"))
        messages = _messages(shown)
        assert any("FAILED" in m and "not an absence" in m for m in messages)
        assert not any("no shares or domain info" in m for m in messages)


class TestEvidenceContainsAnalysedFieldsOnly:
    """Q4: no full tool output, no secret, in Findings or evidence."""

    MARKERS = ("MARKER-PASSWORD", "MARKER-RAW", "MARKER-COMMENT", "Hunter2")

    def test_json_full_output_and_secrets_absent_from_evidence(self):
        document = {
            "anonymous_session": True,
            "shares": [
                {"name": "tmp", "accessible": True, "permissions": "READ_WRITE",
                 "comment": "MARKER-COMMENT"},
                {"name": "Public", "accessible": True, "permissions": "READ",
                 "comment": "MARKER-COMMENT"},
            ],
            "users": ["Administrator"],
            "passwordpolicy": {"minpasswdlength": 6, "lockoutthreshold": 0},
            "credentials": {"username": "alice", "password": "MARKER-PASSWORD"},
            "sessions": {"null_session": True, "password": "MARKER-PASSWORD"},
            "unrelated_blob": "MARKER-RAW Hunter2",
        }
        raw = json.dumps(document)
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-q4")
        assert findings
        for finding in findings:
            blob = " ".join([finding.evidence.raw, finding.evidence.command,
                             finding.target_service])
            for marker in self.MARKERS:
                assert marker not in blob
            assert raw not in finding.evidence.raw
            assert "smb_enum_" not in finding.evidence.command
            assert "/tmp" not in finding.evidence.command

    def test_text_full_output_absent_from_evidence(self):
        raw = (
            "MARKER-RAW-TEXT noise line\n"
            "Sharename       Type      Comment\n"
            "---------       ----      -------\n"
            "Public          Disk      MARKER-COMMENT\n"
            "Account: alice\n"
        )
        findings = _parse_enum4linux_output(raw, "10.0.0.5", "session-q4")
        share = next(f for f in findings if f.target_service == "Public")
        assert "MARKER" not in share.evidence.raw
        assert "noise" not in share.evidence.raw
        assert json.loads(share.evidence.raw) == {
            "share": "Public",
            "source": "enum4linux-ng share listing",
        }

    def test_admin_share_evidence_has_no_comment_and_no_raw_output(self):
        findings = _parse_enum4linux_output(ENUM4LINUX_ADMIN_ONLY, IP, "session-q4")
        admin = next(f for f in findings if f.target_service == "ADMIN$")
        assert "Remote Admin" not in admin.evidence.raw
        assert "Sharename" not in admin.evidence.raw


class TestAccountRegex:
    def test_account_with_space_is_extracted(self):
        assert normalize_smb_output("Account: alice", IP).users == ("alice",)

    def test_account_with_tab_is_extracted(self):
        assert normalize_smb_output("Account:\talice", IP).users == ("alice",)


# ---------------------------------------------------------------------------
# SMB-01 / CLI — run_smb_enum : échec (None) distinct du résultat vide ([])
# ---------------------------------------------------------------------------

def _run_checked(fake_run=None, *, confirm=True, resolve="/usr/bin/enum4linux-ng"):
    """Call run_smb_enum() and count the enum4linux-ng executions."""
    calls = []
    if fake_run is not None:
        inner = fake_run

        def counting_run(command, **kwargs):
            calls.append(list(command))
            return inner(command, **kwargs)
        run_patch = patch("detect.smb_enum.subprocess.run", side_effect=counting_run)
    else:
        run_patch = patch("detect.smb_enum.subprocess.run", side_effect=AssertionError("must not run"))
    with patch("detect.smb_enum._resolve_tool_path", return_value=resolve), \
         patch("detect.smb_enum.typer.confirm", return_value=confirm), \
         run_patch:
        from detect.smb_enum import run_smb_enum
        outcome = run_smb_enum(IP, "session-smb01")
    return outcome, calls


class TestRunSmbEnumOutcome:
    def test_success_with_findings_returns_list(self, shown):
        export = json.dumps({"shares": [{"name": "Public", "accessible": True}]})
        outcome, calls = _run_checked(_fake_enum_run(export=export))
        assert isinstance(outcome, list)
        assert [f.target_service for f in outcome] == ["Public"]
        assert len(calls) == 1

    def test_success_without_findings_returns_empty_list(self, shown):
        outcome, calls = _run_checked(_fake_enum_run(export="{}"))
        assert outcome == []
        assert len(calls) == 1
        assert any("no shares or domain info" in m for m in _messages(shown))

    def test_failure_returns_none(self, shown):
        outcome, calls = _run_checked(_fake_enum_run(rc=2, stderr="usage"))
        assert outcome is None
        assert len(calls) == 1
        assert any("FAILED" in m for m in _messages(shown))

    def test_tool_missing_returns_none_without_running(self, shown):
        outcome, calls = _run_checked(None, resolve=None)
        assert outcome is None
        assert calls == []
        assert any("not found" in m for m in _messages(shown))

    def test_user_cancel_returns_empty_list_without_running(self, shown):
        outcome, calls = _run_checked(None, confirm=False)
        assert outcome == []
        assert calls == []

    def test_smb_enum_wrapper_maps_failure_to_empty_list(self, shown):
        with patch("detect.smb_enum._resolve_tool_path", return_value="/usr/bin/enum4linux-ng"), \
             patch("detect.smb_enum.typer.confirm", return_value=True), \
             patch("detect.smb_enum.subprocess.run", side_effect=_fake_enum_run(rc=2)):
            assert smb_enum(IP, "session-smb01") == []
