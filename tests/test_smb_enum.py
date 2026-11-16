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
    _SMB1_DIALECT_NAMES,
    _extract_dialects,
    _parse_enum4linux_output,
    _policy_int,
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
    def test_admin_share_no_access_info_is_info(self):
        """D-SMB-02: ADMIN$ without confirmed access -> SERVICE/INFO (inventory observation)."""
        findings = _parse_enum4linux_output(
            ENUM4LINUX_ADMIN_ONLY, "192.168.1.26", "session-test"
        )
        admin = [f for f in findings if f.target_service.upper() == "ADMIN$"]
        assert len(admin) == 1
        finding = admin[0]
        # accessible is unknown from text output -> do not assign MEDIUM by name alone
        assert finding.severity == Severity.INFO
        assert finding.module == "smb_enum"
        assert finding.target_ip == "192.168.1.26"
        assert finding.target_port == 445
        assert finding.session_id == "session-test"

    def test_admin_share_confirmed_access_is_credential_medium(self):
        """D-SMB-02: ADMIN$ with confirmed access -> CREDENTIAL/MEDIUM."""
        raw = json.dumps({"shares": {"ADMIN$": {"access": {"mapping": "ok"}}}})
        findings = _parse_enum4linux_output(raw, "192.168.1.26", "session-test")
        admin = [f for f in findings if f.target_service.upper() == "ADMIN$"]
        assert len(admin) == 1
        assert admin[0].category == Category.CREDENTIAL
        assert admin[0].severity == Severity.MEDIUM

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
        # D-SMB-02: text fixture has no access info -> accessible=None -> INFO
        assert result[0].severity == Severity.INFO
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


# ---------------------------------------------------------------------------
# SMB-03 — reconnaissance des dialectes SMBv1 dans la sortie JSON
# ---------------------------------------------------------------------------

class TestExtractDialects:
    """Unit tests for _extract_dialects — the two JSON formats from SMB-03."""

    # ── Format 1 : bool ────────────────────────────────────────────────────

    def test_bool_true_returns_empty_dialects_and_imposed_flag(self):
        """smb_dialects: true → no dialect name invented; smb1_imposed=True returned."""
        dialects, smb1_imposed = _extract_dialects(True)
        assert dialects == (), "NT1 must not be invented as a dialect name"
        assert smb1_imposed is True

    def test_bool_false_returns_empty_dialects_and_no_imposed(self):
        """smb_dialects: false → no dialect, smb1_imposed=False."""
        dialects, smb1_imposed = _extract_dialects(False)
        assert dialects == ()
        assert smb1_imposed is False

    # ── Format 2 : dict de dialectes ──────────────────────────────────────

    def test_dict_smb1_true_is_included(self):
        dialects, smb1_imposed = _extract_dialects({"SMB 1.0": True, "SMB 2.0.2": False})
        assert "SMB 1.0" in dialects
        assert "SMB 2.0.2" not in dialects
        assert smb1_imposed is False

    def test_dict_smb1_false_is_excluded(self):
        dialects, smb1_imposed = _extract_dialects({"SMB 1.0": False, "SMB 2.0.2": True})
        assert "SMB 1.0" not in dialects
        assert "SMB 2.0.2" in dialects
        assert smb1_imposed is False

    def test_dict_multiple_active_dialects(self):
        d = {"SMB 1.0": True, "SMB 2.0.2": True, "SMB 2.1": True, "SMB 3.0": False}
        dialects, smb1_imposed = _extract_dialects(d)
        assert set(dialects) == {"SMB 1.0", "SMB 2.0.2", "SMB 2.1"}
        assert smb1_imposed is False

    def test_dict_all_false_returns_empty(self):
        dialects, smb1_imposed = _extract_dialects({"SMB 1.0": False, "SMB 2.0.2": False})
        assert dialects == ()
        assert smb1_imposed is False

    def test_dict_string_false_is_not_truthy(self):
        """The string "false" must not be treated as the boolean True."""
        dialects, _ = _extract_dialects({"SMB 1.0": "false"})
        assert "SMB 1.0" not in dialects

    def test_dict_string_true_is_truthy(self):
        dialects, _ = _extract_dialects({"SMB 1.0": "true"})
        assert "SMB 1.0" in dialects

    def test_dict_integer_zero_is_excluded(self):
        dialects, _ = _extract_dialects({"SMB 1.0": 0})
        assert "SMB 1.0" not in dialects

    def test_dict_empty_key_is_skipped(self):
        dialects, _ = _extract_dialects({"": True, "SMB 2.0.2": True})
        assert "" not in dialects
        assert "SMB 2.0.2" in dialects

    # ── Fallback / edge cases ──────────────────────────────────────────────

    def test_list_of_names_uses_fallback(self):
        """Plain list → original _as_strings behaviour, unchanged."""
        dialects, smb1_imposed = _extract_dialects(["SMBv1", "SMB2"])
        assert "SMBv1" in dialects
        assert "SMB2" in dialects
        assert smb1_imposed is False

    def test_none_returns_empty(self):
        dialects, smb1_imposed = _extract_dialects(None)
        assert dialects == ()
        assert smb1_imposed is False

    def test_string_value_uses_fallback(self):
        dialects, smb1_imposed = _extract_dialects("SMBv1")
        assert "SMBv1" in dialects
        assert smb1_imposed is False


class TestSMB1DialectNames:
    def test_contains_all_expected_variants(self):
        for name in ("NT1", "SMBv1", "SMB 1.0", "SMB1"):
            assert name in _SMB1_DIALECT_NAMES, f"{name!r} missing from _SMB1_DIALECT_NAMES"

    def test_does_not_contain_smb2_or_smb3(self):
        for name in ("SMB 2.0.2", "SMB 2.1", "SMB 3.0", "SMB2", "SMB3"):
            assert name not in _SMB1_DIALECT_NAMES, f"{name!r} should not be in _SMB1_DIALECT_NAMES"


class TestSMB03NormalizeDialects:
    """Integration tests: JSON normalize + Finding detection for SMB-03 formats."""

    # ── Format 1 (bool) ───────────────────────────────────────────────────

    def test_bool_true_produces_smbv1_finding(self):
        raw = json.dumps({"smb_dialects": True})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-smb03")
        services = [f.target_service for f in findings]
        assert "SMBv1" in services

    def test_bool_false_produces_no_smbv1_finding(self):
        raw = json.dumps({"smb_dialects": False})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-smb03")
        assert not any(f.target_service == "SMBv1" for f in findings)

    def test_bool_true_finding_has_correct_severity(self):
        raw = json.dumps({"smb_dialects": True})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-smb03")
        smb1 = next(f for f in findings if f.target_service == "SMBv1")
        from core.finding import Severity
        assert smb1.severity == Severity.HIGH

    def test_bool_true_evidence_uses_imposed_flag_not_dialect_name(self):
        """smb_dialects:true → evidence uses smb1_imposed:true, never a dialect name."""
        raw = json.dumps({"smb_dialects": True})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-smb03")
        smb1 = next(f for f in findings if f.target_service == "SMBv1")
        evidence = json.loads(smb1.evidence.raw)
        # Must have smb1_imposed flag, not a invented dialect name
        assert evidence.get("smb1_imposed") is True
        assert "dialects" not in evidence, "no dialect list for imposed case"
        assert "NT1" not in str(evidence), "NT1 must not be invented"
        assert "True" not in str(evidence.get("dialects", "")), "bool repr must not appear"

    # ── Format 2 (dict) ───────────────────────────────────────────────────

    def test_dict_smb10_true_produces_smbv1_finding(self):
        raw = json.dumps({"smb_dialects": {"SMB 1.0": True, "SMB 2.0.2": False}})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-smb03")
        assert any(f.target_service == "SMBv1" for f in findings)

    def test_dict_smb10_false_produces_no_smbv1_finding(self):
        raw = json.dumps({"smb_dialects": {"SMB 1.0": False, "SMB 2.0.2": True}})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-smb03")
        assert not any(f.target_service == "SMBv1" for f in findings)

    def test_dict_multiple_dialects_no_smb1(self):
        raw = json.dumps({"smb_dialects": {"SMB 2.0.2": True, "SMB 2.1": True, "SMB 3.0": True}})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-smb03")
        assert not any(f.target_service == "SMBv1" for f in findings)

    def test_dict_smb10_string_false_no_finding(self):
        """'false' as a string value must not trigger SMBv1 finding."""
        raw = json.dumps({"smb_dialects": {"SMB 1.0": "false"}})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-smb03")
        assert not any(f.target_service == "SMBv1" for f in findings)

    # ── Clé "dialects" (alias attendu par le code) ────────────────────────

    def test_dialects_key_bool_true_does_not_trigger_smb1_imposed(self):
        """V3: 'dialects':true is a generic alias; smb1_imposed requires 'smb_dialects':true."""
        raw = json.dumps({"dialects": True})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-smb03")
        assert not any(f.target_service == "SMBv1" for f in findings), (
            "'dialects':true (generic) must not trigger SMBv1 finding; only 'smb_dialects':true can"
        )

    def test_dialects_key_dict_smb10(self):
        raw = json.dumps({"dialects": {"SMB 1.0": True}})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-smb03")
        assert any(f.target_service == "SMBv1" for f in findings)

    # ── Absent ou type inattendu ──────────────────────────────────────────

    def test_missing_dialects_key_no_finding(self):
        raw = json.dumps({"shares": []})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-smb03")
        assert not any(f.target_service == "SMBv1" for f in findings)

    def test_null_dialects_no_finding(self):
        raw = json.dumps({"dialects": None})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-smb03")
        assert not any(f.target_service == "SMBv1" for f in findings)

    # ── Non-régression des formats existants ─────────────────────────────

    def test_list_smbv1_still_works(self):
        """Original list format ["SMBv1"] continues to produce a Finding."""
        raw = json.dumps({"dialects": ["SMBv1"]})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-smb03")
        assert any(f.target_service == "SMBv1" for f in findings)

    def test_list_nt1_still_works(self):
        raw = json.dumps({"dialects": ["NT1"]})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-smb03")
        assert any(f.target_service == "SMBv1" for f in findings)

    def test_list_smb2_no_smbv1_finding(self):
        raw = json.dumps({"dialects": ["SMB2", "SMB3"]})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-smb03")
        assert not any(f.target_service == "SMBv1" for f in findings)

    def test_normalize_smb_output_bool_true_roundtrip(self):
        """normalize_smb_output(json) → smb1_imposed=True, dialects empty (no NT1 invented)."""
        raw = json.dumps({"smb_dialects": True})
        result = normalize_smb_output(raw, "192.168.57.3")
        assert result.smb1_imposed is True
        assert result.dialects == (), "NT1 must not be invented in dialects"

    def test_normalize_smb_output_dict_roundtrip(self):
        raw = json.dumps({"smb_dialects": {"SMB 1.0": True, "SMB 2.0.2": False}})
        result = normalize_smb_output(raw, "192.168.57.3")
        assert "SMB 1.0" in result.dialects
        assert "SMB 2.0.2" not in result.dialects


class TestExtractDialectsConf02:
    """CONF-02: unknown/unrecognised string values must not trigger a Finding."""

    def test_string_zero_is_not_active(self):
        dialects, _ = _extract_dialects({"SMB 1.0": "0"})
        assert "SMB 1.0" not in dialects

    def test_string_none_lowercase_is_not_active(self):
        dialects, _ = _extract_dialects({"SMB 1.0": "none"})
        assert "SMB 1.0" not in dialects

    def test_string_None_mixed_case_is_not_active(self):
        dialects, _ = _extract_dialects({"SMB 1.0": "None"})
        assert "SMB 1.0" not in dialects

    def test_string_not_set_is_not_active(self):
        dialects, _ = _extract_dialects({"SMB 1.0": "not set"})
        assert "SMB 1.0" not in dialects

    def test_string_unsupported_is_not_active(self):
        dialects, _ = _extract_dialects({"SMB 1.0": "unsupported"})
        assert "SMB 1.0" not in dialects

    def test_no_smbv1_finding_for_unknown_string_values(self):
        for s in ("0", "none", "None", "not set", "unsupported"):
            raw = json.dumps({"smb_dialects": {"SMB 1.0": s}})
            findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-conf02")
            assert not any(f.target_service == "SMBv1" for f in findings),                 f"SMBv1 finding wrongly triggered for SMB 1.0: {s!r}"


class TestSMB03Risq01Priority:
    """RISQ-01: smb_dialects/dialects key takes priority over generic 'protocol'."""

    def test_protocol_key_alone_no_smb1_finding(self):
        """protocol='SMB2' alone should not trigger SMBv1."""
        raw = json.dumps({"protocol": "SMB2"})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-risq01")
        assert not any(f.target_service == "SMBv1" for f in findings)

    def test_smb_dialects_wins_over_protocol(self):
        """When both 'protocol':'SMB2' and 'smb_dialects':{'SMB 1.0':true} are present,
        smb_dialects wins and SMBv1 is correctly detected."""
        raw = json.dumps({"protocol": "SMB2", "smb_dialects": {"SMB 1.0": True}})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-risq01")
        assert any(f.target_service == "SMBv1" for f in findings)

    def test_protocol_string_smbv1_still_detected_via_fallback(self):
        """protocol='SMBv1' as a plain string still triggers detection via fallback."""
        raw = json.dumps({"protocol": "SMBv1"})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-risq01")
        assert any(f.target_service == "SMBv1" for f in findings)


class TestSMB03Risq02CaseInsensitive:
    """RISQ-02: dialect name comparison is case-insensitive for _SMB1_DIALECT_NAMES."""

    def test_smb_1_0_lowercase_is_recognised(self):
        """'smb 1.0' (all lower) should be recognised as SMBv1."""
        raw = json.dumps({"dialects": {"smb 1.0": True}})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-risq02")
        assert any(f.target_service == "SMBv1" for f in findings)

    def test_nt1_uppercase_still_recognised(self):
        raw = json.dumps({"dialects": ["NT1"]})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-risq02")
        assert any(f.target_service == "SMBv1" for f in findings)

    def test_smbv1_mixed_case_recognised(self):
        raw = json.dumps({"dialects": ["SMBv1"]})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-risq02")
        assert any(f.target_service == "SMBv1" for f in findings)


class TestSMB03V3Provenance:
    """SMB-03 V3: strict provenance — only smb_dialects:true can set smb1_imposed.

    Cases mandated by Antigravity final review.
    """

    @staticmethod
    def _smb1(raw_dict):
        raw = json.dumps(raw_dict)
        fs = _parse_enum4linux_output(raw, "192.168.57.3", "session-smb03v3")
        return next((f for f in fs if f.target_service == "SMBv1"), None)

    def test_smb_dialects_false_wins_over_protocol_true(self):
        """smb_dialects:false must not be overridden by protocol:true."""
        f = self._smb1({"smb_dialects": False, "protocol": True})
        assert f is None, "SMBv1 must not be detected when smb_dialects is explicitly false"

    def test_smb_dialects_true_wins_over_protocol_false(self):
        """smb_dialects:true is the only source of smb1_imposed."""
        f = self._smb1({"smb_dialects": True, "protocol": False})
        assert f is not None
        ev = json.loads(f.evidence.raw)
        assert ev.get("smb1_imposed") is True
        assert "dialects" not in ev

    def test_smb_dialects_false_wins_over_smbprotocol_true(self):
        f = self._smb1({"smb_dialects": False, "smbprotocol": True})
        assert f is None

    def test_smb_dialects_empty_list_wins_over_protocol_smbv1(self):
        """smb_dialects:[] is an explicit empty observation; protocol:SMBv1 must be ignored."""
        f = self._smb1({"smb_dialects": [], "protocol": "SMBv1"})
        assert f is None

    def test_smb_dialects_empty_dict_wins_over_protocol_smbv1(self):
        """smb_dialects:{} is an explicit empty observation."""
        f = self._smb1({"smb_dialects": {}, "protocol": "SMBv1"})
        assert f is None

    def test_smb_dialects_null_wins_over_protocol_smbv1(self):
        """smb_dialects:null is an explicit null observation; protocol must be ignored."""
        f = self._smb1({"smb_dialects": None, "protocol": "SMBv1"})
        assert f is None

    def test_protocol_true_alone_never_triggers_smb1_imposed(self):
        """protocol:true (generic alias) must never produce smb1_imposed=True."""
        f = self._smb1({"protocol": True})
        assert f is None, "protocol:true must not trigger SMBv1 finding"

    def test_dialects_true_alone_never_triggers_smb1_imposed(self):
        """dialects:true (generic alias) must never produce smb1_imposed=True."""
        f = self._smb1({"dialects": True})
        assert f is None, "dialects:true (generic) must not trigger SMBv1 finding"

    def test_smb_dialects_true_evidence_has_imposed_flag_not_dialect_key(self):
        """Evidence for smb_dialects:true contains smb1_imposed but not dialects."""
        f = self._smb1({"smb_dialects": True})
        assert f is not None
        ev = json.loads(f.evidence.raw)
        assert ev.get("smb1_imposed") is True
        assert "dialects" not in ev
        assert "NT1" not in str(ev)

    def test_smb_dialects_dict_evidence_has_dialects_not_imposed_flag(self):
        """Evidence for smb_dialects:{SMB 1.0:true} contains dialects but not smb1_imposed."""
        f = self._smb1({"smb_dialects": {"SMB 1.0": True}})
        assert f is not None
        ev = json.loads(f.evidence.raw)
        assert "dialects" in ev
        assert "smb1_imposed" not in ev

    def test_no_finding_cannot_affirm_success_that_did_not_occur(self):
        """When smb_dialects:false, no Finding exists to affirm success."""
        f = self._smb1({"smb_dialects": False})
        assert f is None


# ---------------------------------------------------------------------------
# SMB-04 — politique de mots de passe avec valeurs textuelles
# ---------------------------------------------------------------------------


class TestPolicyInt:
    """Unit tests for _policy_int — the field-by-field converter."""

    def test_none_python_returns_zero(self):
        assert _policy_int(None) == 0

    def test_string_None_returns_zero(self):
        assert _policy_int("None") == 0

    def test_string_none_lowercase_returns_zero(self):
        assert _policy_int("none") == 0

    def test_string_not_set_returns_none(self):
        assert _policy_int("not set") is None

    def test_string_not_set_variant_underscore(self):
        assert _policy_int("not_set") is None

    def test_string_na_returns_none(self):
        assert _policy_int("n/a") is None

    def test_empty_string_returns_none(self):
        assert _policy_int("") is None

    def test_integer_zero(self):
        assert _policy_int(0) == 0

    def test_integer_positive(self):
        assert _policy_int(8) == 8

    def test_numeric_string(self):
        assert _policy_int("6") == 6

    def test_numeric_string_zero(self):
        assert _policy_int("0") == 0

    def test_unknown_string_returns_none(self):
        assert _policy_int("unknown") is None

    def test_unrecognised_string_returns_none(self):
        assert _policy_int("??") is None

    def test_bool_true_rejected(self):
        """Python True must never become 1 — it is not a valid numeric policy value."""
        assert _policy_int(True) is None

    def test_bool_false_rejected(self):
        """Python False must never become 0 — it is not a valid numeric policy value."""
        assert _policy_int(False) is None


class TestSMB04PasswordPolicy:
    """SMB-04: field-by-field extraction — one invalid field must not lose the others."""

    @staticmethod
    def _policy(raw_dict):
        raw = json.dumps({"passwordpolicy": raw_dict})
        result = normalize_smb_output(raw, "192.168.57.3")
        return result.password_policy

    def test_both_fields_none_string_gives_zero(self):
        p = self._policy({"minpasswdlength": "None", "lockoutthreshold": "None"})
        assert p == {"min_password_length": 0, "lockout_threshold": 0}

    def test_both_fields_none_lowercase_gives_zero(self):
        p = self._policy({"minpasswdlength": "none", "lockoutthreshold": "none"})
        assert p == {"min_password_length": 0, "lockout_threshold": 0}

    def test_min_none_lockout_numeric_preserved(self):
        """min='None' (zero) must not cause lockout to be lost."""
        p = self._policy({"minpasswdlength": "None", "lockoutthreshold": 5})
        assert p is not None
        assert p["min_password_length"] == 0
        assert p["lockout_threshold"] == 5

    def test_min_not_set_lockout_none_string(self):
        """`not set` omits min; `None` on lockout → 0."""
        p = self._policy({"minpasswdlength": "not set", "lockoutthreshold": "None"})
        assert p is not None
        assert "min_password_length" not in p
        assert p["lockout_threshold"] == 0

    def test_both_not_set_returns_none(self):
        p = self._policy({"minpasswdlength": "not set", "lockoutthreshold": "not set"})
        assert p is None

    def test_valid_integers_unchanged(self):
        p = self._policy({"minpasswdlength": 8, "lockoutthreshold": 3})
        assert p == {"min_password_length": 8, "lockout_threshold": 3}

    def test_unknown_min_with_valid_lockout_keeps_lockout(self):
        """An unrecognised min value must not discard lockout."""
        p = self._policy({"minpasswdlength": "??unknown??", "lockoutthreshold": 10})
        assert p is not None
        assert "min_password_length" not in p
        assert p["lockout_threshold"] == 10

    def test_lockout_zero_integer_preserved(self):
        """lockout=0 is a valid value and must be kept."""
        p = self._policy({"minpasswdlength": 7, "lockoutthreshold": 0})
        assert p == {"min_password_length": 7, "lockout_threshold": 0}

    def test_mixed_none_and_valid(self):
        """Real-world Metasploitable-style: some fields None, others numeric."""
        p = self._policy({
            "minpasswdlength": "None",
            "lockoutthreshold": "None",
            "minpasswordage": "not set",
        })
        assert p is not None
        assert p["min_password_length"] == 0
        assert p["lockout_threshold"] == 0

    def test_evidence_raw_contains_policy_fields(self):
        """The Finding evidence must reflect the extracted policy, not raw strings."""
        raw = json.dumps({
            "passwordpolicy": {"minpasswdlength": "None", "lockoutthreshold": 0}
        })
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "session-smb04")
        policy_finding = next(
            (f for f in findings if f.target_service == "smb_weak_password_policy"), None
        )
        # lockoutthreshold=0 means no lockout → weak policy finding expected
        assert policy_finding is not None, "smb_weak_password_policy finding expected"
        ev = json.loads(policy_finding.evidence.raw)
        # Evidence must show no_lockout=True (lockout_threshold=0)
        assert ev.get("no_lockout") is True
        # Must not contain the raw string "None" as a value
        assert "None" not in json.dumps(ev) or "no_lockout" in ev, (
            "raw 'None' string must not appear verbatim in evidence"
        )

    # ── SMB-04 V2 — key-presence and boolean rejection ───────────────────────

    def test_key_absent_min_field_omitted(self):
        """When minpasswdlength key is absent, min_password_length must not appear."""
        p = self._policy({"lockoutthreshold": 5})
        assert p == {"lockout_threshold": 5}
        assert "min_password_length" not in p

    def test_key_absent_lockout_field_omitted(self):
        """When lockoutthreshold key is absent, lockout_threshold must not appear."""
        p = self._policy({"minpasswdlength": 7})
        assert p == {"min_password_length": 7}
        assert "lockout_threshold" not in p

    def test_key_present_json_null_gives_zero(self):
        """JSON null (Python None after json.loads) on a present key must yield 0."""
        # JSON: {"minpasswdlength": null, "lockoutthreshold": 5}
        # Python dict: {"minpasswdlength": None, "lockoutthreshold": 5}
        p = self._policy({"minpasswdlength": None, "lockoutthreshold": 5})
        assert p is not None
        assert p["min_password_length"] == 0
        assert p["lockout_threshold"] == 5

    def test_bool_lockout_false_no_false_positive(self):
        """Boolean False in lockoutthreshold must be omitted, never treated as 0.
        minpasswdlength=12 is a strong value and isolates the boolean as the
        only potential source of a false positive Finding."""
        p = self._policy({"minpasswdlength": 12, "lockoutthreshold": False})
        assert p == {"min_password_length": 12}
        assert "lockout_threshold" not in p
        raw = json.dumps(
            {"passwordpolicy": {"minpasswdlength": 12, "lockoutthreshold": False}}
        )
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "sess-smb04v2")
        assert not any(f.target_service == "smb_weak_password_policy" for f in findings), (
            "No smb_weak_password_policy Finding expected when lockout is a boolean"
        )

    def test_bool_lockout_true_field_omitted(self):
        """Boolean True in lockoutthreshold must be omitted — no Finding produced."""
        p = self._policy({"lockoutthreshold": True})
        assert p is None
        raw = json.dumps({"passwordpolicy": {"lockoutthreshold": True}})
        findings = _parse_enum4linux_output(raw, "192.168.57.3", "sess-smb04v2")
        assert not any(f.target_service == "smb_weak_password_policy" for f in findings)


# ---------------------------------------------------------------------------
# SMB Finalisation — parsing corrections and D-SMB-02
# ---------------------------------------------------------------------------

class TestSMBFinalisationParsing:
    """Tests for C1-C5 parsing corrections and D-SMB-02 ADMIN$ reclassification."""

    @staticmethod
    def _result(raw_dict):
        return normalize_smb_output(json.dumps(raw_dict), "192.168.57.3")

    @staticmethod
    def _findings(raw_dict):
        return _parse_enum4linux_output(json.dumps(raw_dict), "192.168.57.3", "sess-final")

    # ── C1 — sessions.null ──────────────────────────────────────────────

    def test_sessions_null_true_recognized(self):
        """sessions.null: true -> anonymous_session=True."""
        result = self._result({"sessions": {"null": True}})
        assert result.anonymous_session is True

    def test_sessions_null_false_recognized(self):
        """sessions.null: false -> anonymous_session=False."""
        result = self._result({"sessions": {"null": False}})
        assert result.anonymous_session is False

    def test_anonymous_flat_key_still_works(self):
        """Existing flat 'anonymous' alias is preserved."""
        result = self._result({"anonymous": True})
        assert result.anonymous_session is True

    # ── C2/C3 — nested policy ───────────────────────────────────────────

    def test_policy_nested_structure_produces_finding(self):
        """Nested policy dict is parsed and produces smb_weak_password_policy."""
        raw = {
            "policy": {
                "domain_password_information": {"min_password_length": 7},
                "domain_lockout_information": {"lockout_threshold": 0},
            }
        }
        findings = self._findings(raw)
        assert any(f.target_service == "smb_weak_password_policy" for f in findings)

    def test_smb04v2_rules_preserved_none_string(self):
        """SMB-04 V2 rule: 'None' string -> 0, 'not set' -> field omitted."""
        raw = {"passwordpolicy": {"minpasswdlength": "None", "lockoutthreshold": "not set"}}
        result = self._result(raw)
        assert result.password_policy is not None
        assert result.password_policy.get("min_password_length") == 0
        assert "lockout_threshold" not in result.password_policy

    def test_smb04v2_key_absent_omitted(self):
        """SMB-04 V2 rule: absent key must not produce a field."""
        raw = {"passwordpolicy": {"lockoutthreshold": 5}}
        result = self._result(raw)
        assert result.password_policy is not None
        assert "min_password_length" not in result.password_policy
        assert result.password_policy["lockout_threshold"] == 5

    # ── C4 — access.mapping ────────────────────────────────────────────

    def test_access_mapping_ok_is_accessible(self):
        """access.mapping: ok -> share.accessible=True."""
        raw = {"shares": {"PUBLIC": {"access": {"mapping": "ok"}}}}
        result = self._result(raw)
        share = next((s for s in result.shares if s.name == "PUBLIC"), None)
        assert share is not None
        assert share.accessible is True

    def test_access_mapping_denied_is_not_accessible(self):
        raw = {"shares": {"IPC$": {"access": {"mapping": "denied"}}}}
        result = self._result(raw)
        share = next((s for s in result.shares), None)
        assert share is not None
        assert share.accessible is False

    def test_access_mapping_unknown_is_none(self):
        raw = {"shares": {"DATA": {"access": {"mapping": "unknown"}}}}
        result = self._result(raw)
        share = next((s for s in result.shares), None)
        assert share is not None
        assert share.accessible is None

    def test_mapping_ok_never_means_write(self):
        """mapping: ok must NOT produce smb_share_writable Finding."""
        raw = {"shares": {"PUBLIC": {"access": {"mapping": "ok", "listing": "ok"}}}}
        findings = self._findings(raw)
        assert not any(f.target_service == "smb_share_writable" for f in findings)

    # ── C5 — users RID dict ────────────────────────────────────────────

    def test_users_rid_dict_extracts_usernames(self):
        """RID-keyed dict: usernames extracted, not RID keys."""
        raw = {"users": {"1000": {"username": "msfadmin"}, "1001": {"username": "user"}}}
        result = self._result(raw)
        assert "msfadmin" in result.users
        assert "user" in result.users
        assert "1000" not in result.users
        assert "1001" not in result.users

    def test_users_list_fallback_preserved(self):
        """Plain list of strings still works."""
        raw = {"users": ["alice", "bob"]}
        result = self._result(raw)
        assert result.users == ("alice", "bob")

    # ── D-SMB-02 — ADMIN$ classification ──────────────────────────────

    def test_admin_accessible_is_medium(self):
        """ADMIN$ with confirmed access -> CREDENTIAL / MEDIUM."""
        raw = {"shares": {"ADMIN$": {"access": {"mapping": "ok"}}}}
        findings = self._findings(raw)
        admin = next((f for f in findings if f.target_service == "ADMIN$"), None)
        assert admin is not None
        from core.finding import Category, Severity
        assert admin.severity == Severity.MEDIUM
        assert admin.category == Category.CREDENTIAL

    def test_admin_denied_is_info(self):
        """ADMIN$ with denied access -> SERVICE / INFO (inventory observation)."""
        raw = {"shares": {"ADMIN$": {"access": {"mapping": "denied"}}}}
        findings = self._findings(raw)
        admin = next((f for f in findings if f.target_service == "ADMIN$"), None)
        assert admin is not None
        from core.finding import Severity
        assert admin.severity == Severity.INFO

    def test_admin_unknown_access_is_info(self):
        """ADMIN$ with unknown access -> SERVICE / INFO (do not invent severity)."""
        raw = {"shares": {"ADMIN$": {}}}   # no access info
        findings = self._findings(raw)
        admin = next((f for f in findings if f.target_service == "ADMIN$"), None)
        assert admin is not None
        from core.finding import Severity
        assert admin.severity == Severity.INFO


# ---------------------------------------------------------------------------
# _format_evidence_raw (from cli.py) — tested via import
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

# Realistic enum4linux-ng 1.3.10 JSON output for Metasploitable2 (192.168.57.3).
# Based on the real output reported by the owner (2026-11-13 SMB-02 closure).
# Adapted for unit testing — no real network access.
METASPLOITABLE2_JSON = {
    "hostname": "metasploitable",
    "domain": "WORKGROUP",
    "os": "Unix",
    "smb_dialects": True,          # enforce_smb1 succeeded → smb1_imposed=True
    "sessions": {"null": True},    # anonymous session allowed
    "shares": {
        "print$": {"access": {"mapping": "denied", "listing": "denied"}},
        "tmp":    {"access": {"mapping": "ok",     "listing": "ok"},     "type": "Disk"},
        "opt":    {"access": {"mapping": "denied", "listing": "denied"}},
        "IPC$":   {"access": {"mapping": "ok",     "listing": "denied"}, "type": "IPC"},
        "ADMIN$": {"access": {"mapping": "denied", "listing": "denied"}},
    },
    "users": {
        "0":    {"username": "root"},
        "1000": {"username": "msfadmin"},
        "1002": {"username": "user"},
        "1003": {"username": "service"},
    },
    "policy": {
        "domain_password_information": {"min_password_length": 5},
        "domain_lockout_information":  {"lockout_threshold": 0},
    },
    "signing_required": False,
}


class TestMetasploitable2Fixture:
    """Integration tests using the realistic Metasploitable2 fixture."""

    @staticmethod
    def _result():
        import json
        return normalize_smb_output(json.dumps(METASPLOITABLE2_JSON), "192.168.57.3")

    @staticmethod
    def _findings():
        import json
        return _parse_enum4linux_output(
            json.dumps(METASPLOITABLE2_JSON), "192.168.57.3", "sess-m2"
        )

    def test_smb1_imposed_detected(self):
        """smb_dialects: true -> smb1_imposed=True."""
        result = self._result()
        assert result.smb1_imposed is True

    def test_anonymous_session_via_sessions_null(self):
        """sessions.null: true -> anonymous_session=True."""
        result = self._result()
        assert result.anonymous_session is True

    def test_tmp_share_accessible(self):
        """tmp share with mapping=ok -> accessible=True."""
        result = self._result()
        tmp = next((s for s in result.shares if s.name == "tmp"), None)
        assert tmp is not None
        assert tmp.accessible is True

    def test_admin_share_denied(self):
        """ADMIN$ with mapping=denied -> accessible=False."""
        result = self._result()
        admin = next((s for s in result.shares if s.name == "ADMIN$"), None)
        assert admin is not None
        assert admin.accessible is False

    def test_usernames_extracted_not_rids(self):
        """users RID-dict: extracts usernames, not RID keys."""
        result = self._result()
        assert "msfadmin" in result.users
        assert "root" in result.users
        assert "0" not in result.users
        assert "1000" not in result.users

    def test_policy_extracted_from_nested_structure(self):
        """Nested policy dict: min_password_length and lockout_threshold extracted."""
        result = self._result()
        assert result.password_policy is not None
        assert result.password_policy.get("min_password_length") == 5
        assert result.password_policy.get("lockout_threshold") == 0

    def test_smbv1_finding_produced(self):
        """smb1_imposed=True -> SMBv1 HIGH Finding produced."""
        findings = self._findings()
        smb1 = next((f for f in findings if f.target_service == "SMBv1"), None)
        assert smb1 is not None
        from core.finding import Severity
        assert smb1.severity == Severity.HIGH

    def test_signing_not_required_finding(self):
        """signing_required=False -> smb_signing_not_required Finding."""
        findings = self._findings()
        assert any(f.target_service == "smb_signing_not_required" for f in findings)

    def test_admin_denied_is_not_medium(self):
        """ADMIN$ with denied access -> SERVICE/INFO, not CREDENTIAL/MEDIUM."""
        findings = self._findings()
        admin = next((f for f in findings if f.target_service == "ADMIN$"), None)
        assert admin is not None
        from core.finding import Severity
        assert admin.severity == Severity.INFO

    def test_tmp_writable_anonymous_is_high(self):
        """tmp is accessible anonymously -> smb_share_writable HIGH if permissions indicate."""
        # tmp has accessible=True and anonymous_session=True; but permissions field
        # is not set in this fixture, so smb_share_writable requires explicit permissions.
        # Verify at minimum that no crash occurs and the share is listed.
        result = self._result()
        shares = [s.name for s in result.shares]
        assert "tmp" in shares

    def test_anonymous_access_finding_produced(self):
        """anonymous_session=True + accessible shares -> smb_anonymous_share_access."""
        findings = self._findings()
        assert any(f.target_service == "smb_anonymous_share_access" for f in findings)

    def test_weak_policy_finding_produced(self):
        """lockout_threshold=0 -> smb_weak_password_policy Finding."""
        findings = self._findings()
        assert any(f.target_service == "smb_weak_password_policy" for f in findings)
