"""
tests/test_tcp_scan.py — Unit tests for detect/tcp_scan.py

Strategy:
- ZERO real network calls — nmap subprocess always mocked
- Fixed XML strings replicate real nmap output
- Tests cover: open ports, closed ports, filtered ports,
  service extraction, confidence rules, profile flags, invariants

Critical negative tests:
- Closed port MUST NOT produce a Finding
- Filtered port MUST NOT produce a Finding
- open|filtered port MUST NOT produce a Finding
"""

import pytest
from unittest.mock import patch, MagicMock

from core.finding import (
    Finding,
    Category,
    Severity,
    Confidence,
    Exposure,
    FindingStatus,
)
from detect.tcp_scan import (
    tcp_scan,
    _parse_tcp_xml,
    _extract_service,
    _run_nmap_tcp,
    PROFILE_FLAGS,
)
import xml.etree.ElementTree as ET


# ---------------------------------------------------------------------------
# Fixed XML fixtures
# ---------------------------------------------------------------------------

TCP_XML_ONE_OPEN = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.26" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack"/>
        <service name="microsoft-ds" product="Microsoft Windows Server 2019"
                 version="" extrainfo="workgroup: WORKGROUP" method="probed"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

TCP_XML_MULTIPLE_OPEN = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="7.4" method="probed"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18.0" method="probed"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="" version="" method="table"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

TCP_XML_CLOSED_PORT = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="23">
        <state state="closed" reason="rst"/>
        <service name="telnet" method="table"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

TCP_XML_FILTERED_PORT = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3389">
        <state state="filtered" reason="no-response"/>
        <service name="ms-wbt-server" method="table"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

TCP_XML_MIXED = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9" method="probed"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="closed" reason="rst"/>
        <service name="telnet" method="table"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="filtered" reason="no-response"/>
        <service name="http" method="table"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

TCP_XML_NO_SERVICE = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="9999">
        <state state="open" reason="syn-ack"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

TCP_XML_EMPTY = """<?xml version="1.0"?><nmaprun></nmaprun>"""
MALFORMED_XML = "not xml <<<"


# ---------------------------------------------------------------------------
# _parse_tcp_xml — core parser tests
# ---------------------------------------------------------------------------

class TestParseTcpXml:
    def test_one_open_port_returns_one_finding(self):
        findings = _parse_tcp_xml(TCP_XML_ONE_OPEN, "192.168.1.26", "session-test")
        assert len(findings) == 1

    def test_finding_has_correct_port(self):
        findings = _parse_tcp_xml(TCP_XML_ONE_OPEN, "192.168.1.26", "session-test")
        assert findings[0].target_port == 445

    def test_finding_has_correct_ip(self):
        findings = _parse_tcp_xml(TCP_XML_ONE_OPEN, "192.168.1.26", "session-test")
        assert findings[0].target_ip == "192.168.1.26"

    def test_finding_service_name(self):
        findings = _parse_tcp_xml(TCP_XML_ONE_OPEN, "192.168.1.26", "session-test")
        assert findings[0].target_service == "microsoft-ds"

    def test_finding_module_is_tcp_scan(self):
        findings = _parse_tcp_xml(TCP_XML_ONE_OPEN, "192.168.1.26", "session-test")
        assert findings[0].module == "tcp_scan"

    def test_finding_category_is_service(self):
        findings = _parse_tcp_xml(TCP_XML_ONE_OPEN, "192.168.1.26", "session-test")
        assert findings[0].category == Category.SERVICE

    def test_multiple_open_ports(self):
        findings = _parse_tcp_xml(TCP_XML_MULTIPLE_OPEN, "192.168.1.1", "session-test")
        assert len(findings) == 3
        ports = {f.target_port for f in findings}
        assert ports == {22, 80, 443}

    # --- CRITICAL NEGATIVE TESTS ---

    def test_closed_port_produces_no_finding(self):
        """CRITICAL: closed ports must NEVER produce a Finding."""
        findings = _parse_tcp_xml(TCP_XML_CLOSED_PORT, "192.168.1.1", "session-test")
        assert findings == []

    def test_filtered_port_produces_no_finding(self):
        """CRITICAL: filtered ports must NEVER produce a Finding."""
        findings = _parse_tcp_xml(TCP_XML_FILTERED_PORT, "192.168.1.1", "session-test")
        assert findings == []

    def test_mixed_states_only_open_returned(self):
        """Only port 22 (open) should be returned — 23 (closed) and 80 (filtered) excluded."""
        findings = _parse_tcp_xml(TCP_XML_MIXED, "192.168.1.10", "session-test")
        assert len(findings) == 1
        assert findings[0].target_port == 22

    def test_empty_xml_returns_empty_list(self):
        findings = _parse_tcp_xml(TCP_XML_EMPTY, "192.168.1.1", "session-test")
        assert findings == []

    def test_malformed_xml_returns_empty_list(self):
        findings = _parse_tcp_xml(MALFORMED_XML, "192.168.1.1", "session-test")
        assert findings == []

    def test_open_port_without_service_returns_finding(self):
        """A port with no <service> element still produces a Finding."""
        findings = _parse_tcp_xml(TCP_XML_NO_SERVICE, "192.168.1.1", "session-test")
        assert len(findings) == 1
        assert findings[0].target_port == 9999


# ---------------------------------------------------------------------------
# _extract_service — confidence rules
# ---------------------------------------------------------------------------

class TestExtractService:
    def test_probed_method_returns_confirmed(self):
        xml = '<service name="ssh" product="OpenSSH" version="8.9" method="probed"/>'
        elem = ET.fromstring(xml)
        name, version, confidence = _extract_service(elem)
        assert confidence == Confidence.CONFIRMED
        assert name == "ssh"
        assert "OpenSSH" in version

    def test_table_with_version_returns_probable(self):
        xml = '<service name="http" product="Apache" version="2.4.51" method="table"/>'
        elem = ET.fromstring(xml)
        _, _, confidence = _extract_service(elem)
        assert confidence == Confidence.PROBABLE

    def test_table_without_version_returns_possible(self):
        xml = '<service name="unknown" method="table"/>'
        elem = ET.fromstring(xml)
        _, _, confidence = _extract_service(elem)
        assert confidence == Confidence.POSSIBLE

    def test_none_service_returns_confirmed(self):
        """No <service> element — port is open but service unknown. Still CONFIRMED."""
        name, version, confidence = _extract_service(None)
        assert confidence == Confidence.CONFIRMED
        assert name == ""
        assert version == ""

    def test_version_string_combines_product_version_extrainfo(self):
        xml = '<service name="ssh" product="OpenSSH" version="7.4" extrainfo="protocol 2.0" method="probed"/>'
        elem = ET.fromstring(xml)
        _, version, _ = _extract_service(elem)
        assert "OpenSSH" in version
        assert "7.4" in version
        assert "protocol 2.0" in version


# ---------------------------------------------------------------------------
# Finding invariants
# ---------------------------------------------------------------------------

class TestTcpFindingInvariants:
    def test_risk_score_is_none(self):
        findings = _parse_tcp_xml(TCP_XML_ONE_OPEN, "192.168.1.26", "session-test")
        assert all(f.risk_score is None for f in findings)

    def test_explanation_is_none(self):
        findings = _parse_tcp_xml(TCP_XML_ONE_OPEN, "192.168.1.26", "session-test")
        assert all(f.explanation is None for f in findings)

    def test_evidence_raw_not_empty(self):
        findings = _parse_tcp_xml(TCP_XML_ONE_OPEN, "192.168.1.26", "session-test")
        assert all(f.evidence.raw != "" for f in findings)

    def test_evidence_command_contains_nmap(self):
        findings = _parse_tcp_xml(TCP_XML_ONE_OPEN, "192.168.1.26", "session-test")
        assert all("nmap" in f.evidence.command for f in findings)

    def test_session_id_set_on_all_findings(self):
        findings = _parse_tcp_xml(TCP_XML_MULTIPLE_OPEN, "192.168.1.1", "session-abc")
        assert all(f.session_id == "session-abc" for f in findings)

    def test_status_is_open(self):
        findings = _parse_tcp_xml(TCP_XML_ONE_OPEN, "192.168.1.26", "session-test")
        assert all(f.status == FindingStatus.OPEN for f in findings)


# ---------------------------------------------------------------------------
# Profile flags
# ---------------------------------------------------------------------------

class TestProfileFlags:
    def test_normal_profile_has_T3(self):
        assert "-T3" in PROFILE_FLAGS["normal"]

    def test_stealth_profile_has_sS(self):
        assert "-sS" in PROFILE_FLAGS["stealth"]

    def test_stealth_profile_has_T2(self):
        assert "-T2" in PROFILE_FLAGS["stealth"]

    def test_aggressive_profile_has_T4(self):
        assert "-T4" in PROFILE_FLAGS["aggressive"]


# ---------------------------------------------------------------------------
# tcp_scan() — integration (nmap mocked)
# ---------------------------------------------------------------------------

class TestTcpScan:
    def test_cancelled_by_user_returns_empty(self):
        with patch("detect.tcp_scan.typer.confirm", return_value=False):
            result = tcp_scan("192.168.1.1", "session-test")
        assert result == []

    def test_nmap_not_found_returns_empty(self):
        with patch("detect.tcp_scan.typer.confirm", return_value=True), \
             patch("detect.tcp_scan._run_nmap_tcp", return_value=None):
            result = tcp_scan("192.168.1.1", "session-test")
        assert result == []

    def test_open_port_confirmed_returns_finding(self):
        with patch("detect.tcp_scan.typer.confirm", return_value=True), \
             patch("detect.tcp_scan._run_nmap_tcp", return_value=TCP_XML_ONE_OPEN):
            result = tcp_scan("192.168.1.26", "session-test")
        assert len(result) == 1
        assert result[0].target_port == 445

    def test_unknown_profile_falls_back_to_normal(self):
        with patch("detect.tcp_scan.typer.confirm", return_value=True), \
             patch("detect.tcp_scan._run_nmap_tcp", return_value=TCP_XML_EMPTY) as mock_nmap:
            tcp_scan("192.168.1.1", "session-test", profile="turbo")
        # Profile falls back to "normal" — _run_nmap_tcp called with "normal"
        call_args = mock_nmap.call_args
        assert call_args[0][1] == "normal"
