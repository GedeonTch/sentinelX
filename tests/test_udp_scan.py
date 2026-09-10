"""
tests/test_udp_scan.py — Unit tests for detect/udp_scan.py

Critical negative tests:
- "open|filtered" MUST NOT produce a Finding
- "closed" MUST NOT produce a Finding
- Only strict "open" state produces a Finding
"""

import pytest
from unittest.mock import patch

from core.finding import (
    Category,
    Confidence,
    FindingStatus,
)
from detect.udp_scan import (
    udp_scan,
    _parse_udp_xml,
    _extract_udp_service,
)
import xml.etree.ElementTree as ET


# ---------------------------------------------------------------------------
# Fixed XML fixtures
# ---------------------------------------------------------------------------

UDP_XML_ONE_OPEN = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="53">
        <state state="open" reason="udp-response"/>
        <service name="domain" product="dnsmasq" version="2.86" method="probed"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

UDP_XML_OPEN_FILTERED = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="161">
        <state state="open|filtered" reason="no-response"/>
        <service name="snmp" method="table"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

UDP_XML_CLOSED = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="69">
        <state state="closed" reason="port-unreach"/>
        <service name="tftp" method="table"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

UDP_XML_MIXED = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="53">
        <state state="open" reason="udp-response"/>
        <service name="domain" method="probed"/>
      </port>
      <port protocol="udp" portid="161">
        <state state="open|filtered" reason="no-response"/>
        <service name="snmp" method="table"/>
      </port>
      <port protocol="udp" portid="69">
        <state state="closed" reason="port-unreach"/>
        <service name="tftp" method="table"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

UDP_XML_EMPTY = """<?xml version="1.0"?><nmaprun></nmaprun>"""


# ---------------------------------------------------------------------------
# _parse_udp_xml
# ---------------------------------------------------------------------------

class TestParseUdpXml:
    def test_open_port_returns_one_finding(self):
        findings = _parse_udp_xml(UDP_XML_ONE_OPEN, "192.168.1.1", "session-test")
        assert len(findings) == 1
        assert findings[0].target_port == 53

    def test_open_filtered_produces_no_finding(self):
        """CRITICAL: open|filtered must NEVER produce a Finding."""
        findings = _parse_udp_xml(UDP_XML_OPEN_FILTERED, "192.168.1.1", "session-test")
        assert findings == []

    def test_closed_produces_no_finding(self):
        """CRITICAL: closed UDP port must NEVER produce a Finding."""
        findings = _parse_udp_xml(UDP_XML_CLOSED, "192.168.1.1", "session-test")
        assert findings == []

    def test_mixed_states_only_open_returned(self):
        """Only port 53 (open) — 161 (open|filtered) and 69 (closed) excluded."""
        findings = _parse_udp_xml(UDP_XML_MIXED, "192.168.1.1", "session-test")
        assert len(findings) == 1
        assert findings[0].target_port == 53

    def test_finding_module_is_udp_scan(self):
        findings = _parse_udp_xml(UDP_XML_ONE_OPEN, "192.168.1.1", "session-test")
        assert findings[0].module == "udp_scan"

    def test_finding_category_is_service(self):
        findings = _parse_udp_xml(UDP_XML_ONE_OPEN, "192.168.1.1", "session-test")
        assert findings[0].category == Category.SERVICE

    def test_empty_xml_returns_empty(self):
        findings = _parse_udp_xml(UDP_XML_EMPTY, "192.168.1.1", "session-test")
        assert findings == []

    def test_malformed_xml_returns_empty(self):
        findings = _parse_udp_xml("not xml <<<", "192.168.1.1", "session-test")
        assert findings == []


# ---------------------------------------------------------------------------
# Finding invariants
# ---------------------------------------------------------------------------

class TestUdpFindingInvariants:
    def test_risk_score_is_none(self):
        findings = _parse_udp_xml(UDP_XML_ONE_OPEN, "192.168.1.1", "session-test")
        assert all(f.risk_score is None for f in findings)

    def test_explanation_is_none(self):
        findings = _parse_udp_xml(UDP_XML_ONE_OPEN, "192.168.1.1", "session-test")
        assert all(f.explanation is None for f in findings)

    def test_evidence_raw_not_empty(self):
        findings = _parse_udp_xml(UDP_XML_ONE_OPEN, "192.168.1.1", "session-test")
        assert all(f.evidence.raw != "" for f in findings)

    def test_session_id_propagated(self):
        findings = _parse_udp_xml(UDP_XML_ONE_OPEN, "192.168.1.1", "session-xyz")
        assert findings[0].session_id == "session-xyz"

    def test_status_is_open(self):
        findings = _parse_udp_xml(UDP_XML_ONE_OPEN, "192.168.1.1", "session-test")
        assert findings[0].status == FindingStatus.OPEN


# ---------------------------------------------------------------------------
# udp_scan() — integration
# ---------------------------------------------------------------------------

class TestUdpScan:
    def test_cancelled_returns_empty(self):
        with patch("detect.udp_scan.typer.confirm", return_value=False):
            result = udp_scan("192.168.1.1", "session-test")
        assert result == []

    def test_nmap_not_found_returns_empty(self):
        with patch("detect.udp_scan.typer.confirm", return_value=True), \
             patch("detect.udp_scan._run_nmap_udp", return_value=None):
            result = udp_scan("192.168.1.1", "session-test")
        assert result == []

    def test_open_udp_port_returns_finding(self):
        with patch("detect.udp_scan.typer.confirm", return_value=True), \
             patch("detect.udp_scan._run_nmap_udp", return_value=UDP_XML_ONE_OPEN):
            result = udp_scan("192.168.1.1", "session-test")
        assert len(result) == 1
        assert result[0].target_port == 53

    def test_all_findings_risk_score_none(self):
        with patch("detect.udp_scan.typer.confirm", return_value=True), \
             patch("detect.udp_scan._run_nmap_udp", return_value=UDP_XML_ONE_OPEN):
            result = udp_scan("192.168.1.1", "session-test")
        assert all(f.risk_score is None for f in result)
