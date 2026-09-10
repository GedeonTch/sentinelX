"""
tests/test_device_fingerprint.py — Unit tests for 01_recon/device_fingerprint.py

Strategy:
- ZERO real network calls — nmap subprocess is always mocked
- All tests use fixed XML strings that replicate real nmap output
- Tests cover: parser, confidence rules, MAC/hostname extraction,
  OS detection, empty output, malformed XML, no active hosts

No lab test here — lab validation (real scan on authorized VM) is
a separate manual step required before marking the ticket DONE.
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
from recon.device_fingerprint import (
    _parse_active_hosts,
    _parse_host,
    _extract_mac_hostname,
    _detect_os,
    fingerprint,
)


# ---------------------------------------------------------------------------
# Fixed XML fixtures — real nmap output format
# ---------------------------------------------------------------------------

PING_XML_ONE_HOST = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <address addr="aa:bb:cc:dd:ee:ff" addrtype="mac" vendor="AcmeCorp"/>
    <hostnames>
      <hostname name="lab-server.local" type="PTR"/>
    </hostnames>
  </host>
</nmaprun>"""

PING_XML_TWO_HOSTS = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
  </host>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.1.20" addrtype="ipv4"/>
  </host>
</nmaprun>"""

PING_XML_HOST_DOWN = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="192.168.1.99" addrtype="ipv4"/>
  </host>
</nmaprun>"""

PING_XML_EMPTY = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
</nmaprun>"""

OS_XML_HIGH_ACCURACY = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <os>
      <osmatch name="Linux 4.15" accuracy="96"/>
      <osmatch name="Linux 4.4" accuracy="88"/>
    </os>
  </host>
</nmaprun>"""

OS_XML_LOW_ACCURACY = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <os>
      <osmatch name="Linux 2.6.x" accuracy="70"/>
    </os>
  </host>
</nmaprun>"""

OS_XML_NO_MATCH = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <os>
    </os>
  </host>
</nmaprun>"""

MALFORMED_XML = "this is not xml <<<<"


# ---------------------------------------------------------------------------
# _parse_active_hosts
# ---------------------------------------------------------------------------

class TestParseActiveHosts:
    def test_one_active_host(self):
        result = _parse_active_hosts(PING_XML_ONE_HOST)
        assert result == ["192.168.1.10"]

    def test_two_active_hosts(self):
        result = _parse_active_hosts(PING_XML_TWO_HOSTS)
        assert "192.168.1.10" in result
        assert "192.168.1.20" in result
        assert len(result) == 2

    def test_host_down_not_included(self):
        result = _parse_active_hosts(PING_XML_HOST_DOWN)
        assert result == []

    def test_empty_xml_returns_empty_list(self):
        result = _parse_active_hosts(PING_XML_EMPTY)
        assert result == []

    def test_malformed_xml_returns_empty_list(self):
        result = _parse_active_hosts(MALFORMED_XML)
        assert result == []


# ---------------------------------------------------------------------------
# _extract_mac_hostname
# ---------------------------------------------------------------------------

class TestExtractMacHostname:
    def test_extracts_mac_and_hostname(self):
        mac, hostname = _extract_mac_hostname("192.168.1.10", PING_XML_ONE_HOST)
        assert mac == "aa:bb:cc:dd:ee:ff"
        assert hostname == "lab-server.local"

    def test_ip_not_in_xml_returns_empty(self):
        mac, hostname = _extract_mac_hostname("10.0.0.1", PING_XML_ONE_HOST)
        assert mac == ""
        assert hostname == ""

    def test_no_mac_returns_empty_string(self):
        mac, hostname = _extract_mac_hostname("192.168.1.10", PING_XML_TWO_HOSTS)
        assert mac == ""

    def test_malformed_xml_returns_empty(self):
        mac, hostname = _extract_mac_hostname("192.168.1.10", MALFORMED_XML)
        assert mac == ""
        assert hostname == ""


# ---------------------------------------------------------------------------
# _detect_os
# ---------------------------------------------------------------------------

class TestDetectOs:
    def test_high_accuracy_returns_probable(self):
        os_name, confidence = _detect_os(OS_XML_HIGH_ACCURACY)
        assert os_name == "Linux 4.15"
        assert confidence == Confidence.PROBABLE

    def test_low_accuracy_returns_possible(self):
        os_name, confidence = _detect_os(OS_XML_LOW_ACCURACY)
        assert os_name == "Linux 2.6.x"
        assert confidence == Confidence.POSSIBLE

    def test_no_os_match_returns_empty_confirmed(self):
        """No OS match → empty string + CONFIRMED (absence of info is not uncertain)."""
        os_name, confidence = _detect_os(OS_XML_NO_MATCH)
        assert os_name == ""
        assert confidence == Confidence.CONFIRMED

    def test_malformed_xml_returns_empty_confirmed(self):
        os_name, confidence = _detect_os(MALFORMED_XML)
        assert os_name == ""
        assert confidence == Confidence.CONFIRMED

    def test_picks_best_accuracy_among_multiple_matches(self):
        """Must pick the osmatch with the highest accuracy."""
        os_name, confidence = _detect_os(OS_XML_HIGH_ACCURACY)
        # accuracy=96 > accuracy=88 → Linux 4.15 wins
        assert os_name == "Linux 4.15"

    def test_accuracy_exactly_85_is_probable(self):
        xml = """<nmaprun><host><os>
            <osmatch name="Windows 10" accuracy="85"/>
        </os></host></nmaprun>"""
        os_name, confidence = _detect_os(xml)
        assert confidence == Confidence.PROBABLE

    def test_accuracy_84_is_possible(self):
        xml = """<nmaprun><host><os>
            <osmatch name="Windows 7" accuracy="84"/>
        </os></host></nmaprun>"""
        os_name, confidence = _detect_os(xml)
        assert confidence == Confidence.POSSIBLE


# ---------------------------------------------------------------------------
# _parse_host — Finding construction
# ---------------------------------------------------------------------------

class TestParseHost:
    def test_returns_one_finding_per_host(self):
        findings = _parse_host(
            ip="192.168.1.10",
            ping_xml=PING_XML_ONE_HOST,
            os_xml=OS_XML_HIGH_ACCURACY,
            session_id="session-test",
        )
        assert len(findings) == 1

    def test_finding_has_correct_ip(self):
        findings = _parse_host("192.168.1.10", PING_XML_ONE_HOST, None, "session-test")
        assert findings[0].target_ip == "192.168.1.10"

    def test_finding_session_id_set(self):
        findings = _parse_host("192.168.1.10", PING_XML_ONE_HOST, None, "session-abc")
        assert findings[0].session_id == "session-abc"

    def test_finding_module_is_device_fingerprint(self):
        findings = _parse_host("192.168.1.10", PING_XML_ONE_HOST, None, "session-test")
        assert findings[0].module == "device_fingerprint"

    def test_finding_category_is_network(self):
        findings = _parse_host("192.168.1.10", PING_XML_ONE_HOST, None, "session-test")
        assert findings[0].category == Category.NETWORK

    def test_finding_severity_is_info(self):
        """Host discovery is INFO — it is not a vulnerability."""
        findings = _parse_host("192.168.1.10", PING_XML_ONE_HOST, None, "session-test")
        assert findings[0].severity == Severity.INFO

    def test_finding_confidence_confirmed_when_no_os(self):
        """Host is up (ping responded) → CONFIRMED, regardless of OS detection."""
        findings = _parse_host("192.168.1.10", PING_XML_ONE_HOST, None, "session-test")
        assert findings[0].confidence == Confidence.CONFIRMED

    def test_finding_evidence_raw_not_empty(self):
        findings = _parse_host("192.168.1.10", PING_XML_ONE_HOST, None, "session-test")
        assert findings[0].evidence.raw != ""

    def test_finding_evidence_command_contains_nmap(self):
        findings = _parse_host("192.168.1.10", PING_XML_ONE_HOST, None, "session-test")
        assert "nmap" in findings[0].evidence.command

    def test_finding_risk_score_is_none(self):
        """risk_score must always be None — never set by a scanner."""
        findings = _parse_host("192.168.1.10", PING_XML_ONE_HOST, None, "session-test")
        assert findings[0].risk_score is None

    def test_finding_explanation_is_none(self):
        """explanation is always None here — set by knowledge base in #015."""
        findings = _parse_host("192.168.1.10", PING_XML_ONE_HOST, None, "session-test")
        assert findings[0].explanation is None

    def test_finding_os_stored_in_service_version(self):
        findings = _parse_host(
            "192.168.1.10",
            PING_XML_ONE_HOST,
            OS_XML_HIGH_ACCURACY,
            "session-test",
        )
        assert findings[0].service_version == "Linux 4.15"

    def test_finding_status_is_open(self):
        findings = _parse_host("192.168.1.10", PING_XML_ONE_HOST, None, "session-test")
        assert findings[0].status == FindingStatus.OPEN


# ---------------------------------------------------------------------------
# fingerprint() — integration (nmap mocked)
# ---------------------------------------------------------------------------

class TestFingerprint:
    def test_cancelled_by_user_returns_empty(self):
        with patch("recon.device_fingerprint.typer.confirm", return_value=False):
            result = fingerprint("192.168.1.0/24", "session-test")
        assert result == []

    def test_nmap_not_found_returns_empty(self):
        with patch("recon.device_fingerprint.typer.confirm", return_value=True), \
             patch("recon.device_fingerprint._run_nmap", return_value=None):
            result = fingerprint("192.168.1.0/24", "session-test")
        assert result == []

    def test_no_active_hosts_returns_empty(self):
        with patch("recon.device_fingerprint.typer.confirm", return_value=True), \
             patch("recon.device_fingerprint._run_nmap_ping", return_value=PING_XML_EMPTY), \
             patch("recon.device_fingerprint._run_nmap_os", return_value=None):
            result = fingerprint("192.168.1.0/24", "session-test")
        assert result == []

    def test_one_active_host_returns_one_finding(self):
        with patch("recon.device_fingerprint.typer.confirm", return_value=True), \
             patch("recon.device_fingerprint._run_nmap_ping", return_value=PING_XML_ONE_HOST), \
             patch("recon.device_fingerprint._run_nmap_os", return_value=OS_XML_HIGH_ACCURACY):
            result = fingerprint("192.168.1.10", "session-test")
        assert len(result) == 1
        assert isinstance(result[0], Finding)

    def test_two_active_hosts_returns_two_findings(self):
        with patch("recon.device_fingerprint.typer.confirm", return_value=True), \
             patch("recon.device_fingerprint._run_nmap_ping", return_value=PING_XML_TWO_HOSTS), \
             patch("recon.device_fingerprint._run_nmap_os", return_value=None):
            result = fingerprint("192.168.1.0/24", "session-test")
        assert len(result) == 2

    def test_all_findings_have_session_id(self):
        with patch("recon.device_fingerprint.typer.confirm", return_value=True), \
             patch("recon.device_fingerprint._run_nmap_ping", return_value=PING_XML_TWO_HOSTS), \
             patch("recon.device_fingerprint._run_nmap_os", return_value=None):
            result = fingerprint("192.168.1.0/24", "session-xyz")
        assert all(f.session_id == "session-xyz" for f in result)

    def test_all_findings_have_non_empty_evidence(self):
        with patch("recon.device_fingerprint.typer.confirm", return_value=True), \
             patch("recon.device_fingerprint._run_nmap_ping", return_value=PING_XML_ONE_HOST), \
             patch("recon.device_fingerprint._run_nmap_os", return_value=None):
            result = fingerprint("192.168.1.10", "session-test")
        assert all(f.evidence.raw != "" for f in result)

    def test_all_findings_risk_score_is_none(self):
        """Invariant: no scanner sets risk_score."""
        with patch("recon.device_fingerprint.typer.confirm", return_value=True), \
             patch("recon.device_fingerprint._run_nmap_ping", return_value=PING_XML_ONE_HOST), \
             patch("recon.device_fingerprint._run_nmap_os", return_value=None):
            result = fingerprint("192.168.1.10", "session-test")
        assert all(f.risk_score is None for f in result)
