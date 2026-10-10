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

import subprocess
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
    TcpScanCancelled,
    TcpScanFailed,
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
  <scaninfo type="connect" protocol="tcp" numservices="1" services="445"/>
  <host>
    <status state="up" reason="syn-ack" reason_ttl="128"/>
    <address addr="192.168.1.26" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack"/>
        <service name="microsoft-ds" product="Microsoft Windows Server 2019"
                 version="" extrainfo="workgroup: WORKGROUP" method="probed"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1700000000" exit="success" elapsed="2.10"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
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

# Complete run, host up, zero open ports (closed ports only).
TCP_XML_UP_NO_OPEN_PORTS = """<?xml version="1.0"?>
<nmaprun>
  <scaninfo type="connect" protocol="tcp" numservices="3" services="23,80,443"/>
  <host>
    <status state="up" reason="echo-reply" reason_ttl="64"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <extraports state="closed" count="3">
        <extrareasons reason="conn-refused" count="3" proto="tcp" ports="23,80,443"/>
      </extraports>
    </ports>
  </host>
  <runstats>
    <finished time="1700000000" exit="success" elapsed="1.20"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>"""

# Host down and not printed by nmap (no host element without verbosity).
TCP_XML_DOWN_UNREPORTED = """<?xml version="1.0"?>
<nmaprun>
  <scaninfo type="connect" protocol="tcp" numservices="1" services="23"/>
  <runstats>
    <finished time="1700000000" exit="success" elapsed="1.00"/>
    <hosts up="0" down="1" total="1"/>
  </runstats>
</nmaprun>"""

# Host explicitly reported down.
TCP_XML_DOWN_REPORTED = """<?xml version="1.0"?>
<nmaprun>
  <scaninfo type="connect" protocol="tcp" numservices="1" services="23"/>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
  </host>
  <runstats>
    <finished time="1700000000" exit="success" elapsed="1.00"/>
    <hosts up="0" down="1" total="1"/>
  </runstats>
</nmaprun>"""

# Up host with a port table but no runstats: the run is not proven finished.
TCP_XML_NO_RUNSTATS = """<?xml version="1.0"?>
<nmaprun>
  <scaninfo type="connect" protocol="tcp" numservices="1" services="23"/>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <extraports state="closed" count="1">
        <extrareasons reason="conn-refused" count="1" proto="tcp" ports="23"/>
      </extraports>
    </ports>
  </host>
</nmaprun>"""

# Complete-looking run whose runstats report an error exit.
TCP_XML_RUN_ERROR = """<?xml version="1.0"?>
<nmaprun>
  <scaninfo type="connect" protocol="tcp" numservices="1" services="23"/>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <extraports state="closed" count="1">
        <extrareasons reason="conn-refused" count="1" proto="tcp" ports="23"/>
      </extraports>
    </ports>
  </host>
  <runstats>
    <finished time="1700000000" exit="error" errormsg="Interrupted"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>"""

# Up host without any port table.
TCP_XML_NO_PORT_TABLE = """<?xml version="1.0"?>
<nmaprun>
  <scaninfo type="connect" protocol="tcp" numservices="1" services="23"/>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
  </host>
  <runstats>
    <finished time="1700000000" exit="success" elapsed="1.00"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>"""
# Real nmap 7.95 output (-p 2000-2100), paths removed: zero open ports, all closed.
TCP_XML_REAL_CLOSED_RANGE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV --version-intensity 5 -T3 -oX - -p 2000-2100 127.0.0.1" start="1791543719" startstr="Fri Oct  9 11:01:59 2026" version="7.95" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="101" services="2000-2100"/>
<verbose level="0"/>
<debugging level="0"/>
<hosthint><status state="up" reason="unknown-response" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
</hostnames>
</hosthint>
<host starttime="1791543719" endtime="1791543719"><status state="up" reason="conn-refused" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
<hostname name="localhost" type="PTR"/>
</hostnames>
<ports><extraports state="closed" count="101">
<extrareasons reason="conn-refused" count="101" proto="tcp" ports="2000-2100"/>
</extraports>
</ports>
<times srtt="58" rttvar="52" to="100000"/>
</host>
<runstats><finished time="1791543719" timestr="Fri Oct  9 11:01:59 2026" summary="Nmap done at Fri Oct  9 11:01:59 2026; 1 IP address (1 host up) scanned in 0.15 seconds" elapsed="0.15" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>"""

# Real nmap 7.95 output (-p 8080,2000-2100), paths removed: one open port, the rest closed.
TCP_XML_REAL_OPEN_AND_CLOSED = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV --version-intensity 5 -T3 -oX - -p 8080,2000-2100 127.0.0.1" start="1791543719" startstr="Fri Oct  9 11:01:59 2026" version="7.95" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="102" services="2000-2100,8080"/>
<verbose level="0"/>
<debugging level="0"/>
<hosthint><status state="up" reason="unknown-response" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
</hostnames>
</hosthint>
<host starttime="1791543719" endtime="1791543725"><status state="up" reason="conn-refused" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
<hostname name="localhost" type="PTR"/>
</hostnames>
<ports><extraports state="closed" count="101">
<extrareasons reason="conn-refused" count="101" proto="tcp" ports="2000-2100"/>
</extraports>
<port protocol="tcp" portid="8080"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" product="SimpleHTTPServer" version="0.6" extrainfo="Python 3.13.16" method="probed" conf="10"><cpe>cpe:/a:python:simplehttpserver:0.6</cpe></service></port>
</ports>
<times srtt="47" rttvar="39" to="100000"/>
</host>
<runstats><finished time="1791543725" timestr="Fri Oct  9 11:02:05 2026" summary="Nmap done at Fri Oct  9 11:02:05 2026; 1 IP address (1 host up) scanned in 6.18 seconds" elapsed="6.18" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>"""

# Real nmap 7.95 output (-p 19001), paths removed: one filtered port (no response).
TCP_XML_REAL_FILTERED_PORT = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV --version-intensity 5 -T3 -oX - -p 19001 127.0.0.1" start="1791543725" startstr="Fri Oct  9 11:02:05 2026" version="7.95" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="1" services="19001"/>
<verbose level="0"/>
<debugging level="0"/>
<hosthint><status state="up" reason="unknown-response" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
</hostnames>
</hosthint>
<host starttime="1791543725" endtime="1791543725"><status state="up" reason="conn-refused" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
<hostname name="localhost" type="PTR"/>
</hostnames>
<ports><port protocol="tcp" portid="19001"><state state="filtered" reason="no-response" reason_ttl="0"/></port>
</ports>
<times srtt="82" rttvar="5000" to="100000"/>
</host>
<runstats><finished time="1791543725" timestr="Fri Oct  9 11:02:05 2026" summary="Nmap done at Fri Oct  9 11:02:05 2026; 1 IP address (1 host up) scanned in 0.38 seconds" elapsed="0.38" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>"""

# Real nmap 7.95 output (--host-timeout 300ms), paths removed: nmap dropped the port
# table and flagged the host timedout, while the run still reports exit="success".
TCP_XML_REAL_HOST_TIMEOUT_NO_PORTS = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV --version-intensity 5 -T3 -oX - --host-timeout 300ms -p 18081,19001,2000-2010 127.0.0.1" start="1791543769" startstr="Fri Oct  9 11:02:49 2026" version="7.95" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="13" services="2000-2010,18081,19001"/>
<verbose level="0"/>
<debugging level="0"/>
<hosthint><status state="up" reason="unknown-response" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
</hostnames>
</hosthint>
<host starttime="1791543769" endtime="1791543770" timedout="true"><status state="up" reason="conn-refused" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
<hostname name="localhost" type="PTR"/>
</hostnames>
<times srtt="37" rttvar="188" to="100000"/>
</host>
<runstats><finished time="1791543770" timestr="Fri Oct  9 11:02:50 2026" summary="Nmap done at Fri Oct  9 11:02:50 2026; 1 IP address (1 host up) scanned in 1.27 seconds" elapsed="1.27" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>"""

# Real nmap 7.95 output (-p 2000-2100,2050-2150), paths removed: the two ranges overlap,
# so nmap counts the 151 distinct ports once (numservices="151") and records all closed.
TCP_XML_REAL_OVERLAPPING_RANGES = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV --version-intensity 5 -T3 -oX - -p 2000-2100,2050-2150 127.0.0.1" start="1791545561" startstr="Fri Oct  9 11:32:41 2026" version="7.95" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="151" services="2000-2150"/>
<verbose level="0"/>
<debugging level="0"/>
<hosthint><status state="up" reason="unknown-response" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
</hostnames>
</hosthint>
<host starttime="1791545561" endtime="1791545561"><status state="up" reason="conn-refused" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
<hostname name="localhost" type="PTR"/>
</hostnames>
<ports><extraports state="closed" count="151">
<extrareasons reason="conn-refused" count="151" proto="tcp" ports="2000-2150"/>
</extraports>
</ports>
<times srtt="49" rttvar="41" to="100000"/>
</host>
<runstats><finished time="1791545561" timestr="Fri Oct  9 11:32:41 2026" summary="Nmap done at Fri Oct  9 11:32:41 2026; 1 IP address (1 host up) scanned in 0.14 seconds" elapsed="0.14" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
"""


def _tcp_scaninfo(numservices: str, services: str = "23") -> str:
    """The <scaninfo> element nmap writes for a TCP connect scan (real format)."""
    return f'<scaninfo type="connect" protocol="tcp" numservices="{numservices}" services="{services}"/>'


def _up_host_xml(ports_inner: str, scaninfo: str = None) -> str:
    """Return a finished run with one up host whose <ports> holds ports_inner.

    scaninfo is written before the host; by default it plans one port
    (numservices="1"). Pass "" to leave the element out."""
    if scaninfo is None:
        scaninfo = _tcp_scaninfo("1")
    return (
        '<?xml version="1.0"?>\n<nmaprun>\n'
        f"  {scaninfo}\n"
        '  <host>\n'
        '    <status state="up" reason="conn-refused" reason_ttl="0"/>\n'
        '    <address addr="192.168.1.1" addrtype="ipv4"/>\n'
        f"    <ports>{ports_inner}</ports>\n"
        "  </host>\n"
        "  <runstats>\n"
        '    <finished time="1700000000" exit="success" elapsed="1.00"/>\n'
        '    <hosts up="1" down="0" total="1"/>\n'
        "  </runstats>\n</nmaprun>"
    )


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
    def test_cancelled_by_user_raises_tcp_scan_cancelled(self):
        with patch("detect.tcp_scan.typer.confirm", return_value=False):
            with pytest.raises(TcpScanCancelled):
                tcp_scan("192.168.1.1", "session-test")

    def test_nmap_not_found_raises_tcp_scan_failed(self):
        with patch("detect.tcp_scan.typer.confirm", return_value=True), \
             patch("detect.tcp_scan._run_nmap_tcp", return_value=None):
            with pytest.raises(TcpScanFailed):
                tcp_scan("192.168.1.1", "session-test")

    def test_timeout_raises_tcp_scan_failed(self):
        with patch("detect.tcp_scan.typer.confirm", return_value=True), \
             patch("detect.tcp_scan.subprocess.run", side_effect=subprocess.TimeoutExpired("nmap", 300)):
            with pytest.raises(TcpScanFailed):
                tcp_scan("192.168.1.1", "session-test")

    def test_known_launch_error_raises_tcp_scan_failed(self):
        with patch("detect.tcp_scan.typer.confirm", return_value=True), \
             patch("detect.tcp_scan.subprocess.run", side_effect=PermissionError("denied")):
            with pytest.raises(TcpScanFailed):
                tcp_scan("192.168.1.1", "session-test")

    def test_unexpected_exception_is_not_masked_as_scan_failure(self):
        # T20: a programming error must not be turned into a normal host failure.
        with patch("detect.tcp_scan.typer.confirm", return_value=True), \
             patch("detect.tcp_scan.subprocess.run", side_effect=RuntimeError("programming error")):
            with pytest.raises(RuntimeError, match="programming error"):
                tcp_scan("192.168.1.1", "session-test")

    def test_malformed_xml_raises_tcp_scan_failed(self):
        with patch("detect.tcp_scan.typer.confirm", return_value=True), \
             patch("detect.tcp_scan._run_nmap_tcp", return_value=MALFORMED_XML):
            with pytest.raises(TcpScanFailed):
                tcp_scan("192.168.1.1", "session-test")

    def test_empty_nmaprun_without_host_is_not_a_success(self):
        # T20: a valid XML that proves no up host is not a successful scan.
        with patch("detect.tcp_scan.typer.confirm", return_value=True), \
             patch("detect.tcp_scan._run_nmap_tcp", return_value=TCP_XML_EMPTY):
            with pytest.raises(TcpScanFailed):
                tcp_scan("192.168.1.1", "session-test")

    def test_host_up_without_open_ports_is_a_success(self):
        # T20: zero open ports on an up host is a completed TCP scan.
        with patch("detect.tcp_scan.typer.confirm", return_value=True), \
             patch("detect.tcp_scan._run_nmap_tcp", return_value=TCP_XML_UP_NO_OPEN_PORTS):
            assert tcp_scan("192.168.1.1", "session-test") == []

    def test_open_port_confirmed_returns_finding(self):
        with patch("detect.tcp_scan.typer.confirm", return_value=True), \
             patch("detect.tcp_scan._run_nmap_tcp", return_value=TCP_XML_ONE_OPEN):
            result = tcp_scan("192.168.1.26", "session-test")
        assert len(result) == 1
        assert result[0].target_port == 445

    def test_unknown_profile_falls_back_to_normal(self):
        with patch("detect.tcp_scan.typer.confirm", return_value=True), \
             patch("detect.tcp_scan._run_nmap_tcp", return_value=TCP_XML_UP_NO_OPEN_PORTS) as mock_nmap:
            tcp_scan("192.168.1.1", "session-test", profile="turbo")
        # Profile falls back to "normal" — _run_nmap_tcp called with "normal"
        call_args = mock_nmap.call_args
        assert call_args[0][1] == "normal"


# ---------------------------------------------------------------------------
# T20 — success criterion: the XML must prove a completed scan of an up host
# ---------------------------------------------------------------------------

class TestTcpSuccessCriterion:
    """A TCP scan is a success only when the nmap XML proves it."""

    def _scan(self, xml: str):
        with patch("detect.tcp_scan.typer.confirm", return_value=True), \
             patch("detect.tcp_scan._run_nmap_tcp", return_value=xml):
            return tcp_scan("192.168.1.1", "session-test")

    def test_host_up_with_zero_open_ports_is_a_success(self):
        assert self._scan(TCP_XML_UP_NO_OPEN_PORTS) == []

    def test_host_up_with_open_port_is_a_success(self):
        assert [f.target_port for f in self._scan(TCP_XML_ONE_OPEN)] == [445]

    def test_host_reported_down_is_not_a_success(self):
        with pytest.raises(TcpScanFailed):
            self._scan(TCP_XML_DOWN_REPORTED)

    def test_host_not_reported_is_not_a_success(self):
        with pytest.raises(TcpScanFailed):
            self._scan(TCP_XML_DOWN_UNREPORTED)

    def test_run_without_runstats_is_not_a_success(self):
        with pytest.raises(TcpScanFailed):
            self._scan(TCP_XML_NO_RUNSTATS)

    def test_run_with_error_exit_is_not_a_success(self):
        with pytest.raises(TcpScanFailed):
            self._scan(TCP_XML_RUN_ERROR)

    def test_up_host_without_port_table_is_not_a_success(self):
        with pytest.raises(TcpScanFailed):
            self._scan(TCP_XML_NO_PORT_TABLE)

    def test_unexpected_root_element_is_not_a_success(self):
        with pytest.raises(TcpScanFailed):
            self._scan('<?xml version="1.0"?><other/>')

    # Port accounting: nmap's <scaninfo numservices="N"> is the number of ports
    # it planned. The port table must record exactly N port states, as explicit
    # <port> entries plus the counts of <extraports> groups.

    def test_empty_port_table_is_not_a_success(self):
        with pytest.raises(TcpScanFailed):
            self._scan(_up_host_xml(""))

    def test_empty_port_table_with_zero_planned_ports_is_not_a_success(self):
        # numservices="0" is not a planned scan, and an empty <ports/> records nothing.
        with pytest.raises(TcpScanFailed):
            self._scan(_up_host_xml("", scaninfo=_tcp_scaninfo("0")))

    @pytest.mark.parametrize("group", [
        '<extraports state="closed" count="0"/>',
        '<extraports state="closed" count="-3"/>',
        '<extraports state="closed" count="x"/>',
        '<extraports state="closed"/>',
        '<extraports state="closed" count="' + "9" * 5000 + '"/>',
        '<extraports state="closed" count="65536"/>',
        '<extraports state="closed" count="999999999"/>',
    ], ids=["zero", "negative", "text", "absent", "overflow", "above-tcp-max", "nine-digits"])
    def test_port_table_without_a_valid_state_count_is_not_a_success(self, group):
        with pytest.raises(TcpScanFailed):
            self._scan(_up_host_xml(group))

    def test_invalid_extraports_count_beside_complete_entries_is_not_a_success(self):
        # The explicit entry matches the one planned port, but the group's size
        # is unknown: the table cannot be counted, so it is not proven complete.
        xml = _up_host_xml(
            '<port protocol="tcp" portid="18081">'
            '<state state="closed" reason="conn-refused" reason_ttl="0"/></port>'
            '<extraports state="closed" count="x"/>',
            scaninfo=_tcp_scaninfo("1", "18081"),
        )
        with pytest.raises(TcpScanFailed):
            self._scan(xml)

    def test_numservices_at_the_tcp_maximum_is_a_success(self):
        # 65535 is the highest TCP port: a full-range scan recording every port as closed is complete.
        xml = _up_host_xml(
            '<extraports state="closed" count="65535">'
            '<extrareasons reason="conn-refused" count="65535" proto="tcp" ports="1-65535"/>'
            "</extraports>",
            scaninfo=_tcp_scaninfo("65535", "1-65535"),
        )
        assert self._scan(xml) == []

    def test_states_summing_above_the_tcp_maximum_is_not_a_success(self):
        # Two groups of 60000 ports cannot belong to a scan of at most 65535 ports.
        xml = _up_host_xml(
            '<extraports state="closed" count="60000"/>'
            '<extraports state="filtered" count="60000"/>',
            scaninfo=_tcp_scaninfo("65535", "1-65535"),
        )
        with pytest.raises(TcpScanFailed):
            self._scan(xml)

    def test_zero_count_extraports_group_is_accepted_when_the_table_is_complete(self):
        # 0 is a valid extraports count: an explicit port plus an empty group still
        # records exactly the one planned port.
        xml = _up_host_xml(
            '<port protocol="tcp" portid="23">'
            '<state state="closed" reason="conn-refused" reason_ttl="0"/></port>'
            '<extraports state="filtered" count="0"/>',
        )
        assert self._scan(xml) == []

    def test_closed_port_recorded_as_port_entry_is_a_success(self):
        xml = _up_host_xml(
            '<port protocol="tcp" portid="18081">'
            '<state state="closed" reason="conn-refused" reason_ttl="0"/></port>'
        )
        assert self._scan(xml) == []

    def test_filtered_ports_summarised_in_extraports_is_a_success(self):
        xml = _up_host_xml(
            '<extraports state="filtered" count="12">'
            '<extrareasons reason="no-response" count="12" proto="tcp" ports="80,2000-2010"/>'
            "</extraports>",
            scaninfo=_tcp_scaninfo("12", "80,2000-2010"),
        )
        assert self._scan(xml) == []

    def test_closed_ports_grouped_in_extraports_covering_every_planned_port_is_a_success(self):
        xml = _up_host_xml(
            '<extraports state="closed" count="5">'
            '<extrareasons reason="conn-refused" count="5" proto="tcp" ports="2000-2004"/>'
            "</extraports>",
            scaninfo=_tcp_scaninfo("5", "2000-2004"),
        )
        assert self._scan(xml) == []

    def test_closed_and_filtered_groups_covering_every_planned_port_is_a_success(self):
        xml = _up_host_xml(
            '<extraports state="closed" count="10">'
            '<extrareasons reason="conn-refused" count="10" proto="tcp" ports="2000-2009"/>'
            "</extraports>"
            '<extraports state="filtered" count="2">'
            '<extrareasons reason="no-response" count="2" proto="tcp" ports="2010-2011"/>'
            "</extraports>",
            scaninfo=_tcp_scaninfo("12", "2000-2011"),
        )
        assert self._scan(xml) == []

    def test_zero_open_with_explicit_and_grouped_states_is_a_success(self):
        xml = _up_host_xml(
            '<port protocol="tcp" portid="18081">'
            '<state state="closed" reason="conn-refused" reason_ttl="0"/></port>'
            '<extraports state="filtered" count="2">'
            '<extrareasons reason="no-response" count="2" proto="tcp" ports="19001-19002"/>'
            "</extraports>",
            scaninfo=_tcp_scaninfo("3", "18081,19001-19002"),
        )
        assert self._scan(xml) == []

    def test_partial_extraports_table_is_not_a_success(self):
        # 101 ports planned, only 50 recorded.
        xml = _up_host_xml(
            '<extraports state="closed" count="50">'
            '<extrareasons reason="conn-refused" count="50" proto="tcp" ports="2000-2049"/>'
            "</extraports>",
            scaninfo=_tcp_scaninfo("101", "2000-2100"),
        )
        with pytest.raises(TcpScanFailed):
            self._scan(xml)

    def test_partial_explicit_entries_is_not_a_success(self):
        # 3 ports planned, only 2 recorded as explicit <port> entries.
        xml = _up_host_xml(
            '<port protocol="tcp" portid="22"><state state="closed" reason="conn-refused"/></port>'
            '<port protocol="tcp" portid="80"><state state="closed" reason="conn-refused"/></port>',
            scaninfo=_tcp_scaninfo("3", "22,80,443"),
        )
        with pytest.raises(TcpScanFailed):
            self._scan(xml)

    def test_open_port_from_a_partial_table_is_not_a_success(self):
        # The open port is real, but the planned port 3389 was never recorded:
        # the scan cannot be trusted, so no finding is returned.
        xml = _up_host_xml(
            '<port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/>'
            '<service name="microsoft-ds" method="table"/></port>',
            scaninfo=_tcp_scaninfo("2", "445,3389"),
        )
        with pytest.raises(TcpScanFailed):
            self._scan(xml)

    def test_more_states_than_planned_ports_is_not_a_success(self):
        # 2 ports planned but 3 states recorded: the counts disagree.
        xml = _up_host_xml(
            '<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/></port>'
            '<port protocol="tcp" portid="80"><state state="closed" reason="conn-refused"/></port>'
            '<extraports state="closed" count="1">'
            '<extrareasons reason="conn-refused" count="1" proto="tcp" ports="443"/>'
            "</extraports>",
            scaninfo=_tcp_scaninfo("2", "22,80"),
        )
        with pytest.raises(TcpScanFailed):
            self._scan(xml)

    def test_conflicting_tcp_scaninfo_counts_is_not_a_success(self):
        xml = _up_host_xml(
            '<extraports state="closed" count="1">'
            '<extrareasons reason="conn-refused" count="1" proto="tcp" ports="23"/>'
            "</extraports>",
            scaninfo=_tcp_scaninfo("1", "23") + "\n  " + _tcp_scaninfo("2", "23,80"),
        )
        with pytest.raises(TcpScanFailed):
            self._scan(xml)

    @pytest.mark.parametrize(
        "scaninfo",
        [
            "",  # no scaninfo element at all
            '<scaninfo type="udp" protocol="udp" numservices="1" services="53"/>',  # no TCP scaninfo
            '<scaninfo type="connect" protocol="tcp" services="23"/>',  # numservices absent
            _tcp_scaninfo(""),
            _tcp_scaninfo("abc"),
            _tcp_scaninfo("0"),
            _tcp_scaninfo("-1"),
            _tcp_scaninfo("1.0"),
            _tcp_scaninfo(" 1"),
            _tcp_scaninfo("01"),
            _tcp_scaninfo("9" * 5000),
        ],
        ids=["no-scaninfo", "udp-only", "no-numservices", "empty", "text", "zero",
             "negative", "decimal", "padded", "leading-zero", "overflow"],
    )
    def test_missing_or_invalid_planned_port_count_is_not_a_success(self, scaninfo):
        xml = _up_host_xml(
            '<extraports state="closed" count="1">'
            '<extrareasons reason="conn-refused" count="1" proto="tcp" ports="23"/>'
            "</extraports>",
            scaninfo=scaninfo,
        )
        with pytest.raises(TcpScanFailed):
            self._scan(xml)

    @pytest.mark.parametrize("planned", ["65536", "999999999"], ids=["above-tcp-max", "nine-digits"])
    def test_planned_count_above_the_tcp_maximum_is_not_a_success(self, planned):
        # The table records exactly the declared number of states, so only the
        # TCP range rule can refuse it: no TCP scan plans more than 65535 ports.
        xml = _up_host_xml(
            f'<extraports state="closed" count="{planned}"/>',
            scaninfo=_tcp_scaninfo(planned, "1-65535"),
        )
        with pytest.raises(TcpScanFailed):
            self._scan(xml)

    # Real nmap 7.95 outputs (see the fixtures above).

    def test_real_nmap_zero_open_closed_range_is_a_success(self):
        assert self._scan(TCP_XML_REAL_CLOSED_RANGE) == []

    def test_real_nmap_open_and_closed_is_a_success(self):
        assert [f.target_port for f in self._scan(TCP_XML_REAL_OPEN_AND_CLOSED)] == [8080]

    def test_real_nmap_filtered_port_is_a_success(self):
        assert self._scan(TCP_XML_REAL_FILTERED_PORT) == []

    def test_real_nmap_overlapping_ranges_count_each_port_once(self):
        assert self._scan(TCP_XML_REAL_OVERLAPPING_RANGES) == []

    def test_real_nmap_host_timeout_without_port_table_is_not_a_success(self):
        with pytest.raises(TcpScanFailed):
            self._scan(TCP_XML_REAL_HOST_TIMEOUT_NO_PORTS)

    def test_host_flagged_timedout_by_nmap_is_not_a_success(self):
        # Variant of the real closed-range output with nmap's timedout flag:
        # a table with recorded states still cannot prove the host scan finished.
        xml = TCP_XML_REAL_CLOSED_RANGE.replace(
            'endtime="1791543719"><status',
            'endtime="1791543719" timedout="true"><status',
            1,
        )
        assert 'timedout="true"' in xml
        with pytest.raises(TcpScanFailed):
            self._scan(xml)


class TestTcpRunnerContracts:
    """Pipeline runner (strict=True) versus the historical runner used by Sentinel."""

    def _run(self, strict: bool, **mock_kwargs):
        from detect.tcp_scan import _run_nmap_tcp
        with patch("detect.tcp_scan.subprocess.run", **mock_kwargs):
            return _run_nmap_tcp("192.168.1.1", "normal", "1-1024", strict=strict)

    @staticmethod
    def _completed(code: int, stdout: str):
        return subprocess.CompletedProcess(args=["nmap"], returncode=code, stdout=stdout, stderr="")

    def test_strict_zero_exit_returns_xml(self):
        out = self._run(True, return_value=self._completed(0, TCP_XML_UP_NO_OPEN_PORTS))
        assert out == TCP_XML_UP_NO_OPEN_PORTS

    @pytest.mark.parametrize("code", [1, 2])
    def test_strict_non_zero_exit_is_rejected_even_with_xml(self, code):
        out = self._run(True, return_value=self._completed(code, TCP_XML_UP_NO_OPEN_PORTS))
        assert out is None

    def test_strict_non_zero_exit_makes_the_tcp_scan_fail(self):
        with patch("detect.tcp_scan.typer.confirm", return_value=True), \
             patch("detect.tcp_scan.subprocess.run",
                   return_value=self._completed(2, TCP_XML_UP_NO_OPEN_PORTS)):
            with pytest.raises(TcpScanFailed):
                tcp_scan("192.168.1.1", "session-test")

    @pytest.mark.parametrize("error", [
        FileNotFoundError("nmap"),
        PermissionError("denied"),
        subprocess.TimeoutExpired("nmap", 300),
        UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
    ])
    def test_strict_known_errors_return_none(self, error):
        assert self._run(True, side_effect=error) is None

    def test_strict_unexpected_exception_propagates(self):
        with pytest.raises(RuntimeError, match="programming error"):
            self._run(True, side_effect=RuntimeError("programming error"))

    def test_legacy_non_zero_exit_keeps_historical_output(self):
        # Sentinel/baseline contract unchanged: exit 2 with stdout is still returned.
        out = self._run(False, return_value=self._completed(2, TCP_XML_UP_NO_OPEN_PORTS))
        assert out == TCP_XML_UP_NO_OPEN_PORTS

    def test_legacy_unexpected_exception_keeps_historical_none(self):
        assert self._run(False, side_effect=RuntimeError("bug")) is None

    def test_legacy_known_error_returns_none(self):
        assert self._run(False, side_effect=FileNotFoundError("nmap")) is None

    def test_sentinel_baseline_wrapper_keeps_legacy_contract(self):
        from sentinel.baseline import _run_nmap_tcp as baseline_run
        with patch("detect.tcp_scan.subprocess.run",
                   return_value=self._completed(2, TCP_XML_UP_NO_OPEN_PORTS)):
            assert baseline_run("192.168.1.1", "normal", "1-1024") == TCP_XML_UP_NO_OPEN_PORTS

    def test_sentinel_monitor_open_ports_keeps_legacy_contract(self):
        from sentinel.monitor import _get_open_ports
        with patch("detect.tcp_scan.subprocess.run", side_effect=RuntimeError("bug")):
            assert _get_open_ports("192.168.1.1") is None
