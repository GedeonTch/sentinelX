"""
tests/test_sentinel_monitor.py — Unit tests for sentinel/monitor.py

Covers: new_host, mac_change candidates and the TCP observations (T23-B: new_port is decided by the manager).
        removed_host: NOT detected (out of scope V1).
        All network calls mocked.
"""

import pytest
from unittest.mock import patch

from sentinel.arp_probe import ArpProbeResult, ArpProbeStatus
from sentinel.baseline import BaselineEntry, NetworkIdentity
from sentinel.monitor import (
    NetworkChange,
    ScanDegradedError,
    ScanFailedError,
    check_network,
    HostTcpObservation,
)
from tests.test_sentinel_baseline_reliability import nmap_tcp_xml

IDENTITY = NetworkIdentity("192.168.1.0/24", "192.168.1.1", "aa:aa:aa:aa:aa:aa")
SESSION = "session-monitor-test"
NO_KNOWN = frozenset()

TEST_NMAP_TCP_XML = nmap_tcp_xml()
TEST_NMAP_TCP_XML_OPEN_22_80 = nmap_tcp_xml(open_ports=[22, 80])
TEST_NMAP_TCP_XML_OMIT_EXTRAPORTS = nmap_tcp_xml(open_ports=[22], omit_extraports=True)
TEST_NMAP_TCP_XML_OMIT_RUNSTATS = nmap_tcp_xml(open_ports=[22], omit_runstats=True)
TEST_NMAP_TCP_XML_FINISHED_ERROR = nmap_tcp_xml(open_ports=[22], finished="error")
TEST_NMAP_TCP_XML_HOST_DOWN = nmap_tcp_xml(open_ports=[22], host_state="down")
TEST_NMAP_TCP_XML_TIMEDOUT = nmap_tcp_xml(open_ports=[22], timedout=True)
TEST_NMAP_TCP_XML_OMIT_PORTS = nmap_tcp_xml(open_ports=[22], omit_ports=True)
TEST_NMAP_TCP_XML_DUPLICATE_PORT = nmap_tcp_xml(open_ports=[22], duplicate_port=22)
TEST_NMAP_TCP_XML_WRONG_SERVICES = nmap_tcp_xml(open_ports=[22], services="1-1024")
TEST_NMAP_TCP_XML_EXTRA_HOST = nmap_tcp_xml(open_ports=[22], extra_host_ip="192.168.1.99")


@pytest.fixture(autouse=True)
def _no_real_arp():
    """Tests never send ARP traffic: every probe answers ERROR unless a test patches it."""
    with patch("sentinel.monitor.arp_probe",
               return_value=ArpProbeResult(ArpProbeStatus.ERROR, "0.0.0.0", error="test double")):
        yield

BASELINE = {
    "192.168.1.10": BaselineEntry(
        asset_id="a1", ip="192.168.1.10", mac="11:22:33:44:55:66",
        ports=[22, 80], last_scan="2026-01-01T00:00:00+00:00"
    ),
    "192.168.1.20": BaselineEntry(
        asset_id="a2", ip="192.168.1.20", mac="",
        ports=[443], last_scan="2026-01-01T00:00:00+00:00"
    ),
}


def _mock_active(ips):
    return ips


def _mock_ports(ip, ports_map):
    return ports_map.get(ip, [])


def _mock_mac(ip, mac_map):
    return mac_map.get(ip, "")


class TestNewHost:
    def test_new_host_detected(self):
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10", "192.168.1.99"]), \
             patch("sentinel.monitor._get_host_tcp_observation", return_value=HostTcpObservation(ip="192.168.1.10", ports=[22])), \
             patch("sentinel.monitor._get_arp_mac", return_value=""):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE, NO_KNOWN).candidate_changes
        new_hosts = [c for c in changes if c.change_type == "new_host"]
        assert len(new_hosts) == 1
        assert new_hosts[0].asset_ip == "192.168.1.99"

    def test_no_new_host_when_all_known(self):
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
             patch("sentinel.monitor._get_host_tcp_observation", return_value=HostTcpObservation(ip="192.168.1.10", ports=[22, 80])), \
             patch("sentinel.monitor._get_arp_mac", return_value="11:22:33:44:55:66"):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE, NO_KNOWN).candidate_changes
        new_hosts = [c for c in changes if c.change_type == "new_host"]
        assert new_hosts == []


class TestNewPort:
    def test_new_port_detected(self):
        """T23-B: the monitor reports the observed ports; new_port is decided by the manager (§9.5)."""
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
             patch("sentinel.monitor._get_host_tcp_observation", return_value=HostTcpObservation(ip="192.168.1.10", ports=[22, 80, 4444])), \
             patch("sentinel.monitor._get_arp_mac", return_value="11:22:33:44:55:66"):
            obs = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE, NO_KNOWN)
        assert obs.tcp_observations["192.168.1.10"].ports == [22, 80, 4444]
        assert [c for c in obs.candidate_changes if c.change_type == "new_port"] == []

    def test_no_new_port_when_ports_match(self):
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
             patch("sentinel.monitor._get_host_tcp_observation", return_value=HostTcpObservation(ip="192.168.1.10", ports=[22, 80])), \
             patch("sentinel.monitor._get_arp_mac", return_value="11:22:33:44:55:66"):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE, NO_KNOWN).candidate_changes
        new_ports = [c for c in changes if c.change_type == "new_port"]
        assert new_ports == []

    def test_multiple_new_ports(self):
        """T23-B: both unknown ports are present in the TCP observation, not in candidate_changes."""
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
             patch("sentinel.monitor._get_host_tcp_observation", return_value=HostTcpObservation(ip="192.168.1.10", ports=[22, 80, 3389, 4444])), \
             patch("sentinel.monitor._get_arp_mac", return_value=""):
            obs = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE, NO_KNOWN)
        assert obs.tcp_observations["192.168.1.10"].ports == [22, 80, 3389, 4444]
        assert [c for c in obs.candidate_changes if c.change_type == "new_port"] == []


class TestMacChange:
    def test_mac_change_detected(self):
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
             patch("sentinel.monitor._get_host_tcp_observation", return_value=HostTcpObservation(ip="192.168.1.10", ports=[22, 80])), \
             patch("sentinel.monitor._get_arp_mac", return_value="ff:ff:ff:ff:ff:ff"):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE, NO_KNOWN).candidate_changes
        mac_changes = [c for c in changes if c.change_type == "mac_change"]
        assert len(mac_changes) == 1
        assert mac_changes[0].asset_ip == "192.168.1.10"

    def test_no_mac_change_when_mac_matches(self):
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
             patch("sentinel.monitor._get_host_tcp_observation", return_value=HostTcpObservation(ip="192.168.1.10", ports=[22, 80])), \
             patch("sentinel.monitor._get_arp_mac", return_value="11:22:33:44:55:66"):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE, NO_KNOWN).candidate_changes
        mac_changes = [c for c in changes if c.change_type == "mac_change"]
        assert mac_changes == []

    def test_no_mac_change_when_baseline_mac_empty(self):
        """If baseline has no MAC, we cannot detect a change."""
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.20"]), \
             patch("sentinel.monitor._get_host_tcp_observation", return_value=HostTcpObservation(ip="192.168.1.10", ports=[443])), \
             patch("sentinel.monitor._get_arp_mac", return_value="aa:bb:cc:dd:ee:ff"):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE, NO_KNOWN).candidate_changes
        mac_changes = [c for c in changes if c.change_type == "mac_change"]
        assert mac_changes == []


class TestRemovedHostOutOfScope:
    def test_removed_host_not_reported(self):
        """A host in baseline that goes offline must NOT produce a change."""
        with patch("sentinel.monitor._get_active_hosts", return_value=[]), \
             patch("sentinel.monitor._get_host_tcp_observation", return_value=HostTcpObservation(ip="192.168.1.10", ports=[])), \
             patch("sentinel.monitor._get_arp_mac", return_value=""):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE, NO_KNOWN).candidate_changes
        assert changes == []


class TestMonitorEdgeCases:
    def test_empty_baseline_only_new_hosts(self):
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
             patch("sentinel.monitor._get_host_tcp_observation", return_value=HostTcpObservation(ip="192.168.1.10", ports=[22])), \
             patch("sentinel.monitor._get_arp_mac", return_value=""):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, {}, NO_KNOWN).candidate_changes
        new_hosts = [c for c in changes if c.change_type == "new_host"]
        assert len(new_hosts) == 1

    def test_ping_scan_failure_returns_empty(self):
        """A failed ping scan must raise ScanFailedError, not return []."""
        import pytest
        with patch("sentinel.monitor._get_active_hosts", return_value=None):
            with pytest.raises(ScanFailedError):
                check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE, NO_KNOWN)

    def test_evidence_not_empty(self):
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.99"]), \
             patch("sentinel.monitor._get_host_tcp_observation", return_value=HostTcpObservation(ip="192.168.1.10", ports=[])), \
             patch("sentinel.monitor._get_arp_mac", return_value=""):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE, NO_KNOWN).candidate_changes
        assert all(c.evidence != "" for c in changes)


# ---------------------------------------------------------------------------
# A3 — Return contract tests : None vs [] vs [ports]
# ---------------------------------------------------------------------------

class TestScanFailedContract:

    def test_ping_failure_raises_scan_failed_error(self):
        """None from _get_active_hosts → ScanFailedError, NOT empty list."""
        import pytest
        with patch("sentinel.monitor._get_active_hosts", return_value=None):
            with pytest.raises(ScanFailedError):
                check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE, NO_KNOWN)

    def test_ping_success_empty_network_returns_empty_list(self):
        """[] from _get_active_hosts → empty changes, no exception."""
        with patch("sentinel.monitor._get_active_hosts", return_value=[]), \
             patch("sentinel.monitor._get_host_tcp_observation", return_value=HostTcpObservation(ip="192.168.1.10", ports=[])), \
             patch("sentinel.monitor._get_arp_mac", return_value=""):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE, NO_KNOWN).candidate_changes
        assert changes == []

    def test_port_scan_failure_degrades_without_new_port(self):
        """None from _get_host_tcp_observation → degraded check, no new_port change."""
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
             patch("sentinel.monitor._get_host_tcp_observation", return_value=HostTcpObservation(ip="192.168.1.10", ports=None)), \
             patch("sentinel.monitor._get_arp_mac", return_value="11:22:33:44:55:66"):
            with pytest.raises(ScanDegradedError) as exc_info:
                check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE, NO_KNOWN)
        new_ports = [c for c in exc_info.value.observations.candidate_changes if c.change_type == "new_port"]
        assert new_ports == []

    def test_port_scan_empty_result_reports_no_new_ports(self):
        """[] from _get_host_tcp_observation → scan succeeded, no new ports."""
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
             patch("sentinel.monitor._get_host_tcp_observation", return_value=HostTcpObservation(ip="192.168.1.10", ports=[])), \
             patch("sentinel.monitor._get_arp_mac", return_value="11:22:33:44:55:66"):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE, NO_KNOWN).candidate_changes
        # Baseline has ports [22, 80], scan returns [] → ports 22 and 80 disappeared
        # but removed_host/port is out of scope V1 → no changes
        new_ports = [c for c in changes if c.change_type == "new_port"]
        assert new_ports == []

    def test_port_scan_new_port_detected_when_scan_succeeds(self):
        """[22, 80, 4444] from _get_host_tcp_observation → complete observation; new_port is a manager decision."""
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
             patch("sentinel.monitor._get_host_tcp_observation", return_value=HostTcpObservation(ip="192.168.1.10", ports=[22, 80, 4444])), \
             patch("sentinel.monitor._get_arp_mac", return_value="11:22:33:44:55:66"):
            obs = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE, NO_KNOWN)
        assert obs.tcp_observations["192.168.1.10"].ports == [22, 80, 4444]
        assert obs.tcp_observations["192.168.1.10"].ports is not None

    def test_scan_failed_error_is_distinct_from_empty_changes(self):
        """ScanFailedError and [] are two distinct outcomes."""
        import pytest
        # ScanFailedError on ping failure
        with patch("sentinel.monitor._get_active_hosts", return_value=None):
            with pytest.raises(ScanFailedError):
                check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE, NO_KNOWN)

        # [] on successful scan with no changes
        with patch("sentinel.monitor._get_active_hosts", return_value=[]), \
             patch("sentinel.monitor._get_host_tcp_observation", return_value=HostTcpObservation(ip="192.168.1.10", ports=[])), \
             patch("sentinel.monitor._get_arp_mac", return_value=""):
            result = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE, NO_KNOWN).candidate_changes
        assert result == []  # no exception, empty list


# ---------------------------------------------------------------------------
# A1 corrections — integration tests for _get_host_tcp_observation
# ---------------------------------------------------------------------------

class TestGetHostTcpObservationIntegration:
    """Integration: _get_host_tcp_observation uses real XML parsing, single scan."""

    @staticmethod
    def _mock_xml(open_ports=None, closed_ports=None, filtered_ports=None, ip="192.168.1.10"):
        """Build valid nmap XML for SENTINEL_TCP_PORTS port range."""
        from sentinel.baseline import SENTINEL_TCP_PORTS
        from detect.tcp_scan import _expand_port_spec
        expected = _expand_port_spec(SENTINEL_TCP_PORTS)
        if expected is None:
            expected = frozenset()

        open_ports = set(open_ports or [])
        closed_ports = set(closed_ports or [])
        filtered_ports = set(filtered_ports or [])
        assigned = open_ports | closed_ports | filtered_ports
        remaining = expected - assigned

        ports_xml = ""
        for p in sorted(open_ports):
            ports_xml += f'<port protocol="tcp" portid="{p}"><state state="open"/></port>'
        for p in sorted(closed_ports):
            ports_xml += f'<port protocol="tcp" portid="{p}"><state state="closed"/></port>'
        for p in sorted(filtered_ports):
            ports_xml += f'<port protocol="tcp" portid="{p}"><state state="filtered"/></port>'

        if remaining:
            ports_xml += f'<extraports state="filtered" count="{len(remaining)}"/>'

        return (
            f'<?xml version="1.0"?>\n'
            f'<nmaprun><scaninfo type="syn" protocol="tcp" numservices="{len(expected)}" services="{SENTINEL_TCP_PORTS}"/>'
            f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>'
            f'<ports>{ports_xml}</ports></host>'
            f'<runstats><finished exit="success"/></runstats></nmaprun>'
        )

    def test_single_scan_produces_states_and_ports(self):
        """_get_host_tcp_observation returns states from a single scan — no double scan."""
        from sentinel.monitor import _get_host_tcp_observation
        from detect.tcp_scan import PortState
        xml = self._mock_xml(
            open_ports=[22, 80],
            closed_ports=[443],
            filtered_ports=[3389],
        )
        call_count = {"n": 0}
        original_run = None

        def counting_run(*args, **kwargs):
            call_count["n"] += 1
            return xml

        with patch("sentinel.monitor._tcp_run_nmap", side_effect=counting_run):
            obs = _get_host_tcp_observation("192.168.1.10")

        assert call_count["n"] == 1, f"expected 1 nmap call, got {call_count['n']}"
        assert obs.ports == [22, 80]
        assert obs.states is not None
        assert obs.states[22] is PortState.OPEN
        assert obs.states[80] is PortState.OPEN
        assert obs.states[443] is PortState.CLOSED
        assert obs.states[3389] is PortState.FILTERED

    def test_failed_scan_returns_incomplete(self):
        """Failed scan → INCOMPLETE observation with ports=None, no states."""
        from sentinel.monitor import _get_host_tcp_observation
        with patch("sentinel.monitor._tcp_run_nmap", return_value=None):
            obs = _get_host_tcp_observation("192.168.1.10")
        assert obs.ports is None
        assert obs.states is None

    def test_invalid_xml_returns_incomplete(self):
        """Invalid XML → INCOMPLETE, no silent fallback."""
        from sentinel.monitor import _get_host_tcp_observation
        with patch("sentinel.monitor._tcp_run_nmap", return_value="not xml at all"):
            obs = _get_host_tcp_observation("192.168.1.10")
        assert obs.ports is None
        assert obs.states is None

    def test_wrong_address_returns_incomplete(self):
        """XML for a different IP → INCOMPLETE."""
        from sentinel.monitor import _get_host_tcp_observation
        xml = self._mock_xml(open_ports=[80], ip="10.0.0.99")
        with patch("sentinel.monitor._tcp_run_nmap", return_value=xml):
            obs = _get_host_tcp_observation("192.168.1.10")
        assert obs.ports is None
        assert obs.states is None


class TestAuthoritativeTcpValidation:
    """Monitor and baseline share one acceptance gate (Issue A / D-A5)."""

    def _monitor(self, xml):
        from sentinel.monitor import _get_host_tcp_observation
        with patch("sentinel.monitor._tcp_run_nmap", return_value=xml):
            return _get_host_tcp_observation("192.168.1.10")

    @pytest.mark.parametrize("xml,expected", [
        (TEST_NMAP_TCP_XML, []),                                            # complete, zero open ports
        (TEST_NMAP_TCP_XML_OPEN_22_80, [22, 80]),                          # complete, open ports
        (TEST_NMAP_TCP_XML_OMIT_EXTRAPORTS, None),                         # partial port table
        (TEST_NMAP_TCP_XML_OMIT_RUNSTATS, None),                           # run not proven finished
        (TEST_NMAP_TCP_XML_FINISHED_ERROR, None),                          # run failed
        (TEST_NMAP_TCP_XML_HOST_DOWN, None),                                # host down
        (TEST_NMAP_TCP_XML_TIMEDOUT, None),                                 # host timed out
        (TEST_NMAP_TCP_XML_OMIT_PORTS, None),                              # no port table
        (TEST_NMAP_TCP_XML_DUPLICATE_PORT, None),                          # duplicate port
        (TEST_NMAP_TCP_XML_WRONG_SERVICES, None),                          # scaninfo services mismatch
        (TEST_NMAP_TCP_XML_EXTRA_HOST, None),                               # second host
        ("not xml <<<", None),                                               # malformed
    ], ids=[
        "complete-zero-open", "complete-open", "partial", "no-runstats",
        "finished-error", "host-down", "timedout", "no-ports",
        "duplicate-port", "wrong-services", "extra-host", "malformed",
    ])
    def test_monitor_acceptance_matches_the_authoritative_baseline_parser(self, xml, expected):
        from detect.tcp_scan import parse_sentinel_open_ports
        from sentinel.baseline import SENTINEL_TCP_PORTS
        assert parse_sentinel_open_ports(xml, "192.168.1.10", SENTINEL_TCP_PORTS) == expected
        obs = self._monitor(xml)
        assert obs.ports == expected
        assert obs.states is None if expected is None else obs.states is not None

    def test_wrong_scaninfo_services_is_refused_by_the_monitor(self):
        """_check_tcp_xml alone would accept it: the exact service-set gate must refuse it."""
        from detect.tcp_scan import parse_sentinel_open_ports
        from sentinel.baseline import SENTINEL_TCP_PORTS
        from sentinel.monitor import _get_host_tcp_observation
        xml = TEST_NMAP_TCP_XML_WRONG_SERVICES
        with patch("sentinel.monitor._tcp_run_nmap", return_value=xml):
            obs = _get_host_tcp_observation("192.168.1.10")
        assert parse_sentinel_open_ports(xml, "192.168.1.10", SENTINEL_TCP_PORTS) is None
        assert obs.ports is None
