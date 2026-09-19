"""
tests/test_sentinel_monitor.py — Unit tests for sentinel/monitor.py

Covers: new_host, new_port, mac_change detection.
        removed_host: NOT detected (out of scope V1).
        All network calls mocked.
"""

import pytest
from unittest.mock import patch

from sentinel.baseline import BaselineEntry, NetworkIdentity
from sentinel.monitor import NetworkChange, check_network, ScanFailedError

IDENTITY = NetworkIdentity("192.168.1.0/24", "192.168.1.1", "aa:aa:aa:aa:aa:aa")
SESSION = "session-monitor-test"

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
             patch("sentinel.monitor._get_open_ports", return_value=[22]), \
             patch("sentinel.monitor._get_arp_mac", return_value=""):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE)
        new_hosts = [c for c in changes if c.change_type == "new_host"]
        assert len(new_hosts) == 1
        assert new_hosts[0].asset_ip == "192.168.1.99"

    def test_no_new_host_when_all_known(self):
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
             patch("sentinel.monitor._get_open_ports", return_value=[22, 80]), \
             patch("sentinel.monitor._get_arp_mac", return_value="11:22:33:44:55:66"):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE)
        new_hosts = [c for c in changes if c.change_type == "new_host"]
        assert new_hosts == []


class TestNewPort:
    def test_new_port_detected(self):
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
             patch("sentinel.monitor._get_open_ports", return_value=[22, 80, 4444]), \
             patch("sentinel.monitor._get_arp_mac", return_value="11:22:33:44:55:66"):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE)
        new_ports = [c for c in changes if c.change_type == "new_port"]
        assert len(new_ports) == 1
        assert "4444" in new_ports[0].detail

    def test_no_new_port_when_ports_match(self):
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
             patch("sentinel.monitor._get_open_ports", return_value=[22, 80]), \
             patch("sentinel.monitor._get_arp_mac", return_value="11:22:33:44:55:66"):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE)
        new_ports = [c for c in changes if c.change_type == "new_port"]
        assert new_ports == []

    def test_multiple_new_ports(self):
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
             patch("sentinel.monitor._get_open_ports", return_value=[22, 80, 3389, 4444]), \
             patch("sentinel.monitor._get_arp_mac", return_value=""):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE)
        new_ports = [c for c in changes if c.change_type == "new_port"]
        assert len(new_ports) == 2


class TestMacChange:
    def test_mac_change_detected(self):
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
             patch("sentinel.monitor._get_open_ports", return_value=[22, 80]), \
             patch("sentinel.monitor._get_arp_mac", return_value="ff:ff:ff:ff:ff:ff"):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE)
        mac_changes = [c for c in changes if c.change_type == "mac_change"]
        assert len(mac_changes) == 1
        assert mac_changes[0].asset_ip == "192.168.1.10"

    def test_no_mac_change_when_mac_matches(self):
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
             patch("sentinel.monitor._get_open_ports", return_value=[22, 80]), \
             patch("sentinel.monitor._get_arp_mac", return_value="11:22:33:44:55:66"):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE)
        mac_changes = [c for c in changes if c.change_type == "mac_change"]
        assert mac_changes == []

    def test_no_mac_change_when_baseline_mac_empty(self):
        """If baseline has no MAC, we cannot detect a change."""
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.20"]), \
             patch("sentinel.monitor._get_open_ports", return_value=[443]), \
             patch("sentinel.monitor._get_arp_mac", return_value="aa:bb:cc:dd:ee:ff"):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE)
        mac_changes = [c for c in changes if c.change_type == "mac_change"]
        assert mac_changes == []


class TestRemovedHostOutOfScope:
    def test_removed_host_not_reported(self):
        """A host in baseline that goes offline must NOT produce a change."""
        with patch("sentinel.monitor._get_active_hosts", return_value=[]), \
             patch("sentinel.monitor._get_open_ports", return_value=[]), \
             patch("sentinel.monitor._get_arp_mac", return_value=""):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE)
        assert changes == []


class TestMonitorEdgeCases:
    def test_empty_baseline_only_new_hosts(self):
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
             patch("sentinel.monitor._get_open_ports", return_value=[22]), \
             patch("sentinel.monitor._get_arp_mac", return_value=""):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, {})
        new_hosts = [c for c in changes if c.change_type == "new_host"]
        assert len(new_hosts) == 1

    def test_ping_scan_failure_returns_empty(self):
        """A failed ping scan must raise ScanFailedError, not return []."""
        import pytest
        with patch("sentinel.monitor._get_active_hosts", return_value=None):
            with pytest.raises(ScanFailedError):
                check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE)

    def test_evidence_not_empty(self):
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.99"]), \
             patch("sentinel.monitor._get_open_ports", return_value=[]), \
             patch("sentinel.monitor._get_arp_mac", return_value=""):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE)
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
                check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE)

    def test_ping_success_empty_network_returns_empty_list(self):
        """[] from _get_active_hosts → empty changes, no exception."""
        with patch("sentinel.monitor._get_active_hosts", return_value=[]), \
             patch("sentinel.monitor._get_open_ports", return_value=[]), \
             patch("sentinel.monitor._get_arp_mac", return_value=""):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE)
        assert changes == []

    def test_port_scan_failure_skips_host_silently(self):
        """None from _get_open_ports → host skipped, no new_port change reported."""
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
             patch("sentinel.monitor._get_open_ports", return_value=None), \
             patch("sentinel.monitor._get_arp_mac", return_value="11:22:33:44:55:66"):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE)
        new_ports = [c for c in changes if c.change_type == "new_port"]
        assert new_ports == []

    def test_port_scan_empty_result_reports_no_new_ports(self):
        """[] from _get_open_ports → scan succeeded, no new ports."""
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
             patch("sentinel.monitor._get_open_ports", return_value=[]), \
             patch("sentinel.monitor._get_arp_mac", return_value="11:22:33:44:55:66"):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE)
        # Baseline has ports [22, 80], scan returns [] → ports 22 and 80 disappeared
        # but removed_host/port is out of scope V1 → no changes
        new_ports = [c for c in changes if c.change_type == "new_port"]
        assert new_ports == []

    def test_port_scan_new_port_detected_when_scan_succeeds(self):
        """[22, 80, 4444] from _get_open_ports → new_port for 4444."""
        with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
             patch("sentinel.monitor._get_open_ports", return_value=[22, 80, 4444]), \
             patch("sentinel.monitor._get_arp_mac", return_value="11:22:33:44:55:66"):
            changes = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE)
        new_ports = [c for c in changes if c.change_type == "new_port"]
        assert len(new_ports) == 1
        assert "4444" in new_ports[0].detail

    def test_scan_failed_error_is_distinct_from_empty_changes(self):
        """ScanFailedError and [] are two distinct outcomes."""
        import pytest
        # ScanFailedError on ping failure
        with patch("sentinel.monitor._get_active_hosts", return_value=None):
            with pytest.raises(ScanFailedError):
                check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE)

        # [] on successful scan with no changes
        with patch("sentinel.monitor._get_active_hosts", return_value=[]), \
             patch("sentinel.monitor._get_open_ports", return_value=[]), \
             patch("sentinel.monitor._get_arp_mac", return_value=""):
            result = check_network("192.168.1.0/24", SESSION, IDENTITY, BASELINE)
        assert result == []  # no exception, empty list
