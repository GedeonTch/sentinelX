"""Tests for the targeted active ARP probe and its monitor integration."""

import sys
import types
from unittest.mock import MagicMock, patch

import pytest

from sentinel.arp_probe import ArpProbeStatus, ArpProbeResult, arp_probe
from sentinel.baseline import BaselineEntry, NetworkIdentity
from sentinel.monitor import (
    NetworkChange,
    ScanDegradedError,
    ScanFailedError,
    check_network,
)


IDENTITY = NetworkIdentity("192.168.1.0/24", "192.168.1.1", "aa:aa:aa:aa:aa:aa")
BASELINE = {
    "192.168.1.10": BaselineEntry(
        asset_id="a1", ip="192.168.1.10", mac="11:22:33:44:55:66",
        ports=[22], last_scan="2026-01-01T00:00:00+00:00",
    ),
}


def test_arp_probe_rejects_cidr_without_importing_scapy():
    result = arp_probe("192.168.1.0/24")
    assert result.status is ArpProbeStatus.ERROR
    assert "invalid IP" in result.error


def test_arp_probe_reports_scapy_missing(monkeypatch):
    real_import = __import__

    def missing_scapy(name, *args, **kwargs):
        if name == "scapy.all":
            raise ImportError("no scapy")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", missing_scapy)
    result = arp_probe("192.168.1.10")
    assert result.status is ArpProbeStatus.ERROR
    assert "Scapy unavailable" in result.error


def test_arp_probe_reports_permission_error(monkeypatch):
    fake_scapy = types.ModuleType("scapy.all")
    class Packet:
        def __truediv__(self, other):
            return self
    fake_scapy.Ether = lambda **kwargs: Packet()
    fake_scapy.ARP = lambda **kwargs: Packet()

    def denied(*args, **kwargs):
        raise PermissionError("raw socket denied")

    fake_scapy.srp = denied
    monkeypatch.setitem(sys.modules, "scapy.all", fake_scapy)
    result = arp_probe("192.168.1.10")
    assert result.status is ArpProbeStatus.ERROR
    assert "ARP probe failed" in result.error


def test_arp_probe_reports_invalid_interface(monkeypatch):
    fake_scapy = types.ModuleType("scapy.all")
    class Packet:
        def __truediv__(self, other):
            return self
    fake_scapy.Ether = lambda **kwargs: Packet()
    fake_scapy.ARP = lambda **kwargs: Packet()
    fake_scapy.srp = lambda *args, **kwargs: (_ for _ in ()).throw(OSError("No such device"))
    monkeypatch.setitem(sys.modules, "scapy.all", fake_scapy)
    result = arp_probe("192.168.1.10", interface="missing0")
    assert result.status is ArpProbeStatus.ERROR
    assert "ARP probe failed" in result.error


def test_arp_probe_reports_not_observed(monkeypatch):
    fake_scapy = types.ModuleType("scapy.all")
    class Packet:
        def __truediv__(self, other):
            return self
    fake_scapy.Ether = lambda **kwargs: Packet()
    fake_scapy.ARP = lambda **kwargs: Packet()
    fake_scapy.srp = lambda *args, **kwargs: ([], [])
    monkeypatch.setitem(sys.modules, "scapy.all", fake_scapy)
    result = arp_probe("192.168.1.10")
    assert result.status is ArpProbeStatus.NOT_OBSERVED
    assert result.mac is None


def test_arp_probe_reports_present_and_mac(monkeypatch):
    fake_scapy = types.ModuleType("scapy.all")
    class Packet:
        def __truediv__(self, other):
            return self
    class Received:
        psrc = "192.168.1.10"
        hwsrc = "AA:BB:CC:DD:EE:FF"
    fake_scapy.Ether = lambda **kwargs: Packet()
    fake_scapy.ARP = lambda **kwargs: Packet()
    fake_scapy.srp = lambda *args, **kwargs: ([(None, Received())], [])
    monkeypatch.setitem(sys.modules, "scapy.all", fake_scapy)
    result = arp_probe("192.168.1.10")
    assert result == ArpProbeResult(
        ArpProbeStatus.PRESENT, "192.168.1.10", "aa:bb:cc:dd:ee:ff"
    )


def test_ping_failure_arp_present_tcp_success_is_degraded_without_new_host():
    present = ArpProbeResult(ArpProbeStatus.PRESENT, "192.168.1.10", "11:22:33:44:55:66")
    with patch("sentinel.monitor._get_active_hosts", return_value=None), \
         patch("sentinel.monitor.arp_probe", return_value=present), \
         patch("sentinel.monitor._get_open_ports", return_value=[22]):
        with pytest.raises(ScanDegradedError) as exc_info:
            check_network("192.168.1.0/24", "session", IDENTITY, BASELINE)
    assert exc_info.value.changes == []


def test_ping_failure_arp_present_tcp_failure_is_degraded():
    present = ArpProbeResult(ArpProbeStatus.PRESENT, "192.168.1.10", "11:22:33:44:55:66")
    with patch("sentinel.monitor._get_active_hosts", return_value=None), \
         patch("sentinel.monitor.arp_probe", return_value=present), \
         patch("sentinel.monitor._get_open_ports", return_value=None):
        with pytest.raises(ScanDegradedError):
            check_network("192.168.1.0/24", "session", IDENTITY, BASELINE)


def test_ping_success_tcp_failure_is_degraded():
    with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
         patch("sentinel.monitor._get_arp_mac", return_value=""), \
         patch("sentinel.monitor._get_open_ports", return_value=None):
        with pytest.raises(ScanDegradedError) as exc_info:
            check_network("192.168.1.0/24", "session", IDENTITY, BASELINE)
    assert exc_info.value.changes == []


def test_ping_failure_arp_not_observed_is_not_host_removal():
    absent = ArpProbeResult(ArpProbeStatus.NOT_OBSERVED, "192.168.1.10")
    with patch("sentinel.monitor._get_active_hosts", return_value=None), \
         patch("sentinel.monitor.arp_probe", return_value=absent):
        with pytest.raises(ScanFailedError):
            check_network("192.168.1.0/24", "session", IDENTITY, BASELINE)


def test_ping_failure_arp_error_is_not_host_removal():
    error = ArpProbeResult(ArpProbeStatus.ERROR, "192.168.1.10", error="permission denied")
    with patch("sentinel.monitor._get_active_hosts", return_value=None), \
         patch("sentinel.monitor.arp_probe", return_value=error):
        with pytest.raises(ScanFailedError):
            check_network("192.168.1.0/24", "session", IDENTITY, BASELINE)


def test_ping_discovery_new_host_still_comes_only_from_nmap():
    with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.99"]), \
         patch("sentinel.monitor._get_open_ports", return_value=[]), \
         patch("sentinel.monitor._get_arp_mac", return_value=""):
        changes = check_network("192.168.1.0/24", "session", IDENTITY, BASELINE)
    assert [c.change_type for c in changes] == ["new_host"]
    assert changes[0].asset_ip == "192.168.1.99"
