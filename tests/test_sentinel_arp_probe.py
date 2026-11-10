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


NO_KNOWN = frozenset()


@pytest.fixture(autouse=True)
def _no_real_arp():
    """Monitor tests never send ARP traffic unless a test patches arp_probe itself."""
    with patch("sentinel.monitor.arp_probe",
               return_value=ArpProbeResult(ArpProbeStatus.ERROR, "0.0.0.0", error="test double")):
        yield


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
            check_network("192.168.1.0/24", "session", IDENTITY, BASELINE, NO_KNOWN)
    assert exc_info.value.observations.candidate_changes == []


def test_ping_failure_arp_present_tcp_failure_is_degraded():
    present = ArpProbeResult(ArpProbeStatus.PRESENT, "192.168.1.10", "11:22:33:44:55:66")
    with patch("sentinel.monitor._get_active_hosts", return_value=None), \
         patch("sentinel.monitor.arp_probe", return_value=present), \
         patch("sentinel.monitor._get_open_ports", return_value=None):
        with pytest.raises(ScanDegradedError):
            check_network("192.168.1.0/24", "session", IDENTITY, BASELINE, NO_KNOWN)


def test_ping_success_tcp_failure_is_degraded():
    with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
         patch("sentinel.monitor._get_arp_mac", return_value=""), \
         patch("sentinel.monitor._get_open_ports", return_value=None):
        with pytest.raises(ScanDegradedError) as exc_info:
            check_network("192.168.1.0/24", "session", IDENTITY, BASELINE, NO_KNOWN)
    assert exc_info.value.observations.candidate_changes == []


def test_ping_failure_arp_not_observed_is_not_host_removal():
    """T23-B §9.4: NOT_OBSERVED is an exploitable answer, so the cycle is degraded, not failed."""
    absent = ArpProbeResult(ArpProbeStatus.NOT_OBSERVED, "192.168.1.10")
    with patch("sentinel.monitor._get_active_hosts", return_value=None), \
         patch("sentinel.monitor.arp_probe", return_value=absent):
        with pytest.raises(ScanDegradedError) as exc_info:
            check_network("192.168.1.0/24", "session", IDENTITY, BASELINE, NO_KNOWN)
    observations = exc_info.value.observations
    assert observations.host_arp_status == {"192.168.1.10": ArpProbeStatus.NOT_OBSERVED}
    assert observations.current_hosts == []
    assert observations.candidate_changes == []


def test_ping_failure_arp_error_is_not_host_removal():
    error = ArpProbeResult(ArpProbeStatus.ERROR, "192.168.1.10", error="permission denied")
    with patch("sentinel.monitor._get_active_hosts", return_value=None), \
         patch("sentinel.monitor.arp_probe", return_value=error):
        with pytest.raises(ScanFailedError):
            check_network("192.168.1.0/24", "session", IDENTITY, BASELINE, NO_KNOWN)


def test_ping_discovery_new_host_still_comes_only_from_nmap():
    with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.99"]), \
         patch("sentinel.monitor._get_open_ports", return_value=[]), \
         patch("sentinel.monitor._get_arp_mac", return_value=""):
        changes = check_network("192.168.1.0/24", "session", IDENTITY, BASELINE, NO_KNOWN).candidate_changes
    assert [c.change_type for c in changes] == ["new_host"]
    assert changes[0].asset_ip == "192.168.1.99"


# ---------------------------------------------------------------------------
# T23-B §10.2 — ARP independent of ping, TCP observations, known hosts
# ---------------------------------------------------------------------------

def test_ping_ok_absent_host_arp_present_is_recovered_and_scanned_with_pn():
    present = ArpProbeResult(ArpProbeStatus.PRESENT, "192.168.1.10", "11:22:33:44:55:66")
    with patch("sentinel.monitor._get_active_hosts", return_value=[]), \
         patch("sentinel.monitor.arp_probe", return_value=present), \
         patch("sentinel.monitor._get_open_ports", return_value=[22]) as ports:
        obs = check_network("192.168.1.0/24", "session", IDENTITY, BASELINE, NO_KNOWN)
    assert obs.current_hosts == ["192.168.1.10"]
    assert obs.ping_hosts == []
    assert obs.tcp_observations["192.168.1.10"].ports == [22]
    ports.assert_called_once()
    assert ports.call_args.kwargs["skip_host_discovery"] is True


def test_ping_visible_host_is_scanned_without_pn():
    with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10"]), \
         patch("sentinel.monitor._get_open_ports", return_value=[22, 80]) as ports, \
         patch("sentinel.monitor._get_arp_mac", return_value="11:22:33:44:55:66"):
        check_network("192.168.1.0/24", "session", IDENTITY, BASELINE, NO_KNOWN)
    assert not ports.call_args.kwargs.get("skip_host_discovery", False)  # no -Pn for ping-visible hosts


def test_one_arp_probe_per_ip_per_cycle():
    calls = []

    def counting_probe(ip, *args, **kwargs):
        calls.append(ip)
        return ArpProbeResult(ArpProbeStatus.NOT_OBSERVED, ip)

    with patch("sentinel.monitor._get_active_hosts", return_value=[]), \
         patch("sentinel.monitor.arp_probe", side_effect=counting_probe), \
         patch("sentinel.monitor._get_open_ports", return_value=[]):
        check_network("192.168.1.0/24", "session", IDENTITY, BASELINE, {"192.168.1.10", "192.168.1.99"})
    # .10 is both a baseline and a known host: it is probed once, not twice.
    assert sorted(calls) == ["192.168.1.10", "192.168.1.99"]


def test_arp_not_observed_is_recorded_and_not_host_removal_when_ping_ok():
    absent = ArpProbeResult(ArpProbeStatus.NOT_OBSERVED, "192.168.1.10")
    with patch("sentinel.monitor._get_active_hosts", return_value=[]), \
         patch("sentinel.monitor.arp_probe", return_value=absent), \
         patch("sentinel.monitor._get_open_ports", return_value=[]):
        obs = check_network("192.168.1.0/24", "session", IDENTITY, BASELINE, NO_KNOWN)
    assert obs.host_arp_status == {"192.168.1.10": ArpProbeStatus.NOT_OBSERVED}
    assert obs.current_hosts == []
    assert obs.candidate_changes == []


def test_arp_error_is_recorded_without_degrading_ping_ok_cycle():
    error = ArpProbeResult(ArpProbeStatus.ERROR, "192.168.1.10", error="permission denied")
    with patch("sentinel.monitor._get_active_hosts", return_value=[]), \
         patch("sentinel.monitor.arp_probe", return_value=error), \
         patch("sentinel.monitor._get_open_ports", return_value=[]):
        obs = check_network("192.168.1.0/24", "session", IDENTITY, BASELINE, NO_KNOWN)
    assert obs.host_arp_status == {"192.168.1.10": ArpProbeStatus.ERROR}


def test_mixed_not_observed_and_error_when_ping_failed_is_degraded_with_observations():
    statuses = {
        "192.168.1.10": ArpProbeResult(ArpProbeStatus.NOT_OBSERVED, "192.168.1.10"),
        "192.168.1.20": ArpProbeResult(ArpProbeStatus.ERROR, "192.168.1.20", error="timeout"),
    }
    with patch("sentinel.monitor._get_active_hosts", return_value=None), \
         patch("sentinel.monitor.arp_probe", side_effect=lambda ip, *a, **k: statuses[ip]):
        with pytest.raises(ScanDegradedError) as exc_info:
            check_network("192.168.1.0/24", "session",
                          IDENTITY, {**BASELINE, "192.168.1.20": BASELINE["192.168.1.10"]}, NO_KNOWN)
    obs = exc_info.value.observations
    assert obs.host_arp_status["192.168.1.10"] is ArpProbeStatus.NOT_OBSERVED
    assert obs.host_arp_status["192.168.1.20"] is ArpProbeStatus.ERROR
    assert obs.current_hosts == []


def test_known_host_seen_by_ping_is_not_new_host_again():
    with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.99"]), \
         patch("sentinel.monitor._get_open_ports", return_value=[22]), \
         patch("sentinel.monitor._get_arp_mac", return_value=""):
        obs = check_network("192.168.1.0/24", "session", IDENTITY, BASELINE, {"192.168.1.99"})
    assert [c for c in obs.candidate_changes if c.change_type == "new_host"] == []


def test_new_host_carries_initial_ports_only_when_scan_complete():
    with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.99"]), \
         patch("sentinel.monitor._get_open_ports", return_value=[22, 80]), \
         patch("sentinel.monitor._get_arp_mac", return_value=""):
        obs = check_network("192.168.1.0/24", "session", IDENTITY, BASELINE, NO_KNOWN)
    (new_host,) = obs.candidate_changes
    assert new_host.change_type == "new_host"
    assert new_host.initial_ports == [22, 80] and new_host.initial_ports_known is True

    with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.99"]), \
         patch("sentinel.monitor._get_open_ports", return_value=None), \
         patch("sentinel.monitor._get_arp_mac", return_value=""):
        with pytest.raises(ScanDegradedError) as exc_info:
            check_network("192.168.1.0/24", "session", IDENTITY, BASELINE, NO_KNOWN)
    (new_host,) = [c for c in exc_info.value.observations.candidate_changes if c.change_type == "new_host"]
    assert new_host.initial_ports is None and new_host.initial_ports_known is False


def test_tcp_observation_exists_for_every_current_host():
    with patch("sentinel.monitor._get_active_hosts", return_value=["192.168.1.10", "192.168.1.99"]), \
         patch("sentinel.monitor._get_open_ports", side_effect=lambda ip, **k: [22]), \
         patch("sentinel.monitor._get_arp_mac", return_value="11:22:33:44:55:66"):
        obs = check_network("192.168.1.0/24", "session", IDENTITY, BASELINE, NO_KNOWN)
    assert set(obs.tcp_observations) == {"192.168.1.10", "192.168.1.99"}
    assert all(item.ports == [22] for item in obs.tcp_observations.values())
