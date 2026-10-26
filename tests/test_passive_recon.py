"""
tests/test_passive_recon.py — Unit tests for recon/passive_recon.py

Strategy:
- ZERO system calls: subprocess.run is replaced by a fake, /etc/hosts is a tmp file.
- Covers: network filter (P1), arp/ip neigh parsing and fallback, hosts file,
  avahi field order and grouping (P2), mDNS consent gate, per-source statuses.
"""

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from core.finding import Confidence, Exposure
from recon.passive_recon import (
    MDNS_COMMAND,
    SOURCE_ARP,
    SOURCE_HOSTS,
    SOURCE_MDNS,
    STATUS_FAILED,
    STATUS_OK,
    STATUS_SKIPPED,
    STATUS_UNAVAILABLE,
    _in_filter,
    _parse_arp_output,
    _parse_avahi_output,
    _parse_ip_neigh_output,
    _read_hosts_file,
    collect_passive,
    parse_network_filter,
    passive_recon,
)


def fake_run(outputs):
    """Build a subprocess.run fake. Missing tools raise FileNotFoundError.

    outputs maps the executable name to: a stdout string (exit 0), a
    (returncode, stdout) tuple, or an exception instance to raise.
    """
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        name = cmd[0]
        if name not in outputs:
            raise FileNotFoundError(name)
        value = outputs[name]
        if isinstance(value, BaseException):
            raise value
        if isinstance(value, tuple):
            code, stdout = value
        else:
            code, stdout = 0, value
        return subprocess.CompletedProcess(cmd, code, stdout=stdout, stderr="")

    run.calls = calls
    return run


ARP_OUT = """\
Address                  HWtype  HWaddress           Flags Mask            Iface
192.168.1.1              ether   aa:bb:cc:dd:ee:01   C                     eth0
192.168.1.9              (incomplete)                                      eth0
192.168.1.7              ether   ff:ff:ff:ff:ff:ff   C                     eth0
192.168.10.5             ether   aa:bb:cc:dd:ee:05   C                     eth0
"""

IP_NEIGH_OUT = """\
192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE
192.168.1.2 dev eth0  FAILED
192.168.1.3 dev eth0 lladdr aa:bb:cc:dd:ee:03 STALE
"""

AVAHI_OUT = (
    "=;eth0;IPv4;My\\032Printer;_ipp._tcp;local;printer.local;192.168.1.50;631;\n"
    "=;eth0;IPv4;My\\032Printer;_http._tcp;local;printer.local;192.168.1.50;80;\n"
    "=;eth0;IPv6;MyPrinter;_ipp._tcp;local;printer.local;fe80::1;631;\n"
    "+;eth0;IPv4;Unresolved;_ssh._tcp;local\n"
    "=;incomplete\n"
)


@pytest.fixture
def hosts_file(tmp_path) -> Path:
    path = tmp_path / "hosts"
    path.write_text(
        "127.0.0.1 localhost\n"
        "192.168.1.10 nas.lan # file server\n"
        "192.168.1.10 backup.lan\n"
        "::1 localhost6\n"
        "fe80::5 v6host.lan\n"
        "10.0.0.8 router.lan\n",
        encoding="utf-8",
    )
    return path


# ---------------------------------------------------------------------------
# P1 — network filter
# ---------------------------------------------------------------------------

class TestNetworkFilter:
    def test_cidr_is_respected(self):
        network = parse_network_filter("192.168.1.0/24")
        assert _in_filter("192.168.1.50", network)
        assert not _in_filter("192.168.2.50", network)

    def test_legacy_prefix_does_not_match_neighbouring_octet(self):
        """Regression: startswith('192.168.1') wrongly accepted 192.168.10.5."""
        network = parse_network_filter("192.168.1")
        assert _in_filter("192.168.1.5", network)
        assert not _in_filter("192.168.10.5", network)

    def test_single_address_and_empty_filter(self):
        assert _in_filter("10.0.0.1", parse_network_filter("10.0.0.1"))
        assert not _in_filter("10.0.0.2", parse_network_filter("10.0.0.1"))
        assert parse_network_filter("") is None
        assert parse_network_filter("   ") is None
        assert _in_filter("8.8.8.8", None)

    @pytest.mark.parametrize("value", [
        "192.168.1.5/24",   # host bits set
        "192.168.1.300",    # octet out of range
        "10.0.0.0/33",      # bad prefix
        "192.168.1.0/",     # truncated
        "abc",              # not an address
        "fe80::/10",        # IPv6 is not a filter target
        "::1",
    ])
    def test_invalid_values_are_rejected(self, value):
        with pytest.raises(ValueError):
            parse_network_filter(value)

    def test_ipv6_addresses_never_match(self):
        assert not _in_filter("fe80::1", None)
        assert not _in_filter("2001:db8::1", parse_network_filter("10.0.0.0/8"))


# ---------------------------------------------------------------------------
# ARP / neighbour cache parsing
# ---------------------------------------------------------------------------

class TestNeighbourParsing:
    def test_arp_parses_complete_entries_only(self):
        entries = _parse_arp_output(ARP_OUT)
        assert entries == [
            ("192.168.1.1", "aa:bb:cc:dd:ee:01", ""),
            ("192.168.10.5", "aa:bb:cc:dd:ee:05", ""),
        ]

    def test_ip_neigh_keeps_state_and_skips_failed(self):
        entries = _parse_ip_neigh_output(IP_NEIGH_OUT)
        assert ("192.168.1.1", "aa:bb:cc:dd:ee:01", "REACHABLE") in entries
        assert ("192.168.1.3", "aa:bb:cc:dd:ee:03", "STALE") in entries
        assert all(ip != "192.168.1.2" for ip, _, _ in entries)


class TestArpSource:
    def test_arp_findings_are_probable_and_say_presence_not_proven(self):
        run = fake_run({"arp": ARP_OUT})
        with patch("recon.passive_recon.subprocess.run", side_effect=run):
            report = collect_passive("192.168.1", "s1", hosts_path=Path("/nonexistent-hosts"))
        arp = next(s for s in report.sources if s.name == SOURCE_ARP)
        assert arp.status == STATUS_OK and arp.count == 1
        arp_findings = [f for f in report.findings if f.target_service == "arp"]
        assert [f.target_ip for f in arp_findings] == ["192.168.1.1"]
        assert arp_findings[0].confidence == Confidence.PROBABLE
        assert "présence actuelle non prouvée" in arp_findings[0].evidence.raw

    def test_falls_back_to_ip_neigh_when_arp_missing(self):
        run = fake_run({"ip": IP_NEIGH_OUT})
        with patch("recon.passive_recon.subprocess.run", side_effect=run):
            report = collect_passive("", "s1", hosts_path=Path("/nonexistent-hosts"))
        arp = next(s for s in report.sources if s.name == SOURCE_ARP)
        assert arp.status == STATUS_OK
        assert arp.detail == "arp absent : repli sur ip neigh"
        assert any(f.evidence.command == "ip -4 neigh show" for f in report.findings)

    def test_no_arp_and_no_ip_is_unavailable_not_empty(self):
        run = fake_run({})
        with patch("recon.passive_recon.subprocess.run", side_effect=run):
            report = collect_passive("", "s1", hosts_path=Path("/nonexistent-hosts"))
        arp = next(s for s in report.sources if s.name == SOURCE_ARP)
        assert arp.status == STATUS_UNAVAILABLE
        assert all(f.target_service != "arp" for f in report.findings)

    def test_arp_timeout_is_failed(self):
        run = fake_run({"arp": subprocess.TimeoutExpired(["arp", "-n"], 10)})
        with patch("recon.passive_recon.subprocess.run", side_effect=run):
            report = collect_passive("", "s1", hosts_path=Path("/nonexistent-hosts"))
        arp = next(s for s in report.sources if s.name == SOURCE_ARP)
        assert arp.status == STATUS_FAILED


# ---------------------------------------------------------------------------
# /etc/hosts
# ---------------------------------------------------------------------------

class TestHostsSource:
    def test_duplicate_ip_lines_are_all_kept(self, hosts_file):
        pairs, _ = _read_hosts_file(hosts_file)
        assert ("192.168.1.10", "nas.lan") in pairs
        assert ("192.168.1.10", "backup.lan") in pairs

    def test_ipv6_lines_are_counted_not_targeted(self, hosts_file):
        pairs, ignored_v6 = _read_hosts_file(hosts_file)
        assert ignored_v6 == 2  # ::1 and fe80::5
        assert all(":" not in ip for ip, _ in pairs)

    def test_comments_and_loopback_are_handled(self, hosts_file):
        report = collect_passive("", "s1", hosts_path=hosts_file)
        hosts = [f for f in report.findings if f.target_service == "hosts"]
        ips = sorted(f.target_ip for f in hosts)
        assert ips == ["10.0.0.8", "192.168.1.10", "192.168.1.10"]
        assert all(f.exposure == Exposure.INTERNAL for f in hosts)

    def test_filter_applies_to_hosts(self, hosts_file):
        report = collect_passive("192.168.1", "s1", hosts_path=hosts_file)
        hosts = [f for f in report.findings if f.target_service == "hosts"]
        assert {f.target_ip for f in hosts} == {"192.168.1.10"}

    def test_missing_hosts_file_is_unavailable(self, tmp_path):
        report = collect_passive("", "s1", hosts_path=tmp_path / "absent")
        hosts = next(s for s in report.sources if s.name == SOURCE_HOSTS)
        assert hosts.status == STATUS_UNAVAILABLE


# ---------------------------------------------------------------------------
# P2 — avahi / mDNS parsing
# ---------------------------------------------------------------------------

class TestAvahiParsing:
    def test_field_order_host_address_port_from_documented_positions(self):
        """Regression: service name (index 3) was taken as the host."""
        records, _ = _parse_avahi_output(AVAHI_OUT)
        first = records[0]
        assert first.service == "My Printer"
        assert first.service_type == "_ipp._tcp"
        assert first.host == "printer.local"
        assert first.address == "192.168.1.50"
        assert first.port == 631

    def test_ipv6_is_counted_and_ignored(self):
        records, ignored_v6 = _parse_avahi_output(AVAHI_OUT)
        assert ignored_v6 == 1
        assert all(r.address != "fe80::1" for r in records)

    def test_unresolved_and_malformed_lines_are_ignored(self):
        records, _ = _parse_avahi_output(AVAHI_OUT)
        assert all(r.service != "Unresolved" for r in records)
        assert _parse_avahi_output("=;incomplete\n") == ([], 0)

    def test_several_services_on_one_host_do_not_overwrite(self):
        run = fake_run({"avahi-browse": AVAHI_OUT})
        with patch("recon.passive_recon.subprocess.run", side_effect=run):
            report = collect_passive("", "s1", mdns_allowed=True, hosts_path=Path("/nonexistent-hosts"))
        mdns = [f for f in report.findings if f.target_service == "mdns"]
        assert len(mdns) == 1
        assert "_ipp._tcp" in mdns[0].evidence.raw and "_http._tcp" in mdns[0].evidence.raw
        assert mdns[0].service_version == "hostname=printer.local"
        assert mdns[0].confidence == Confidence.POSSIBLE

    def test_two_addresses_for_one_host_are_both_kept(self):
        out = (
            "=;eth0;IPv4;Svc;_ipp._tcp;local;printer.local;192.168.1.50;631;\n"
            "=;eth0;IPv4;Svc;_ipp._tcp;local;printer.local;192.168.1.51;631;\n"
        )
        run = fake_run({"avahi-browse": out})
        with patch("recon.passive_recon.subprocess.run", side_effect=run):
            report = collect_passive("", "s1", mdns_allowed=True, hosts_path=Path("/nonexistent-hosts"))
        assert sorted(f.target_ip for f in report.findings if f.target_service == "mdns") == [
            "192.168.1.50", "192.168.1.51",
        ]


# ---------------------------------------------------------------------------
# mDNS consent gate and source statuses
# ---------------------------------------------------------------------------

class TestMdnsGate:
    def test_default_never_runs_avahi(self, hosts_file):
        run = fake_run({"avahi-browse": AVAHI_OUT, "arp": ARP_OUT})
        with patch("recon.passive_recon.subprocess.run", side_effect=run):
            report = collect_passive("", "s1", hosts_path=hosts_file)
        assert all(cmd[0] != "avahi-browse" for cmd in run.calls)
        mdns = next(s for s in report.sources if s.name == SOURCE_MDNS)
        assert mdns.status == STATUS_SKIPPED
        assert "non lancé" in mdns.detail

    def test_passive_recon_wrapper_never_runs_avahi_by_default(self, hosts_file):
        run = fake_run({"avahi-browse": AVAHI_OUT})
        with patch("recon.passive_recon.subprocess.run", side_effect=run):
            findings = passive_recon("", "s1")
        assert all(cmd[0] != "avahi-browse" for cmd in run.calls)
        assert all(f.target_service != "mdns" for f in findings)

    def test_avahi_missing_with_consent_is_explicit_not_empty(self, hosts_file):
        run = fake_run({})
        with patch("recon.passive_recon.subprocess.run", side_effect=run):
            report = collect_passive("", "s1", mdns_allowed=True, hosts_path=hosts_file)
        mdns = next(s for s in report.sources if s.name == SOURCE_MDNS)
        assert mdns.status == STATUS_UNAVAILABLE
        assert mdns.detail == "avahi-browse absent"
        assert all(f.target_service != "mdns" for f in report.findings)

    def test_avahi_nonzero_exit_is_failed(self, hosts_file):
        run = fake_run({"avahi-browse": (1, "")})
        with patch("recon.passive_recon.subprocess.run", side_effect=run):
            report = collect_passive("", "s1", mdns_allowed=True, hosts_path=hosts_file)
        mdns = next(s for s in report.sources if s.name == SOURCE_MDNS)
        assert mdns.status == STATUS_FAILED

    def test_avahi_timeout_is_failed(self, hosts_file):
        run = fake_run({"avahi-browse": subprocess.TimeoutExpired(list(MDNS_COMMAND), 20)})
        with patch("recon.passive_recon.subprocess.run", side_effect=run):
            report = collect_passive("", "s1", mdns_allowed=True, hosts_path=hosts_file)
        mdns = next(s for s in report.sources if s.name == SOURCE_MDNS)
        assert mdns.status == STATUS_FAILED

    def test_mdns_command_is_passive_listing_not_active_scan(self):
        assert MDNS_COMMAND[0] == "avahi-browse"
        assert "--all" in MDNS_COMMAND and "--parsable" in MDNS_COMMAND
        assert not any("scan" in part for part in MDNS_COMMAND)

    def test_invalid_network_is_rejected_before_any_command(self, hosts_file):
        run = fake_run({"arp": ARP_OUT})
        with patch("recon.passive_recon.subprocess.run", side_effect=run):
            with pytest.raises(ValueError):
                collect_passive("192.168.1.5/24", "s1", hosts_path=hosts_file)
        assert run.calls == []
