"""
tests/test_passive_recon.py — Unit tests for recon/passive_recon.py

Strategy:
- ZERO real system calls — subprocess and file reads are always mocked
- Tests cover: ARP parsing, hosts file parsing, avahi parsing,
  network prefix filtering, loopback exclusion, incomplete ARP entries,
  Finding invariants (risk_score=None, explanation=None, confidence rules)
"""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from core.finding import (
    Finding,
    Category,
    Severity,
    Confidence,
    Exposure,
    FindingStatus,
)
from recon.passive_recon import (
    passive_recon,
    _arp_table,
    _parse_arp_output,
    _arp_findings,
    _read_hosts_file,
    _hosts_file_findings,
    _mdns_lookup,
    _parse_avahi_output,
    _mdns_findings,
)


# ---------------------------------------------------------------------------
# Fixtures — static test data
# ---------------------------------------------------------------------------

ARP_OUTPUT_VALID = """\
Address                  HWtype  HWaddress           Flags Mask            Iface
192.168.1.1              ether   aa:bb:cc:dd:ee:01   C                     enp0s25
192.168.1.26             ether   aa:bb:cc:dd:ee:02   C                     enp0s25
192.168.1.99             ether   (incomplete)         C                     enp0s25
"""

ARP_OUTPUT_WITH_BROADCAST = """\
192.168.1.1              ether   aa:bb:cc:dd:ee:01   C                     enp0s25
192.168.1.255            ether   ff:ff:ff:ff:ff:ff   C                     enp0s25
"""

ARP_OUTPUT_EMPTY = "Address   HWtype  HWaddress\n"

HOSTS_CONTENT = """\
# This is a comment
127.0.0.1   localhost
127.0.1.1   mymachine
::1         localhost ip6-localhost

192.168.1.10    lab-server lab-server.local
192.168.1.20    win-dc
"""

AVAHI_OUTPUT = """\
+;eth0;IPv4;MyPrinter;_ipp._tcp;local
=;eth0;IPv4;MyPrinter;_ipp._tcp;local;myprinter.local;192.168.1.50;631;
=;eth0;IPv4;MacBook;_afpovertcp._tcp;local;macbook.local;192.168.1.60;548;
+;eth0;IPv4;Unresolved;_ssh._tcp;local
"""

AVAHI_OUTPUT_EMPTY = ""


# ---------------------------------------------------------------------------
# _parse_arp_output
# ---------------------------------------------------------------------------

class TestParseArpOutput:
    def test_parses_two_valid_entries(self):
        result = _parse_arp_output(ARP_OUTPUT_VALID)
        assert "192.168.1.1" in result
        assert result["192.168.1.1"] == "aa:bb:cc:dd:ee:01"
        assert "192.168.1.26" in result

    def test_incomplete_entry_not_parsed(self):
        """'(incomplete)' MAC does not match the regex — correctly excluded."""
        result = _parse_arp_output(ARP_OUTPUT_VALID)
        assert "192.168.1.99" not in result

    def test_empty_output_returns_empty_dict(self):
        result = _parse_arp_output(ARP_OUTPUT_EMPTY)
        assert result == {}

    def test_empty_string_returns_empty_dict(self):
        result = _parse_arp_output("")
        assert result == {}

    def test_mac_stored_in_lowercase(self):
        output = "192.168.1.1   ether   AA:BB:CC:DD:EE:FF   C   eth0\n"
        result = _parse_arp_output(output)
        assert result["192.168.1.1"] == "aa:bb:cc:dd:ee:ff"


# ---------------------------------------------------------------------------
# _arp_table
# ---------------------------------------------------------------------------

class TestArpTable:
    def test_calls_arp_n(self):
        mock_result = MagicMock()
        mock_result.stdout = ARP_OUTPUT_VALID
        with patch("recon.passive_recon.subprocess.run", return_value=mock_result) as mock_run:
            _arp_table()
        cmd = mock_run.call_args[0][0]
        assert "arp" in cmd
        assert "-n" in cmd

    def test_returns_empty_on_exception(self):
        with patch("recon.passive_recon.subprocess.run",
                   side_effect=Exception("arp not found")):
            result = _arp_table()
        assert result == {}


# ---------------------------------------------------------------------------
# _arp_findings
# ---------------------------------------------------------------------------

class TestArpFindings:
    def test_returns_findings_for_matching_prefix(self):
        with patch("recon.passive_recon._arp_table",
                   return_value={"192.168.1.1": "aa:bb:cc:dd:ee:01",
                                 "192.168.1.26": "aa:bb:cc:dd:ee:02"}):
            findings = _arp_findings("192.168.1", "session-test")

        assert len(findings) == 2

    def test_filters_by_network_prefix(self):
        with patch("recon.passive_recon._arp_table",
                   return_value={"192.168.1.1": "aa:bb:cc:dd:ee:01",
                                 "10.0.0.1": "ff:ee:dd:cc:bb:aa"}):
            findings = _arp_findings("192.168.1", "session-test")

        assert len(findings) == 1
        assert findings[0].target_ip == "192.168.1.1"

    def test_empty_prefix_returns_all(self):
        with patch("recon.passive_recon._arp_table",
                   return_value={"192.168.1.1": "aa:bb:cc:dd:ee:01",
                                 "10.0.0.1": "ff:ee:dd:cc:bb:aa"}):
            findings = _arp_findings("", "session-test")

        assert len(findings) == 2

    def test_excludes_broadcast_mac(self):
        with patch("recon.passive_recon._arp_table",
                   return_value={"192.168.1.255": "ff:ff:ff:ff:ff:ff"}):
            findings = _arp_findings("192.168.1", "session-test")

        assert findings == []

    def test_excludes_incomplete_entries(self):
        with patch("recon.passive_recon._arp_table",
                   return_value={"192.168.1.99": "(incomplete)"}):
            findings = _arp_findings("192.168.1", "session-test")

        assert findings == []

    def test_finding_confidence_is_confirmed(self):
        with patch("recon.passive_recon._arp_table",
                   return_value={"192.168.1.1": "aa:bb:cc:dd:ee:01"}):
            findings = _arp_findings("192.168.1", "session-test")

        assert findings[0].confidence == Confidence.CONFIRMED

    def test_finding_module_is_passive_recon(self):
        with patch("recon.passive_recon._arp_table",
                   return_value={"192.168.1.1": "aa:bb:cc:dd:ee:01"}):
            findings = _arp_findings("192.168.1", "session-test")

        assert findings[0].module == "passive_recon"

    def test_finding_category_is_network(self):
        with patch("recon.passive_recon._arp_table",
                   return_value={"192.168.1.1": "aa:bb:cc:dd:ee:01"}):
            findings = _arp_findings("192.168.1", "session-test")

        assert findings[0].category == Category.NETWORK

    def test_finding_risk_score_is_none(self):
        with patch("recon.passive_recon._arp_table",
                   return_value={"192.168.1.1": "aa:bb:cc:dd:ee:01"}):
            findings = _arp_findings("192.168.1", "session-test")

        assert findings[0].risk_score is None

    def test_finding_explanation_is_none(self):
        with patch("recon.passive_recon._arp_table",
                   return_value={"192.168.1.1": "aa:bb:cc:dd:ee:01"}):
            findings = _arp_findings("192.168.1", "session-test")

        assert findings[0].explanation is None

    def test_finding_evidence_contains_mac(self):
        with patch("recon.passive_recon._arp_table",
                   return_value={"192.168.1.1": "aa:bb:cc:dd:ee:01"}):
            findings = _arp_findings("192.168.1", "session-test")

        assert "aa:bb:cc:dd:ee:01" in findings[0].evidence.raw


# ---------------------------------------------------------------------------
# _read_hosts_file
# ---------------------------------------------------------------------------

class TestReadHostsFile:
    def test_parses_valid_hosts_file(self, tmp_path):
        hosts = tmp_path / "hosts"
        hosts.write_text(HOSTS_CONTENT)
        result = _read_hosts_file(str(hosts))

        assert "192.168.1.10" in result
        assert result["192.168.1.10"] == "lab-server"
        assert "192.168.1.20" in result

    def test_ignores_comments(self, tmp_path):
        hosts = tmp_path / "hosts"
        hosts.write_text("# comment\n192.168.1.1   router\n")
        result = _read_hosts_file(str(hosts))

        assert len(result) == 1
        assert "192.168.1.1" in result

    def test_loopback_entries_included_in_raw_parse(self, tmp_path):
        """_read_hosts_file returns all entries including loopback.
        Filtering of 127.x is done by _hosts_file_findings, not the parser."""
        hosts = tmp_path / "hosts"
        hosts.write_text("127.0.0.1   localhost\n192.168.1.1  router\n")
        result = _read_hosts_file(str(hosts))

        assert "127.0.0.1" in result

    def test_missing_file_returns_empty(self):
        result = _read_hosts_file("/nonexistent/path/hosts")
        assert result == {}

    def test_empty_file_returns_empty(self, tmp_path):
        hosts = tmp_path / "hosts"
        hosts.write_text("")
        result = _read_hosts_file(str(hosts))
        assert result == {}


# ---------------------------------------------------------------------------
# _hosts_file_findings
# ---------------------------------------------------------------------------

class TestHostsFileFindings:
    def test_returns_findings_for_matching_prefix(self, tmp_path):
        hosts = tmp_path / "hosts"
        hosts.write_text(HOSTS_CONTENT)
        with patch("recon.passive_recon._read_hosts_file",
                   return_value={"192.168.1.10": "lab-server",
                                 "192.168.1.20": "win-dc"}):
            findings = _hosts_file_findings("192.168.1", "session-test")

        assert len(findings) == 2

    def test_skips_loopback_127(self):
        with patch("recon.passive_recon._read_hosts_file",
                   return_value={"127.0.0.1": "localhost",
                                 "192.168.1.10": "lab-server"}):
            findings = _hosts_file_findings("", "session-test")

        ips = [f.target_ip for f in findings]
        assert "127.0.0.1" not in ips
        assert "192.168.1.10" in ips

    def test_finding_confidence_is_probable(self):
        with patch("recon.passive_recon._read_hosts_file",
                   return_value={"192.168.1.10": "lab-server"}):
            findings = _hosts_file_findings("192.168.1", "session-test")

        assert findings[0].confidence == Confidence.PROBABLE

    def test_finding_service_contains_hostname(self):
        with patch("recon.passive_recon._read_hosts_file",
                   return_value={"192.168.1.10": "lab-server"}):
            findings = _hosts_file_findings("192.168.1", "session-test")

        assert "lab-server" in findings[0].service_version


# ---------------------------------------------------------------------------
# _parse_avahi_output
# ---------------------------------------------------------------------------

class TestParseAvahiOutput:
    def test_parses_resolved_entries(self):
        result = _parse_avahi_output(AVAHI_OUTPUT)
        assert "MyPrinter" in result
        assert result["MyPrinter"] == "192.168.1.50"
        assert "MacBook" in result

    def test_ignores_unresolved_entries(self):
        """Lines starting with '+' (not '=') are not resolved — must be ignored."""
        result = _parse_avahi_output(AVAHI_OUTPUT)
        assert "Unresolved" not in result

    def test_empty_output_returns_empty(self):
        result = _parse_avahi_output(AVAHI_OUTPUT_EMPTY)
        assert result == {}

    def test_malformed_line_ignored(self):
        result = _parse_avahi_output("=;incomplete\n")
        assert result == {}


# ---------------------------------------------------------------------------
# _mdns_findings
# ---------------------------------------------------------------------------

class TestMdnsFindings:
    def test_returns_findings_for_matching_prefix(self):
        with patch("recon.passive_recon._mdns_lookup",
                   return_value={"myprinter.local": "192.168.1.50",
                                 "macbook.local": "192.168.1.60"}):
            findings = _mdns_findings("192.168.1", "session-test")

        assert len(findings) == 2

    def test_finding_confidence_is_possible(self):
        """mDNS is self-advertised — not verified → POSSIBLE."""
        with patch("recon.passive_recon._mdns_lookup",
                   return_value={"printer.local": "192.168.1.50"}):
            findings = _mdns_findings("192.168.1", "session-test")

        assert findings[0].confidence == Confidence.POSSIBLE

    def test_avahi_not_installed_returns_empty(self):
        with patch("recon.passive_recon.subprocess.run",
                   side_effect=FileNotFoundError("avahi-browse not found")):
            from recon.passive_recon import _mdns_lookup
            result = _mdns_lookup()
        assert result == {}


# ---------------------------------------------------------------------------
# passive_recon() — integration
# ---------------------------------------------------------------------------

class TestPassiveRecon:
    def test_returns_findings_from_all_sources(self):
        arp_finding = Finding(
            session_id="s", module="passive_recon", target_ip="192.168.1.1",
            target_service="arp", service_version="MAC=aa:bb:cc:dd:ee:01",
            category=Category.NETWORK, severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
        )
        hosts_finding = Finding(
            session_id="s", module="passive_recon", target_ip="192.168.1.10",
            target_service="hosts", service_version="hostname=lab-server",
            category=Category.NETWORK, severity=Severity.INFO,
            confidence=Confidence.PROBABLE,
        )
        mdns_finding = Finding(
            session_id="s", module="passive_recon", target_ip="192.168.1.50",
            target_service="mdns", service_version="hostname=printer.local",
            category=Category.NETWORK, severity=Severity.INFO,
            confidence=Confidence.POSSIBLE,
        )

        with patch("recon.passive_recon._arp_findings", return_value=[arp_finding]), \
             patch("recon.passive_recon._hosts_file_findings", return_value=[hosts_finding]), \
             patch("recon.passive_recon._mdns_findings", return_value=[mdns_finding]):
            findings = passive_recon("192.168.1", "session-test")

        assert len(findings) == 3

    def test_returns_empty_when_nothing_found(self):
        with patch("recon.passive_recon._arp_findings", return_value=[]), \
             patch("recon.passive_recon._hosts_file_findings", return_value=[]), \
             patch("recon.passive_recon._mdns_findings", return_value=[]):
            findings = passive_recon("192.168.1", "session-test")

        assert findings == []

    def test_all_findings_have_session_id(self):
        f = Finding(
            session_id="session-xyz", module="passive_recon",
            target_ip="192.168.1.1", target_service="arp",
            service_version="MAC=aa:bb:cc:dd:ee:01",
            category=Category.NETWORK, severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
        )
        with patch("recon.passive_recon._arp_findings", return_value=[f]), \
             patch("recon.passive_recon._hosts_file_findings", return_value=[]), \
             patch("recon.passive_recon._mdns_findings", return_value=[]):
            findings = passive_recon("192.168.1", "session-xyz")

        assert all(f.session_id == "session-xyz" for f in findings)

    def test_all_findings_risk_score_none(self):
        """Invariant: passive_recon never sets risk_score."""
        f = Finding(
            session_id="s", module="passive_recon", target_ip="192.168.1.1",
            target_service="arp", service_version="MAC=aa:bb:cc:dd:ee:01",
            category=Category.NETWORK, severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
        )
        with patch("recon.passive_recon._arp_findings", return_value=[f]), \
             patch("recon.passive_recon._hosts_file_findings", return_value=[]), \
             patch("recon.passive_recon._mdns_findings", return_value=[]):
            findings = passive_recon("192.168.1", "session-test")

        assert all(f.risk_score is None for f in findings)
