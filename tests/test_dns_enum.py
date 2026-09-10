"""
tests/test_dns_enum.py — Unit tests for recon/dns_enum.py

Strategy:
- ZERO real network calls — dns.resolver and whois are always mocked
- Tests cover: PTR lookup, forward confirmation, DNS records, WHOIS,
  IP vs domain detection, empty results, errors

Confidence rules tested:
    CONFIRMED — PTR resolved AND forward lookup confirms same IP
    PROBABLE  — PTR resolved but forward confirmation failed
    CONFIRMED — DNS A/MX/NS/TXT records are authoritative answers
"""

import pytest
from unittest.mock import patch, MagicMock
from typing import List

from core.finding import (
    Finding,
    Category,
    Severity,
    Confidence,
    Exposure,
    FindingStatus,
)
from recon.dns_enum import (
    dns_enum,
    _reverse_dns,
    _reverse_dns_findings,
    _dns_records,
    _dns_record_findings,
    _whois_lookup,
    _whois_finding,
    _forward_confirm,
    _is_ip,
)


# ---------------------------------------------------------------------------
# _is_ip
# ---------------------------------------------------------------------------

class TestIsIp:
    def test_valid_ipv4_returns_true(self):
        assert _is_ip("192.168.1.1") is True

    def test_valid_ipv4_loopback(self):
        assert _is_ip("127.0.0.1") is True

    def test_domain_returns_false(self):
        assert _is_ip("example.com") is False

    def test_subdomain_returns_false(self):
        assert _is_ip("sub.example.com") is False

    def test_empty_string_returns_false(self):
        assert _is_ip("") is False

    def test_partial_ip_returns_false(self):
        assert _is_ip("192.168") is False


# ---------------------------------------------------------------------------
# _forward_confirm
# ---------------------------------------------------------------------------

class TestForwardConfirm:
    def test_hostname_resolves_to_same_ip_returns_confirmed(self):
        with patch("recon.dns_enum.socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [(None, None, None, None, ("192.168.1.1", 0))]
            result = _forward_confirm("router.local", "192.168.1.1")
        assert result == Confidence.CONFIRMED

    def test_hostname_resolves_to_different_ip_returns_probable(self):
        with patch("recon.dns_enum.socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [(None, None, None, None, ("192.168.1.99", 0))]
            result = _forward_confirm("router.local", "192.168.1.1")
        assert result == Confidence.PROBABLE

    def test_dns_error_returns_probable(self):
        with patch("recon.dns_enum.socket.getaddrinfo", side_effect=Exception("DNS error")):
            result = _forward_confirm("bad.host", "192.168.1.1")
        assert result == Confidence.PROBABLE


# ---------------------------------------------------------------------------
# _reverse_dns
# ---------------------------------------------------------------------------

class TestReverseDns:
    def test_ip_with_ptr_returns_hostname_and_confirmed(self):
        mock_answer = MagicMock()
        mock_answer.__str__ = lambda self: "router.local."
        mock_answer.__iter__ = lambda self: iter([mock_answer])

        with patch("recon.dns_enum.dns.resolver.resolve", return_value=[mock_answer]), \
             patch("recon.dns_enum._forward_confirm", return_value=Confidence.CONFIRMED):
            hostname, confidence, raw = _reverse_dns("192.168.1.1")

        assert hostname == "router.local"
        assert confidence == Confidence.CONFIRMED
        assert "192.168.1.1" in raw

    def test_ip_with_ptr_not_confirmed_returns_probable(self):
        mock_answer = MagicMock()
        mock_answer.__str__ = lambda self: "router.local."

        with patch("recon.dns_enum.dns.resolver.resolve", return_value=[mock_answer]), \
             patch("recon.dns_enum._forward_confirm", return_value=Confidence.PROBABLE):
            hostname, confidence, raw = _reverse_dns("192.168.1.1")

        assert confidence == Confidence.PROBABLE

    def test_dns_error_returns_empty(self):
        import dns.exception
        with patch("recon.dns_enum.dns.resolver.resolve",
                   side_effect=dns.exception.DNSException("no PTR")):
            hostname, confidence, raw = _reverse_dns("192.168.1.99")

        assert hostname == ""
        assert raw == ""


# ---------------------------------------------------------------------------
# _reverse_dns_findings
# ---------------------------------------------------------------------------

class TestReverseDnsFindings:
    def test_returns_finding_when_ptr_found(self):
        with patch("recon.dns_enum._reverse_dns",
                   return_value=("router.local", Confidence.CONFIRMED, "PTR lookup: router.local")):
            findings = _reverse_dns_findings("192.168.1.1", "session-test")

        assert len(findings) == 1
        assert findings[0].module == "dns_enum"
        assert findings[0].category == Category.NETWORK
        assert findings[0].severity == Severity.INFO
        assert findings[0].confidence == Confidence.CONFIRMED
        assert "PTR" in findings[0].service_version
        assert findings[0].risk_score is None
        assert findings[0].explanation is None

    def test_returns_empty_when_no_ptr(self):
        with patch("recon.dns_enum._reverse_dns",
                   return_value=("", Confidence.PROBABLE, "")):
            findings = _reverse_dns_findings("192.168.1.99", "session-test")

        assert findings == []

    def test_finding_evidence_not_empty(self):
        with patch("recon.dns_enum._reverse_dns",
                   return_value=("lab.local", Confidence.CONFIRMED, "PTR: lab.local")):
            findings = _reverse_dns_findings("192.168.1.10", "session-test")

        assert findings[0].evidence.raw != ""
        assert "dig" in findings[0].evidence.command


# ---------------------------------------------------------------------------
# _dns_records
# ---------------------------------------------------------------------------

class TestDnsRecords:
    def test_returns_records_for_valid_domain(self):
        mock_a = MagicMock()
        mock_a.__str__ = lambda self: "93.184.216.34"

        with patch("recon.dns_enum.dns.resolver.resolve", return_value=[mock_a]):
            records, raw = _dns_records("example.com", "A")

        assert records == ["93.184.216.34"]
        assert "example.com" in raw
        assert "A" in raw

    def test_returns_empty_on_dns_error(self):
        import dns.exception
        with patch("recon.dns_enum.dns.resolver.resolve",
                   side_effect=dns.exception.DNSException("NXDOMAIN")):
            records, raw = _dns_records("nonexistent.invalid", "A")

        assert records == []
        assert raw == ""

    def test_returns_multiple_records(self):
        mock_records = [MagicMock(), MagicMock()]
        mock_records[0].__str__ = lambda self: "1.2.3.4"
        mock_records[1].__str__ = lambda self: "5.6.7.8"

        with patch("recon.dns_enum.dns.resolver.resolve", return_value=mock_records):
            records, raw = _dns_records("example.com", "A")

        assert len(records) == 2


# ---------------------------------------------------------------------------
# _dns_record_findings
# ---------------------------------------------------------------------------

class TestDnsRecordFindings:
    def test_creates_finding_per_record_type_found(self):
        def fake_dns_records(domain, rtype):
            if rtype == "A":
                return ["1.2.3.4"], "A: 1.2.3.4"
            if rtype == "MX":
                return ["mail.example.com"], "MX: mail.example.com"
            return [], ""

        with patch("recon.dns_enum._dns_records", side_effect=fake_dns_records):
            findings = _dns_record_findings("example.com", "session-test")

        assert len(findings) == 2
        service_versions = [f.service_version for f in findings]
        assert "A records" in service_versions
        assert "MX records" in service_versions

    def test_returns_empty_when_no_records(self):
        with patch("recon.dns_enum._dns_records", return_value=([], "")):
            findings = _dns_record_findings("example.com", "session-test")

        assert findings == []

    def test_all_findings_have_confirmed_confidence(self):
        with patch("recon.dns_enum._dns_records",
                   return_value=(["1.2.3.4"], "A: 1.2.3.4")):
            findings = _dns_record_findings("example.com", "session-test")

        assert all(f.confidence == Confidence.CONFIRMED for f in findings)

    def test_all_findings_risk_score_is_none(self):
        with patch("recon.dns_enum._dns_records",
                   return_value=(["1.2.3.4"], "A: 1.2.3.4")):
            findings = _dns_record_findings("example.com", "session-test")

        assert all(f.risk_score is None for f in findings)


# ---------------------------------------------------------------------------
# _whois_lookup
# ---------------------------------------------------------------------------

class TestWhoisLookup:
    def test_returns_data_and_raw_for_valid_domain(self):
        mock_w = MagicMock()
        mock_w.domain_name = "example.com"
        mock_w.registrar = "IANA"
        mock_w.creation_date = "1995-08-14"
        mock_w.expiration_date = "2025-08-13"
        mock_w.name_servers = ["a.iana-servers.net"]

        with patch("recon.dns_enum.whois_lib.whois", return_value=mock_w):
            data, raw = _whois_lookup("example.com")

        assert data["registrar"] == "IANA"
        assert "example.com" in raw
        assert "IANA" in raw

    def test_returns_empty_on_error(self):
        with patch("recon.dns_enum.whois_lib.whois",
                   side_effect=Exception("WHOIS timeout")):
            data, raw = _whois_lookup("example.com")

        assert data == {}
        assert raw == ""

    def test_returns_empty_when_no_domain_name(self):
        mock_w = MagicMock()
        mock_w.domain_name = None

        with patch("recon.dns_enum.whois_lib.whois", return_value=mock_w):
            data, raw = _whois_lookup("example.com")

        assert data == {}
        assert raw == ""


# ---------------------------------------------------------------------------
# _whois_finding
# ---------------------------------------------------------------------------

class TestWhoisFinding:
    def test_returns_finding_when_whois_available(self):
        with patch("recon.dns_enum._whois_lookup",
                   return_value=({"registrar": "IANA"}, "WHOIS for example.com:\n  registrar: IANA\n")):
            finding = _whois_finding("example.com", "session-test")

        assert finding is not None
        assert finding.module == "dns_enum"
        assert finding.target_service == "whois"
        assert finding.evidence.raw != ""
        assert finding.risk_score is None
        assert finding.explanation is None

    def test_returns_none_when_no_whois(self):
        with patch("recon.dns_enum._whois_lookup", return_value=({}, "")):
            finding = _whois_finding("example.com", "session-test")

        assert finding is None


# ---------------------------------------------------------------------------
# dns_enum() — integration (all network mocked)
# ---------------------------------------------------------------------------

class TestDnsEnum:
    def test_ip_target_returns_ptr_finding_only(self):
        with patch("recon.dns_enum._reverse_dns_findings",
                   return_value=[Finding(session_id="s", module="dns_enum",
                                         target_ip="192.168.1.1", target_service="dns",
                                         service_version="PTR → router.local",
                                         category=Category.NETWORK, severity=Severity.INFO,
                                         confidence=Confidence.CONFIRMED)]), \
             patch("recon.dns_enum._dns_record_findings") as mock_dns, \
             patch("recon.dns_enum._whois_finding") as mock_whois:

            findings = dns_enum("192.168.1.1", "session-test")

        # DNS records and WHOIS must NOT be called for IP targets
        mock_dns.assert_not_called()
        mock_whois.assert_not_called()
        assert len(findings) == 1

    def test_domain_target_calls_all_lookups(self):
        ptr_finding = Finding(
            session_id="s", module="dns_enum", target_ip="",
            target_service="dns", service_version="PTR → example.com",
            category=Category.NETWORK, severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
        )
        dns_finding = Finding(
            session_id="s", module="dns_enum", target_ip="",
            target_service="dns", service_version="A records",
            category=Category.NETWORK, severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
        )
        whois_finding = Finding(
            session_id="s", module="dns_enum", target_ip="",
            target_service="whois", service_version="registrar=IANA",
            category=Category.NETWORK, severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
        )

        with patch("recon.dns_enum._reverse_dns_findings", return_value=[ptr_finding]), \
             patch("recon.dns_enum._dns_record_findings", return_value=[dns_finding]), \
             patch("recon.dns_enum._whois_finding", return_value=whois_finding):

            findings = dns_enum("example.com", "session-test")

        assert len(findings) == 3

    def test_returns_empty_when_nothing_found(self):
        with patch("recon.dns_enum._reverse_dns_findings", return_value=[]), \
             patch("recon.dns_enum._dns_record_findings", return_value=[]), \
             patch("recon.dns_enum._whois_finding", return_value=None):

            findings = dns_enum("example.com", "session-test")

        assert findings == []

    def test_all_findings_have_session_id(self):
        f = Finding(
            session_id="session-xyz", module="dns_enum", target_ip="192.168.1.1",
            target_service="dns", service_version="PTR → host.local",
            category=Category.NETWORK, severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
        )
        with patch("recon.dns_enum._reverse_dns_findings", return_value=[f]):
            findings = dns_enum("192.168.1.1", "session-xyz")

        assert all(f.session_id == "session-xyz" for f in findings)

    def test_all_findings_risk_score_none(self):
        """Invariant: no scanner sets risk_score."""
        f = Finding(
            session_id="s", module="dns_enum", target_ip="192.168.1.1",
            target_service="dns", service_version="PTR → host.local",
            category=Category.NETWORK, severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
        )
        with patch("recon.dns_enum._reverse_dns_findings", return_value=[f]):
            findings = dns_enum("192.168.1.1", "session-test")

        assert all(f.risk_score is None for f in findings)
