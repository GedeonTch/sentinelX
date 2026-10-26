"""
tests/test_dns_enum.py — Unit tests for recon/dns_enum.py

No network: the resolver is a fake that raises the real dnspython exceptions,
RDAP uses a fake fetch, and WHOIS is a fake function.
"""

from types import SimpleNamespace
from unittest.mock import patch

import dns.exception
import dns.flags
import dns.resolver
import dns.reversename
import pytest

from core.finding import Confidence, Exposure
from recon.dns_enum import (
    DNS_NODATA,
    DNS_NXDOMAIN,
    DNS_TIMEOUT,
    DNS_UNAVAILABLE,
    DNS_ERROR,
    dns_report,
    normalize_domain,
    target_kind,
)
from recon.rdap import BOOTSTRAP_URL, FetchResult, RdapClient, RdapTransportError

DOMAIN = "example.com"
IP = "192.0.2.10"
PTR_NAME = str(dns.reversename.from_address(IP))


class Answer:
    def __init__(self, values, aa=True):
        self._values = list(values)
        self.response = SimpleNamespace(flags=dns.flags.AA if aa else 0)

    def __iter__(self):
        return iter(self._values)


class FakeResolver:
    """Maps (name, rtype) to an Answer or to an exception to raise."""

    def __init__(self, table):
        self.table = table
        self.queries = []

    def resolve(self, name, rtype, raise_on_no_answer=True):
        self.queries.append((name, rtype))
        value = self.table.get((name, rtype))
        if value is None:
            raise dns.resolver.NXDOMAIN()
        if isinstance(value, BaseException):
            raise value
        return value


def factory_for(table):
    resolver = FakeResolver(table)
    return (lambda: resolver), resolver


def _rdap_down():
    def fetch(url):
        raise RdapTransportError("unavailable")
    return RdapClient(fetch=fetch, now=lambda: 0.0)


def _whois_down(domain, **kwargs):
    raise OSError("no network in tests")


def run(table, target=DOMAIN, rdap=None, whois=None):
    factory, resolver = factory_for(table)
    report = dns_report(
        target, "session-test",
        resolver_factory=factory,
        rdap_client=rdap or _rdap_down(),
        whois_func=whois or _whois_down,
    )
    return report, resolver


def by_type(report, rtype):
    return next(o for o in report.outcomes if o.record_type == rtype)


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------

class TestTargets:
    def test_domain_is_normalized(self):
        assert normalize_domain("Example.COM.") == "example.com"

    @pytest.mark.parametrize("value", [
        "http://example.com/", "exa mple.com", "-bad.example", "example", "a..b.com", "x" * 300 + ".com",
    ])
    def test_invalid_domains_are_rejected(self, value):
        with pytest.raises(ValueError):
            normalize_domain(value)

    def test_ipv6_target_is_rejected(self):
        with pytest.raises(ValueError, match="IPv6"):
            target_kind("2001:db8::1")

    def test_kind_detection(self):
        assert target_kind(IP) == "ip"
        assert target_kind(DOMAIN) == "domain"


# ---------------------------------------------------------------------------
# Record outcomes and confidence
# ---------------------------------------------------------------------------

class TestRecords:
    def test_authoritative_answer_is_confirmed(self):
        table = {(DOMAIN, "MX"): Answer(["10 mx.example.com."], aa=True)}
        report, _ = run(table)
        finding = next(f for f in report.findings if "MX" in f.service_version)
        assert finding.confidence == Confidence.CONFIRMED
        assert "AA" in finding.evidence.raw

    def test_non_authoritative_answer_is_probable(self):
        table = {(DOMAIN, "MX"): Answer(["10 mx.example.com."], aa=False)}
        report, _ = run(table)
        finding = next(f for f in report.findings if "MX" in f.service_version)
        assert finding.confidence == Confidence.PROBABLE
        assert "non autoritative" in finding.evidence.raw

    def test_all_values_are_kept_and_types_are_preserved(self):
        table = {
            (DOMAIN, "A"): Answer([IP, "192.0.2.11"]),
            (DOMAIN, "MX"): Answer(["10 mx1.example.com.", "20 mx2.example.com."]),
            (DOMAIN, "NS"): Answer(["ns1.example.net."]),
            (DOMAIN, "TXT"): Answer(['"v=spf1 -all"']),
            (DOMAIN, "CNAME"): Answer(["alias.example.net."]),
        }
        report, _ = run(table)
        assert by_type(report, "A").values == [IP, "192.0.2.11"]
        assert by_type(report, "MX").values == ["10 mx1.example.com", "20 mx2.example.com"]
        assert by_type(report, "NS").values == ["ns1.example.net"]
        assert by_type(report, "TXT").values == ['"v=spf1 -all"']
        assert by_type(report, "CNAME").values == ["alias.example.net"]
        raw = "\n".join(f.evidence.raw for f in report.findings)
        assert "mx2.example.com" in raw and "192.0.2.11" in raw

    def test_duplicate_a_addresses_are_looked_up_once(self):
        table = {
            (DOMAIN, "A"): Answer([IP, IP]),
            (PTR_NAME, "PTR"): Answer(["host.example.net."]),
        }
        report, resolver = run(table)
        ptr_queries = [q for q in resolver.queries if q[1] == "PTR"]
        assert len(ptr_queries) == 1

    def test_distinct_outcomes_are_not_collapsed(self):
        table = {
            (DOMAIN, "A"): dns.resolver.NXDOMAIN(),
            (DOMAIN, "MX"): dns.resolver.NoAnswer(),
            (DOMAIN, "NS"): dns.exception.Timeout(),
            (DOMAIN, "TXT"): dns.resolver.NoNameservers(),
            (DOMAIN, "CNAME"): dns.exception.DNSException(),
        }
        report, _ = run(table)
        statuses = {o.record_type: o.status for o in report.outcomes}
        assert statuses["A"] == DNS_NXDOMAIN
        assert statuses["MX"] == DNS_NODATA
        assert statuses["NS"] == DNS_TIMEOUT
        assert statuses["TXT"] == DNS_UNAVAILABLE
        assert statuses["CNAME"] == DNS_ERROR
        assert len(set(statuses.values())) == 5

    def test_no_answer_is_not_nonexistence(self):
        table = {(DOMAIN, "MX"): dns.resolver.NoAnswer()}
        report, _ = run(table)
        assert by_type(report, "MX").status == DNS_NODATA
        assert by_type(report, "MX").status != DNS_NXDOMAIN

    def test_timeout_is_not_nonexistence(self):
        table = {(DOMAIN, "NS"): dns.resolver.LifetimeTimeout()}
        report, _ = run(table)
        assert by_type(report, "NS").status == DNS_TIMEOUT

    def test_errors_create_no_artificial_finding(self):
        table = {
            (DOMAIN, "A"): dns.exception.Timeout(),
            (DOMAIN, "MX"): dns.resolver.NXDOMAIN(),
        }
        report, _ = run(table)
        assert [f for f in report.findings if f.target_service == "dns"] == []

    def test_dns_findings_are_never_external(self):
        table = {(DOMAIN, "A"): Answer([IP]), (PTR_NAME, "PTR"): Answer(["h.example.net."])}
        report, _ = run(table)
        assert report.findings
        assert all(f.exposure == Exposure.INTERNAL for f in report.findings)


# ---------------------------------------------------------------------------
# PTR
# ---------------------------------------------------------------------------

class TestPtr:
    def test_ip_target_ptr_is_forward_confirmed(self):
        table = {(PTR_NAME, "PTR"): Answer(["host.example.net."])}
        factory, _ = factory_for(table)
        with patch("recon.dns_enum._forward_confirm", return_value=Confidence.CONFIRMED):
            report = dns_report(IP, "s", resolver_factory=factory)
        finding = report.findings[0]
        assert finding.target_ip == IP
        assert finding.service_version == "PTR host.example.net"
        assert finding.confidence == Confidence.CONFIRMED

    def test_ip_target_without_ptr_has_no_finding(self):
        report, _ = run({(PTR_NAME, "PTR"): dns.resolver.NXDOMAIN()}, target=IP)
        assert report.findings == []
        assert report.outcomes[0].status == DNS_NXDOMAIN

    def test_domain_ptr_keeps_ip_as_target_not_domain(self):
        table = {
            (DOMAIN, "A"): Answer([IP]),
            (PTR_NAME, "PTR"): Answer(["host.example.net."]),
        }
        report, _ = run(table)
        ptr = [f for f in report.findings if f.service_version.startswith("PTR")]
        assert len(ptr) == 1
        assert ptr[0].target_ip == IP
        assert ptr[0].confidence == Confidence.PROBABLE  # no forward check on the domain path

    def test_domain_is_never_placed_in_target_ip(self):
        table = {
            (DOMAIN, "A"): Answer([IP]),
            (DOMAIN, "MX"): Answer(["10 mx.example.com."]),
            (PTR_NAME, "PTR"): Answer(["host.example.net."]),
        }
        report, _ = run(table)
        assert all(DOMAIN not in f.target_ip for f in report.findings)


# ---------------------------------------------------------------------------
# Registration integration
# ---------------------------------------------------------------------------

def _rdap_with_domain(domain_object):
    import json

    bootstrap = {"services": [[["com"], ["https://rdap.example-com/"]]]}

    def fetch(url):
        if url == BOOTSTRAP_URL:
            return FetchResult(200, {}, json.dumps(bootstrap).encode())
        return FetchResult(200, {}, json.dumps(domain_object).encode())

    return RdapClient(fetch=fetch, now=lambda: 0.0)


class TestRegistrationIntegration:
    def test_rdap_data_produces_confirmed_registration_finding(self):
        rdap = _rdap_with_domain({
            "objectClassName": "domain",
            "ldhName": "example.com",
            "status": ["active"],
            "nameservers": [{"ldhName": "ns1.example.net"}],
        })
        report, _ = run({}, rdap=rdap)
        reg = [f for f in report.findings if f.target_service == "whois"]
        assert len(reg) == 1
        assert reg[0].confidence == Confidence.CONFIRMED
        assert reg[0].target_ip == ""
        assert "RDAP OK" in reg[0].evidence.raw

    def test_no_registration_finding_when_no_source_answers(self):
        report, _ = run({})
        assert all(f.target_service != "whois" for f in report.findings)
        assert report.registration is not None
        assert report.registration.has_data is False

    def test_registration_sources_are_not_network_in_tests(self):
        """The default RDAP client is never used here: the rdap stub is injected."""
        report, _ = run({})
        assert report.registration.source_status("RDAP").status == "bootstrap_unavailable"
