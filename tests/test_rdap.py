"""
tests/test_rdap.py — Unit tests for recon/rdap.py

No network: every fetch is a fake. Covers the bootstrap (RFC 9224) cache and
HTTPS-only rule, distinct statuses per failure, RFC 9083 parsing, and RFC 9537
redaction detection.
"""

import json

import pytest

from recon.rdap import (
    BOOTSTRAP_TTL_DEFAULT,
    BOOTSTRAP_TTL_MAX,
    BOOTSTRAP_TTL_MIN,
    BOOTSTRAP_URL,
    FetchResult,
    RdapClient,
    RdapTransportError,
    _default_fetch,
    _HttpsOnlyRedirect,
    parse_domain_object,
)

BOOTSTRAP = {
    "version": "1.0",
    "services": [
        [["com", "net"], ["https://rdap.example-com/"]],
        [["kg"], ["http://rdap.insecure.example/"]],
        [["org"], ["http://old.example/", "https://rdap.org.example/"]],
    ],
}

DOMAIN_OBJECT = {
    "objectClassName": "domain",
    "ldhName": "EXAMPLE.COM",
    "status": ["client transfer prohibited", "active"],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2024-08-14T07:01:38Z"},
        {"eventAction": "expiration", "eventDate": "2030-08-13T04:00:00Z"},
    ],
    "nameservers": [
        {"objectClassName": "nameserver", "ldhName": "A.IANA-SERVERS.NET."},
        {"objectClassName": "nameserver", "ldhName": "a.iana-servers.net"},
        {"objectClassName": "nameserver", "ldhName": "b.iana-servers.net"},
    ],
    "secureDNS": {"delegationSigned": False},
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["version", {}, "text", "1.0"], ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]]],
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [["email", {}, "text", "abuse@registrar.example"]]],
                }
            ],
        },
        {
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Jane Doe"], ["org", {}, "text", "Example Org"]]],
        },
    ],
}


class FakeFetch:
    """Routes URLs to canned responses and records every call."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        value = self.routes.get(url)
        if value is None:
            raise AssertionError(f"unexpected URL in test: {url}")
        if isinstance(value, Exception):
            raise value
        return value


def ok_json(document, headers=None):
    return FetchResult(200, headers or {}, json.dumps(document).encode("utf-8"))


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def client_with(routes, clock=None):
    fetch = FakeFetch(routes)
    return RdapClient(fetch=fetch, now=clock or FakeClock()), fetch


# ---------------------------------------------------------------------------
# Bootstrap and routing
# ---------------------------------------------------------------------------

class TestBootstrap:
    def test_https_tld_is_queried_and_parsed(self):
        client, fetch = client_with({
            BOOTSTRAP_URL: ok_json(BOOTSTRAP),
            "https://rdap.example-com/domain/example.com": ok_json(DOMAIN_OBJECT),
        })
        result = client.query_domain("example.com")
        assert result.status == "ok"
        assert fetch.calls[0] == BOOTSTRAP_URL
        assert fetch.calls[1] == "https://rdap.example-com/domain/example.com"

    def test_http_only_tld_is_refused_without_fetching_domain(self):
        client, fetch = client_with({BOOTSTRAP_URL: ok_json(BOOTSTRAP)})
        assert client.query_domain("site.kg").status == "rdap_non_https"
        assert all("site.kg" not in call for call in fetch.calls)

    def test_mixed_tld_uses_https_url_only(self):
        client, fetch = client_with({
            BOOTSTRAP_URL: ok_json(BOOTSTRAP),
            "https://rdap.org.example/domain/x.org": ok_json(DOMAIN_OBJECT),
        })
        assert client.query_domain("x.org").status == "ok"
        assert fetch.calls[-1] == "https://rdap.org.example/domain/x.org"

    def test_tld_without_rdap(self):
        client, _ = client_with({BOOTSTRAP_URL: ok_json(BOOTSTRAP)})
        assert client.query_domain("example.zz").status == "tld_without_rdap"

    def test_bootstrap_is_cached_within_ttl(self):
        clock = FakeClock()
        client, fetch = client_with({
            BOOTSTRAP_URL: ok_json(BOOTSTRAP, {"cache-control": "max-age=7200"}),
            "https://rdap.example-com/domain/a.com": ok_json(DOMAIN_OBJECT),
            "https://rdap.example-com/domain/b.com": ok_json(DOMAIN_OBJECT),
        }, clock)
        client.query_domain("a.com")
        client.query_domain("b.com")
        assert fetch.calls.count(BOOTSTRAP_URL) == 1

    def test_bootstrap_is_refetched_after_ttl(self):
        clock = FakeClock()
        client, fetch = client_with({
            BOOTSTRAP_URL: ok_json(BOOTSTRAP, {"cache-control": "max-age=3600"}),
            "https://rdap.example-com/domain/a.com": ok_json(DOMAIN_OBJECT),
        }, clock)
        client.query_domain("a.com")
        clock.now += 3601
        client.query_domain("a.com")
        assert fetch.calls.count(BOOTSTRAP_URL) == 2

    @pytest.mark.parametrize("header,expected", [
        ("", BOOTSTRAP_TTL_DEFAULT),
        ("max-age=10", BOOTSTRAP_TTL_MIN),
        ("max-age=999999999", BOOTSTRAP_TTL_MAX),
        ("max-age=7200", 7200),
    ])
    def test_ttl_is_clamped(self, header, expected):
        assert RdapClient._ttl({"cache-control": header}) == expected

    def test_bootstrap_timeout_is_timeout_status(self):
        client, _ = client_with({BOOTSTRAP_URL: RdapTransportError("timeout")})
        assert client.query_domain("example.com").status == "timeout"

    def test_bootstrap_http_error_is_unavailable(self):
        client, _ = client_with({BOOTSTRAP_URL: FetchResult(503, {}, b"")})
        assert client.query_domain("example.com").status == "bootstrap_unavailable"

    def test_bootstrap_malformed_json(self):
        client, _ = client_with({BOOTSTRAP_URL: FetchResult(200, {}, b"<html>")})
        assert client.query_domain("example.com").status == "malformed"


# ---------------------------------------------------------------------------
# Domain query statuses
# ---------------------------------------------------------------------------

DOMAIN_URL = "https://rdap.example-com/domain/example.com"


class TestDomainStatuses:
    @pytest.mark.parametrize("response,status", [
        (FetchResult(404, {}, b""), "not_found"),
        (FetchResult(429, {}, b""), "rate_limited"),
        (FetchResult(500, {}, b""), "unavailable"),
        (FetchResult(403, {}, b""), "error"),
        (FetchResult(200, {}, b"not json"), "malformed"),
        (FetchResult(200, {}, json.dumps({"objectClassName": "entity"}).encode()), "malformed"),
        (FetchResult(200, {}, json.dumps([1, 2]).encode()), "malformed"),
        (RdapTransportError("timeout"), "timeout"),
        (RdapTransportError("unavailable"), "unavailable"),
        (RdapTransportError("too_large"), "malformed"),
    ])
    def test_each_failure_has_its_own_status(self, response, status):
        client, _ = client_with({
            BOOTSTRAP_URL: ok_json(BOOTSTRAP),
            DOMAIN_URL: response,
        })
        assert client.query_domain("example.com").status == status


# ---------------------------------------------------------------------------
# RFC 9083 parsing and RFC 9537 redaction
# ---------------------------------------------------------------------------

class TestParsing:
    def test_fields_are_extracted(self):
        data = parse_domain_object(DOMAIN_OBJECT)
        assert data.domain == "example.com"
        assert data.created == "1995-08-14"
        assert data.updated == "2024-08-14"
        assert data.expires == "2030-08-13"
        assert data.dnssec == "non"
        assert data.registrar == "RESERVED-Internet Assigned Numbers Authority"
        assert data.organization == "Example Org"
        assert data.abuse_email == "abuse@registrar.example"
        assert "client transfer prohibited" in data.statuses

    def test_nameservers_are_lowercased_and_deduplicated(self):
        data = parse_domain_object(DOMAIN_OBJECT)
        assert data.nameservers == ["a.iana-servers.net", "b.iana-servers.net"]

    def test_registrant_name_is_kept_for_display_but_raw_document_is_not(self):
        # T26: public contact data is displayed by `whois` (user decision). The
        # parsed contact is kept in memory only; the raw RDAP document is not.
        data = parse_domain_object(DOMAIN_OBJECT)
        assert data.contacts["registrant"]["name"] == "Jane Doe"
        assert "entities" not in data.__dict__ and "raw" not in data.__dict__

    def test_no_redaction_means_no_mask(self):
        assert parse_domain_object(DOMAIN_OBJECT).masked == frozenset()

    def test_registrant_redaction_is_detected(self):
        document = dict(DOMAIN_OBJECT)
        document["redacted"] = [{
            "name": {"description": "Registrant Name"},
            "prePath": "$.entities[?(@.roles[0]=='registrant')]",
            "method": "removal",
        }]
        data = parse_domain_object(document)
        assert "registrant" in data.masked

    def test_abuse_email_redaction_is_detected(self):
        document = dict(DOMAIN_OBJECT)
        document["redacted"] = [{
            "name": {"description": "Registrar Abuse Email"},
            "postPath": "$.entities[?(@.roles[0]=='abuse')].vcardArray[1][?(@[0]=='email')][3]",
            "method": "emptyValue",
        }]
        assert "abuse" in parse_domain_object(document).masked

    def test_missing_fields_stay_none(self):
        data = parse_domain_object({"objectClassName": "domain", "ldhName": "x.com"})
        assert data.created is None and data.registrar is None and data.nameservers == []
        assert data.masked == frozenset()
        assert data.dnssec is None


# ---------------------------------------------------------------------------
# Transport rules (no network)
# ---------------------------------------------------------------------------

class TestTransportRules:
    def test_default_fetch_refuses_plain_http_without_network(self):
        with pytest.raises(RdapTransportError):
            _default_fetch("http://rdap.example/domain/x.com")

    def test_redirect_to_http_is_refused(self):
        handler = _HttpsOnlyRedirect()
        with pytest.raises(RdapTransportError):
            handler.redirect_request(None, None, 301, "Moved", {}, "http://evil.example/")

    def test_redirect_limit_is_bounded(self):
        assert _HttpsOnlyRedirect.max_redirections <= 3

    def test_oversized_response_is_refused_by_client_mapping(self):
        client, _ = client_with({
            BOOTSTRAP_URL: ok_json(BOOTSTRAP),
            DOMAIN_URL: RdapTransportError("too_large"),
        })
        assert client.query_domain("example.com").status == "malformed"

    def test_unexpected_fetch_exception_is_not_raised(self):
        """A bad fetch implementation is a transport failure, not a crash."""
        def boom(url):
            raise RdapTransportError("unavailable")

        client = RdapClient(fetch=boom, now=FakeClock())
        assert client.query_domain("example.com").status == "bootstrap_unavailable"
