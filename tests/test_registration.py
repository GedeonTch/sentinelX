"""
tests/test_registration.py — Unit tests for recon/registration.py

No network: RDAP results and WHOIS answers are built in memory, and the WHOIS
function is a fake. Covers the field-by-field merge rules, masking, divergences,
distinct source statuses, and the rule that raw WHOIS text is never kept.
"""

import socket
from datetime import datetime

import pytest

from recon.rdap import RdapData, RdapResult
from recon.registration import (
    FIELD_ORDER,
    MASKED_LABEL,
    NOT_COMMUNICATED_LABEL,
    SourceStatus,
    TIMEOUT_LABEL,
    field_rows,
    lookup_registration,
    merge_registration,
    query_whois,
    registration_evidence,
    summary_lines,
)
from core.finding import Confidence
from recon.dns_enum import _registration_finding

NOW = "2026-10-26 10:00 UTC"


def whois_entry(**overrides):
    entry = {
        "domain_name": "EXAMPLE.COM",
        "registrar": "Reg Inc",
        "creation_date": datetime(1995, 8, 14, 4, 0),
        "updated_date": [datetime(2024, 8, 14), datetime(2024, 9, 1)],
        "expiration_date": datetime(2030, 8, 13),
        "status": ["clientTransferProhibited https://icann.org/epp#clientTransferProhibited"],
        "name_servers": ["A.IANA-SERVERS.NET", "b.iana-servers.net."],
        "dnssec": "unsigned",
        "org": "Example Org",
        "emails": ["abuse@reg.example"],
        "raw": "SECRET-RAW-TEXT registrant ...",
    }
    entry.update(overrides)
    return entry


def whois_returning(entry):
    def func(domain, **kwargs):
        assert kwargs.get("inc_raw") is True, "inc_raw must be requested"
        assert kwargs.get("timeout") == 10, "explicit timeout must be passed"
        return dict(entry)
    return func


def whois_raising(exc):
    def func(domain, **kwargs):
        raise exc
    return func


def rdap_ok(**overrides):
    values = dict(
        domain="example.com",
        statuses=["client transfer prohibited"],
        created="1995-08-14",
        updated="2024-08-14",
        expires="2030-08-13",
        registrar="Reg Inc",
        organization="Example Org",
        abuse_email="abuse@reg.example",
        nameservers=["a.iana-servers.net", "b.iana-servers.net"],
        dnssec="non",
        masked=frozenset(),
    )
    values.update(overrides)
    return RdapResult(status="ok", data=RdapData(**values))


def whois_status_and_fields(entry=None, exc=None):
    from recon.registration import query_whois as _q
    func = whois_raising(exc) if exc else whois_returning(entry or whois_entry())
    return _q("example.com", whois_func=func)


def merged(rdap, whois_ws, domain="example.com"):
    status, fields = whois_ws
    return merge_registration(domain, rdap, status, fields, NOW)


def value_of(summary, name):
    field = summary.fields[name]
    return None if field is None else field.value


# ---------------------------------------------------------------------------
# WHOIS source: status, timeout, errors, raw text
# ---------------------------------------------------------------------------

class TestWhoisSource:
    def test_ok_and_raw_text_is_dropped(self):
        status, fields = whois_status_and_fields()
        assert status.status == "ok"
        assert fields is not None
        assert "SECRET-RAW-TEXT" not in repr(fields)

    def test_timeout_is_timeout_status(self):
        status, fields = whois_status_and_fields(exc=socket.timeout())
        assert status.status == "timeout" and fields is None

    @pytest.mark.parametrize("exc_name,expected", [
        ("WhoisDomainNotFoundError", "not_found"),
        ("UnknownTldError", "tld_unsupported"),
        ("WhoisQuotaExceededError", "rate_limited"),
        ("FailedParsingWhoisOutputError", "malformed"),
        ("WhoisCommandFailedError", "error"),
    ])
    def test_library_errors_have_distinct_statuses(self, exc_name, expected):
        import whois.exceptions as wx
        exc = getattr(wx, exc_name)("boom")
        status, _ = whois_status_and_fields(exc=exc)
        assert status.status == expected

    def test_network_failure_is_never_not_found(self):
        status, _ = whois_status_and_fields(exc=OSError("network down"))
        assert status.status == "error"
        assert status.status != "not_found"

    def test_empty_answer_is_no_data(self):
        status, fields = whois_status_and_fields(entry={"domain_name": None})
        assert status.status == "no_data" and fields is None

    def test_oversized_raw_is_refused(self):
        status, fields = whois_status_and_fields(entry=whois_entry(raw="x" * (600 * 1024)))
        assert status.status == "malformed" and fields is None

    def test_non_dict_answer_is_malformed(self):
        status, _ = query_whois("example.com", whois_func=lambda d, **k: "text")
        assert status.status == "malformed"


# ---------------------------------------------------------------------------
# Merge rules
# ---------------------------------------------------------------------------

class TestMerge:
    def test_rdap_is_primary_and_whois_identical_values_add_nothing(self):
        summary = merged(rdap_ok(), whois_status_and_fields())
        assert summary.primary_source == "RDAP"
        assert value_of(summary, "registrar") == "Reg Inc"
        assert summary.fields["registrar"].source == "RDAP"
        assert summary.divergences == []

    def test_dates_are_deduplicated_across_sources(self):
        summary = merged(rdap_ok(), whois_status_and_fields())
        assert value_of(summary, "created") == "1995-08-14"
        assert summary.divergences == []

    def test_statuses_are_deduplicated_across_sources(self):
        summary = merged(rdap_ok(), whois_status_and_fields())
        assert value_of(summary, "statuses") == ["client transfer prohibited"]
        assert summary.divergences == []

    def test_nameservers_are_deduplicated_across_sources(self):
        summary = merged(rdap_ok(), whois_status_and_fields())
        assert value_of(summary, "nameservers") == ["a.iana-servers.net", "b.iana-servers.net"]
        assert summary.divergences == []

    def test_conflict_is_shown_with_provenance(self):
        summary = merged(rdap_ok(registrar="Reg Inc"),
                         whois_status_and_fields(whois_entry(registrar="Other Reg")))
        assert value_of(summary, "registrar") == "Reg Inc"
        assert summary.fields["registrar"].source == "RDAP"
        assert any("Registrar" in d and "RDAP" in d and "WHOIS" in d for d in summary.divergences)

    def test_rdap_masked_organization_is_never_revealed_by_whois(self):
        """Critical: a field masked by RDAP must not be filled from WHOIS."""
        summary = merged(
            rdap_ok(organization=None, masked=frozenset({"registrant"})),
            whois_status_and_fields(whois_entry(org="Secret Holding Ltd")),
        )
        field = summary.fields["organization"]
        assert field.masked is True
        assert field.value == MASKED_LABEL
        assert field.source == "RDAP"
        assert "Secret Holding" not in repr(summary.fields)
        assert "Secret Holding" not in "\n".join(summary_lines(summary))

    def test_rdap_masked_abuse_contact_is_not_filled_from_whois(self):
        summary = merged(
            rdap_ok(abuse_email=None, masked=frozenset({"abuse"})),
            whois_status_and_fields(whois_entry(emails=["abuse@reg.example"])),
        )
        assert summary.fields["abuse_contact"].masked is True

    def test_absence_is_not_masking(self):
        summary = merged(rdap_ok(organization=None), whois_status_and_fields(whois_entry(org=None)))
        assert summary.fields["organization"] is None
        assert field_rows(summary)[7][1] == NOT_COMMUNICATED_LABEL

    def test_whois_only_when_rdap_times_out(self):
        summary = merged(RdapResult(status="timeout"), whois_status_and_fields())
        assert summary.primary_source == "WHOIS"
        assert summary.fields["registrar"].source == "WHOIS"
        assert summary.source_status("RDAP").status == "timeout"

    def test_rdap_not_found_is_not_silently_replaced(self):
        summary = merged(RdapResult(status="not_found"), whois_status_and_fields())
        assert value_of(summary, "registrar") == "Reg Inc"
        assert summary.fields["registrar"].note == "à confirmer : RDAP introuvable"
        assert any("RDAP : domaine introuvable" in d for d in summary.divergences)
        assert summary.source_status("RDAP").status == "not_found"

    def test_both_sources_timeout_labels_as_timeout(self):
        summary = merged(RdapResult(status="timeout"), (SourceStatus("WHOIS", "timeout"), None))
        assert all(summary.fields[name] is None for name in FIELD_ORDER)
        assert field_rows(summary)[0][1] == TIMEOUT_LABEL
        assert summary.primary_source is None

    def test_no_source_data_is_not_proof_of_absence(self):
        summary = merged(RdapResult(status="not_found"), (SourceStatus("WHOIS", "not_found"), None))
        assert summary.has_data is False
        assert summary.primary_source is None

    def test_list_fields_with_no_items_are_not_communicated(self):
        summary = merged(rdap_ok(statuses=[], nameservers=[]), (SourceStatus("WHOIS", "ok"), None))
        assert summary.fields["statuses"] is None
        assert summary.fields["nameservers"] is None

    def test_whois_statuses_are_displayed_readably(self):
        summary = merged(RdapResult(status="timeout"), whois_status_and_fields())
        assert value_of(summary, "statuses") == ["client transfer prohibited"]


class TestLookup:
    def test_rdap_exception_does_not_hide_whois(self):
        class BrokenRdap:
            def query_domain(self, domain):
                raise RuntimeError("bug in client")

        summary = lookup_registration(
            "example.com", rdap_client=BrokenRdap(), whois_func=whois_returning(whois_entry()),
        )
        assert summary.source_status("RDAP").status == "error"
        assert summary.source_status("WHOIS").status == "ok"
        assert summary.primary_source == "WHOIS"

    def test_both_sources_are_run_independently(self):
        calls = []

        class RecordingRdap:
            def query_domain(self, domain):
                calls.append("rdap")
                return RdapResult(status="timeout")

        def recording_whois(domain, **kwargs):
            calls.append("whois")
            return whois_entry()

        summary = lookup_registration("example.com", rdap_client=RecordingRdap(), whois_func=recording_whois)
        assert calls == ["rdap", "whois"]
        assert summary.source_status("WHOIS").status == "ok"


# ---------------------------------------------------------------------------
# Presentation and Finding confidence
# ---------------------------------------------------------------------------

class TestPresentation:
    def test_evidence_has_no_raw_text_and_lists_sources(self):
        summary = merged(rdap_ok(), whois_status_and_fields())
        text = registration_evidence(summary)
        assert "SECRET-RAW-TEXT" not in text
        assert "Sources : RDAP OK ; WHOIS OK" in text

    def test_rows_follow_stable_order(self):
        summary = merged(rdap_ok(), whois_status_and_fields())
        labels = [row[0] for row in field_rows(summary)]
        assert labels[0] == "Registrar" and labels[-1] == "Contact abus"
        assert len(labels) == len(FIELD_ORDER)

    def test_finding_confidence_follows_primary_source(self):
        rdap_summary = merged(rdap_ok(), whois_status_and_fields())
        assert _registration_finding(rdap_summary, "s").confidence == Confidence.CONFIRMED
        whois_summary = merged(RdapResult(status="timeout"), whois_status_and_fields())
        assert _registration_finding(whois_summary, "s").confidence == Confidence.PROBABLE

    def test_no_finding_without_data(self):
        empty = merged(RdapResult(status="timeout"), (SourceStatus("WHOIS", "timeout"), None))
        assert _registration_finding(empty, "s") is None
