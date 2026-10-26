"""
tests/test_whois_enrichment.py — structured WHOIS/RDAP contacts (T26).

Every person, organisation, address, phone and e-mail below is FICTITIOUS
(reserved example.com domain, invented names, RFC 2606/5737 style placeholders).
No real registration data belongs in this repository.

No network: RDAP documents and WHOIS answers are built in memory. The CLI
tests run the real rendering code with the DNS resolver, RDAP fetch and WHOIS
function replaced.
"""

import json
from datetime import date
from unittest.mock import MagicMock, patch

import dns.flags
import dns.resolver
from types import SimpleNamespace
from typer.testing import CliRunner

from cli import app
from recon.rdap import RdapResult, parse_domain_object
from recon.registration import (
    MASKED_LABEL,
    SourceStatus,
    absence_label,
    contact_sections,
    days_until_expiry,
    domain_rows,
    expiry_notice,
    lookup_registration,
    merge_registration,
    nameserver_gap,
    parse_whois_contacts,
    query_whois,
    registration_evidence,
)

runner = CliRunner()
TODAY = date(2026, 10, 26)

# ---------------------------------------------------------------------------
# Fictitious fixtures
# ---------------------------------------------------------------------------

FAKE_RAW_WHOIS = """\
Domain Name: EXAMPLE.COM
Registry Domain ID: 00000000-FAKE-DOMAIN
Registrar WHOIS Server: whois.registrar.example
Registrar URL: https://registrar.example
Registry WHOIS Server: whois.registry.example
Updated Date: 2026-03-01
Creation Date: 2020-04-20
Registry Expiry Date: 2027-04-20
Registrar: Example Registrar Ltd
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registrant Name: Jane Example
Registrant Organization: Example Trading Co
Registrant Street: 1 Fictional Avenue
Registrant Street: Building B
Registrant City: Exampletown
Registrant State/Province: Example Region
Registrant Postal Code: 0000
Registrant Country: Exampleland
Registrant Phone: +000.0000000
Registrant Email: owner@example.com
Registry Registrant ID: REG-0001
Admin Name: John Sample
Admin Organization: Example Trading Co
Admin Street: 2 Sample Road
Admin City: Exampletown
Admin Country: Exampleland
Admin Phone: +000.0000001
Admin Email: admin@example.com
Registry Admin ID: REG-0002
Tech Name: REDACTED FOR PRIVACY
Tech Organization: REDACTED FOR PRIVACY
Tech Email: REDACTED FOR PRIVACY
Name Server: ns1.example.com
Name Server: ns2.example.com
DNSSEC: unsigned
"""

FAKE_WHOIS_ENTRY = {
    "domain_name": "EXAMPLE.COM",
    "registrar": "Example Registrar Ltd",
    "creation_date": "2020-04-20",
    "updated_date": "2026-03-01",
    "expiration_date": "2027-04-20",
    "status": ["clientTransferProhibited https://icann.org/epp#clientTransferProhibited"],
    "name_servers": ["ns1.example.com", "ns2.example.com"],
    "dnssec": "unsigned",
    "org": None,
    "emails": None,
    "raw": FAKE_RAW_WHOIS,
}

FAKE_RDAP_DOCUMENT = {
    "ldhName": "EXAMPLE.COM",
    "entities": [
        {
            "handle": "RDAP-REG-1",
            "roles": ["registrant"],
            "vcardArray": ["vcard", [
                ["fn", {}, "text", "Jane RDAP"],
                ["org", {}, "text", "Example RDAP Org"],
                ["adr", {}, "text", ["", "", "3 Fictional Street", "Exampletown", "Example Region", "0001", "Exampleland"]],
                ["tel", {}, "uri", "tel:+000.0000002"],
                ["email", {}, "text", "rdap-owner@example.com"],
            ]],
        },
        {
            "handle": "RDAP-ADM-1",
            "roles": ["administrative"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Admin RDAP"]]],
        },
        {
            "roles": ["abuse"],
            "vcardArray": ["vcard", [["email", {}, "text", "abuse@registrar.example"], ["tel", {}, "uri", "tel:+000.0000009"]]],
        },
    ],
    "redacted": [{
        "name": {"description": "Administrative contact name"},
        "prePath": "$.entities[?(@.roles[0]=='administrative')]",
        "method": "removal",
        "reason": {"description": "Privacy"},
    }],
}


def ok_rdap(document=FAKE_RDAP_DOCUMENT):
    return RdapResult(status="ok", data=parse_domain_object(document))


def whois_status_ok():
    return SourceStatus("WHOIS", "ok")


def whois_returning(entry):
    def func(domain, **kwargs):
        assert kwargs.get("inc_raw") is True
        assert kwargs.get("timeout") == 10
        return dict(entry)
    return func


def flat(text):
    """Collapse whitespace and table borders: Rich may wrap long cells."""
    return " ".join(text.replace("│", " ").replace("┃", " ").split())


def summary_from(rdap=None, whois_entry=FAKE_WHOIS_ENTRY):
    rdap = rdap or RdapResult(status="error")
    return lookup_registration(
        "example.com",
        rdap_client=MagicMock(query_domain=MagicMock(return_value=rdap)),
        whois_func=whois_returning(whois_entry),
    )


def section(summary, title):
    for name, rows in contact_sections(summary):
        if name == title:
            return rows
    raise AssertionError(f"no section {title}")


# ---------------------------------------------------------------------------
# WHOIS raw parsing
# ---------------------------------------------------------------------------

class TestWhoisLibraryVersion:
    def test_old_library_signature_is_reported_as_outdated_not_as_error(self):
        def old_whois(domain, command=False, flags=0):  # python-whois 0.8.x signature
            return {}

        def call(domain, **kwargs):
            return old_whois(domain, **kwargs)

        status, fields = query_whois("example.com", call)
        assert status.status == "library_outdated"
        assert fields is None
        assert "trop ancien" in status.label
        assert "erreur" not in status.label


class TestWhoisRawParsing:
    def test_registrant_fields_are_extracted_with_multiline_street(self):
        parsed = parse_whois_contacts(FAKE_RAW_WHOIS)["contacts"]["registrant"]
        assert parsed["name"] == ("Jane Example", False)
        assert parsed["organization"] == ("Example Trading Co", False)
        assert parsed["street"] == ("1 Fictional Avenue, Building B", False)
        assert parsed["city"] == ("Exampletown", False)
        assert parsed["state"] == ("Example Region", False)
        assert parsed["postal_code"] == ("0000", False)
        assert parsed["country"] == ("Exampleland", False)
        assert parsed["phone"] == ("+000.0000000", False)
        assert parsed["email"] == ("owner@example.com", False)
        assert parsed["handle"] == ("REG-0001", False)

    def test_admin_and_billing_roles_and_registry_identifiers(self):
        parsed = parse_whois_contacts(FAKE_RAW_WHOIS)
        assert parsed["contacts"]["admin"]["name"] == ("John Sample", False)
        assert parsed["contacts"]["admin"]["handle"] == ("REG-0002", False)
        assert parsed["extra"]["domain_id"] == "00000000-FAKE-DOMAIN"
        assert parsed["extra"]["registry_server"] == "whois.registry.example"

    def test_masked_values_are_flagged_not_revealed(self):
        tech = parse_whois_contacts(FAKE_RAW_WHOIS)["contacts"]["tech"]
        assert tech["name"] == (None, True)
        assert tech["organization"] == (None, True)
        assert tech["email"] == (None, True)

    def test_absent_role_is_absent_not_masked(self):
        assert "billing" not in parse_whois_contacts(FAKE_RAW_WHOIS)["contacts"]

    def test_non_address_email_is_ignored(self):
        raw = "Registrant Email: Please query the RDDS service of the registrar\n"
        assert "email" not in parse_whois_contacts(raw)["contacts"]["registrant"]

    def test_masked_placeholder_yields_to_real_value(self):
        raw = "Admin Name: REDACTED FOR PRIVACY\nAdmin Name: Real Person\n"
        assert parse_whois_contacts(raw)["contacts"]["admin"]["name"] == ("Real Person", False)

    def test_query_whois_keeps_contacts_and_drops_raw(self):
        status, fields = query_whois("example.com", whois_returning(FAKE_WHOIS_ENTRY))
        assert status.status == "ok"
        assert "raw" not in fields
        assert "Domain Name:" not in json.dumps(fields, default=str)
        assert fields["contacts"]["registrant"]["name"] == ("Jane Example", False)


# ---------------------------------------------------------------------------
# RDAP contacts
# ---------------------------------------------------------------------------

class TestRdapContacts:
    def test_roles_fields_address_and_handle_are_parsed(self):
        contacts = parse_domain_object(FAKE_RDAP_DOCUMENT).contacts
        registrant = contacts["registrant"]
        assert registrant["name"] == "Jane RDAP"
        assert registrant["organization"] == "Example RDAP Org"
        assert registrant["street"] == "3 Fictional Street"
        assert registrant["city"] == "Exampletown"
        assert registrant["state"] == "Example Region"
        assert registrant["postal_code"] == "0001"
        assert registrant["country"] == "Exampleland"
        assert registrant["phone"] == "+000.0000002"  # tel: prefix removed
        assert registrant["email"] == "rdap-owner@example.com"
        assert registrant["handle"] == "RDAP-REG-1"
        assert contacts["admin"]["name"] == "Admin RDAP"
        assert contacts["abuse"]["phone"] == "+000.0000009"

    def test_redacted_admin_role_is_masked_by_category(self):
        assert "admin" in parse_domain_object(FAKE_RDAP_DOCUMENT).masked

    def test_unredacted_role_is_not_masked(self):
        assert "registrant" not in parse_domain_object(FAKE_RDAP_DOCUMENT).masked

    def test_raw_rdap_document_is_not_kept(self):
        data = parse_domain_object(FAKE_RDAP_DOCUMENT)
        assert not any(k in data.__dict__ for k in ("entities", "raw", "document"))


# ---------------------------------------------------------------------------
# Merge rules
# ---------------------------------------------------------------------------

class TestContactMerge:
    def test_rdap_value_wins_and_whois_only_completes_missing_fields(self):
        summary = summary_from(ok_rdap())
        registrant = summary.contacts["registrant"]
        assert registrant["name"].value == "Jane RDAP"
        assert registrant["name"].source == "RDAP"
        assert registrant["city"].value == "Exampletown"
        assert registrant["handle"].value == "RDAP-REG-1"

    def test_contact_conflicts_are_not_divergences(self):
        # RDAP and WHOIS disagree on the registrant name: the conflict must not
        # reach the Divergence lines, which feed the Finding evidence.
        summary = summary_from(ok_rdap())
        assert all("Jane" not in line for line in summary.divergences)

    def test_role_masked_by_rdap_is_never_completed_from_whois(self):
        document = dict(FAKE_RDAP_DOCUMENT)
        document["redacted"] = [{
            "name": {"description": "Registrant Name"},
            "prePath": "$.entities[?(@.roles[0]=='registrant')]",
            "method": "removal",
        }]
        summary = summary_from(ok_rdap(document))
        assert "registrant" in summary.masked_contact_roles
        assert "registrant" not in summary.contacts
        rows = section(summary, "Titulaire")
        assert all(value == MASKED_LABEL for _, value, _ in rows)
        assert all("Jane Example" not in value for _, value, _ in rows)

    def test_whois_only_contacts_are_sourced_from_whois(self):
        summary = summary_from(RdapResult(status="timeout"))
        assert summary.contacts["registrant"]["name"].source == "WHOIS"
        assert summary.contacts["admin"]["email"].value == "admin@example.com"

    def test_masked_whois_field_is_marked_masked(self):
        summary = summary_from(RdapResult(status="timeout"))
        assert summary.contacts["tech"]["name"].masked is True
        assert summary.contacts["tech"]["name"].value == MASKED_LABEL


# ---------------------------------------------------------------------------
# Presentation rules
# ---------------------------------------------------------------------------

class TestPresentation:
    def test_address_is_composed_on_one_line(self):
        rows = section(summary_from(RdapResult(status="timeout")), "Titulaire")
        address = [v for label, v, _ in rows if label == "Adresse physique"][0]
        assert address == "1 Fictional Avenue, Building B, 0000 Exampletown, Example Region, Exampleland"

    def test_absent_and_not_provided_labels_are_distinct(self):
        # WHOIS answered without a billing role; RDAP timed out.
        summary = summary_from(RdapResult(status="timeout"))
        rows = section(summary, "Contact de facturation")
        assert rows == [("Contact", "Absent du WHOIS ; non fourni par RDAP (timeout)", "—")]

    def test_absent_label_when_both_sources_answered(self):
        summary = summary_from(ok_rdap())
        summary.contacts.pop("billing", None)
        assert absence_label(summary) == "Absent du RDAP et du WHOIS"

    def test_source_not_applicable_is_not_listed_as_not_provided(self):
        # ccTLD without RDAP: WHOIS answered, RDAP does not exist for this domain.
        summary = merge_registration(
            "example.com",
            RdapResult(status="tld_without_rdap"),
            whois_status_ok(),
            {"contacts": {}, "extra": {}, "masked": []},
            "now",
        )
        assert absence_label(summary) == "Absent du WHOIS"

    def test_all_sources_timeout_is_timeout_not_absence(self):
        summary = merge_registration(
            "example.com",
            RdapResult(status="timeout"),
            SourceStatus("WHOIS", "timeout"),
            None,
            "now",
        )
        assert absence_label(summary) == "Source en timeout"
        assert section(summary, "Titulaire") == [("Contact", "Source en timeout", "—")]

    def test_fax_row_only_when_present(self):
        labels = [label for label, _, _ in section(summary_from(RdapResult(status="timeout")), "Titulaire")]
        assert "Fax" not in labels
        assert "Téléphone" in labels and "Email" in labels and "Identifiant de contact" in labels

    def test_expiry_countdown_and_notice_under_180_days(self):
        summary = summary_from(RdapResult(status="timeout"))
        assert days_until_expiry(summary, TODAY) == 176
        assert expiry_notice(summary, TODAY) is not None
        assert "176 jour(s)" in expiry_notice(summary, TODAY)
        expiry_values = [v for label, v, _ in domain_rows(summary, TODAY) if label == "Expiration"]
        assert expiry_values == ["2027-04-20 (dans 176 jour(s))"]

    def test_no_notice_when_far_from_expiry(self):
        summary = summary_from(RdapResult(status="timeout"))
        assert expiry_notice(summary, date(2026, 1, 1)) is None

    def test_expired_domain_is_reported_as_information(self):
        summary = summary_from(RdapResult(status="timeout"))
        notice = expiry_notice(summary, date(2028, 1, 1))
        assert "dépassée" in notice and "pas un constat" in notice

    def test_nameserver_gap_when_dns_has_extra_server(self):
        summary = summary_from(RdapResult(status="timeout"))
        dns_ns = ["ns1.example.com.", "ns2.example.com.", "ns3.example.com."]
        gap = nameserver_gap(summary, dns_ns)
        assert "ns3.example.com" in gap
        assert "en DNS seulement" in gap

    def test_no_nameserver_gap_when_sets_match(self):
        summary = summary_from(RdapResult(status="timeout"))
        assert nameserver_gap(summary, ["NS2.example.com.", "ns1.example.com"]) is None

    def test_no_nameserver_gap_without_dns_answer(self):
        summary = summary_from(RdapResult(status="timeout"))
        assert nameserver_gap(summary, []) is None

    def test_contacts_never_reach_finding_evidence(self):
        evidence = registration_evidence(summary_from(ok_rdap()))
        for personal in ("Jane", "Sample", "owner@example.com", "admin@example.com",
                         "+000.0000000", "Fictional Avenue", "rdap-owner"):
            assert personal not in evidence
        assert "Sources :" in evidence  # the evidence itself still exists


# ---------------------------------------------------------------------------
# CLI rendering (real code path, no network)
# ---------------------------------------------------------------------------

class Answer:
    def __init__(self, values, aa=True):
        self._values = list(values)
        self.response = SimpleNamespace(flags=dns.flags.AA if aa else 0)

    def __iter__(self):
        return iter(self._values)


class FakeResolver:
    def __init__(self, table):
        self.table = table

    def resolve(self, name, rtype, raise_on_no_answer=True):
        value = self.table.get((name, rtype))
        if value is None:
            raise dns.resolver.NXDOMAIN()
        return value


def resolver_table():
    return {
        ("example.com", "NS"): Answer(["ns1.example.com.", "ns2.example.com.", "ns3.example.com."]),
        ("example.com", "A"): Answer(["192.0.2.10"]),
    }


def run_whois(entry=FAKE_WHOIS_ENTRY, extra_env=None):
    with patch("recon.dns_enum._make_resolver", lambda *a, **k: FakeResolver(resolver_table())), \
         patch("recon.dns_enum._forward_confirm", return_value=MagicMock()), \
         patch("recon.rdap._default_fetch", side_effect=RuntimeError("no network")), \
         patch("recon.registration._default_whois", side_effect=lambda d, **kw: dict(entry)):
        return runner.invoke(app, ["whois", "example.com"], env={"COLUMNS": "200", **(extra_env or {})})


class TestWhoisCliRendering:
    def test_sections_and_values_are_displayed(self):
        result = run_whois()
        out = flat(result.output)
        assert result.exit_code == 0, result.output
        for expected in ("Titulaire", "Contact administratif", "Contact technique",
                         "Contact de facturation", "Contact abus",
                         "Jane Example", "Example Trading Co", "1 Fictional Avenue",
                         "owner@example.com", "+000.0000000", "John Sample",
                         "Identifiant du domaine (registre)", "00000000-FAKE-DOMAIN",
                         "Serveur WHOIS du registre", "whois.registry.example"):
            assert expected in out, expected

    def test_masked_tech_contact_is_labelled(self):
        out = flat(run_whois().output)
        assert "Contact technique" in out
        assert MASKED_LABEL in out

    def test_absent_billing_contact_is_labelled_absent(self):
        out = flat(run_whois().output)
        assert "Absent du WHOIS" in out

    def test_nameserver_gap_and_expiry_lines_are_shown(self):
        out = flat(run_whois().output)
        assert "Écart des serveurs de noms" in out
        assert "ns3.example.com" in out
        assert "jour(s)" in out  # countdown in the domain table, whatever the clock

    def test_raw_whois_text_is_never_printed(self):
        out = run_whois().output
        assert "Registrant Street:" not in out
        assert "Domain Name:" not in out
        assert "{" not in out

    def test_contact_text_is_escaped_not_interpreted_as_markup(self):
        entry = dict(FAKE_WHOIS_ENTRY, raw=FAKE_RAW_WHOIS.replace("Jane Example", "[bold]Jane[/bold] Example"))
        out = flat(run_whois(entry).output)
        assert "[bold]Jane[/bold] Example" in out
