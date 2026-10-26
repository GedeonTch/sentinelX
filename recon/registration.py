"""
recon/registration.py — domain registration summary (RDAP first, WHOIS complement).

Two independent sources, each with its own status, timeout and error handling:
- RDAP (recon/rdap.py) is the primary source.
- WHOIS (python-whois, inc_raw=True, explicit timeout) only fills fields that
  RDAP does not provide. It never overrides an RDAP value, and never reveals a
  field that the registry masked through RDAP (RFC 9537).

Conflicts are shown with their provenance. Raw JSON and raw WHOIS text are
parsed and dropped: they are not returned, displayed or persisted.

Contacts (registrant, administrative, technical, billing, abuse) are public
registration data. They are displayed by `whois` only: they are not part of
the Finding evidence, nor of any saved or exported object.

A network failure is a status, not evidence that the domain does not exist.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Tuple

from recon.rdap import RdapClient, RdapData, RdapResult

WHOIS_TIMEOUT_SECONDS: int = 10
WHOIS_MAX_RAW_BYTES: int = 512 * 1024

SOURCE_RDAP: str = "RDAP"
SOURCE_WHOIS: str = "WHOIS"
MASKED_LABEL: str = "Masqué par le registre"
NOT_COMMUNICATED_LABEL: str = "Non communiqué"
UNAVAILABLE_LABEL: str = "Non disponible"
TIMEOUT_LABEL: str = "Source en timeout"

FIELD_LABELS: Dict[str, str] = {
    "registrar": "Registrar",
    "created": "Création",
    "updated": "Dernière modification",
    "expires": "Expiration",
    "statuses": "Statuts",
    "nameservers": "Serveurs de noms",
    "dnssec": "DNSSEC",
    "organization": "Organisation du titulaire",
    "abuse_contact": "Contact abus",
}
FIELD_ORDER: Tuple[str, ...] = tuple(FIELD_LABELS)
_LIST_FIELDS = frozenset({"statuses", "nameservers"})

EXPIRY_WARNING_DAYS: int = 180

CONTACT_ROLES: Tuple[str, ...] = ("registrant", "admin", "tech", "billing", "abuse")
CONTACT_ROLE_LABELS: Dict[str, str] = {
    "registrant": "Titulaire",
    "admin": "Contact administratif",
    "tech": "Contact technique",
    "billing": "Contact de facturation",
    "abuse": "Contact abus",
}
CONTACT_FIELDS: Tuple[str, ...] = (
    "name", "organization", "street", "city", "state", "postal_code",
    "country", "phone", "fax", "email", "handle",
)
ADDRESS_FIELDS: Tuple[str, ...] = ("street", "postal_code", "city", "state", "country")
# (label, field) rows of a contact section, in display order.
CONTACT_ROW_SPEC: Tuple[Tuple[str, Optional[str]], ...] = (
    ("Nom", "name"),
    ("Organisation", "organization"),
    ("Adresse physique", None),
    ("Téléphone", "phone"),
    ("Fax", "fax"),
    ("Email", "email"),
    ("Identifiant de contact", "handle"),
)
EXTRA_LABELS: Dict[str, str] = {
    "domain_id": "Identifiant du domaine (registre)",
    "registry_server": "Serveur WHOIS du registre",
}

STATUS_LABELS: Dict[str, str] = {
    "ok": "OK",
    "not_found": "domaine introuvable selon le serveur compétent",
    "tld_without_rdap": "TLD sans service RDAP déclaré",
    "rdap_non_https": "service RDAP non HTTPS, refusé",
    "rate_limited": "limitation de débit (429)",
    "unavailable": "service indisponible",
    "bootstrap_unavailable": "annuaire RDAP indisponible",
    "timeout": "timeout",
    "malformed": "réponse mal formée",
    "error": "erreur",
    "no_data": "aucune donnée exploitable",
    "tld_unsupported": "TLD non géré par WHOIS",
    "private_registry": "registre privé, WHOIS non disponible",
    "skipped": "non interrogé",
}

_DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})")
_STATUS_SPLIT_RE = re.compile(r"\s+https?://")


@dataclass
class SourceStatus:
    name: str
    status: str
    detail: str = ""

    @property
    def label(self) -> str:
        return STATUS_LABELS.get(self.status, self.status)


@dataclass
class FieldValue:
    value: Any
    source: str
    note: str = ""
    masked: bool = False


@dataclass
class RegistrationSummary:
    domain: str
    collected_at: str
    sources: List[SourceStatus]
    fields: Dict[str, Optional[FieldValue]]
    divergences: List[str] = field(default_factory=list)
    # role -> {contact field: FieldValue}; roles masked by RDAP are listed apart.
    contacts: Dict[str, Dict[str, FieldValue]] = field(default_factory=dict)
    masked_contact_roles: FrozenSet[str] = frozenset()
    # registry identifiers from WHOIS: 'domain_id', 'registry_server'
    extra: Dict[str, FieldValue] = field(default_factory=dict)

    @property
    def has_data(self) -> bool:
        return any(value is not None for value in self.fields.values())

    @property
    def primary_source(self) -> Optional[str]:
        statuses = {s.name: s.status for s in self.sources}
        if statuses.get(SOURCE_RDAP) == "ok":
            return SOURCE_RDAP
        if statuses.get(SOURCE_WHOIS) == "ok":
            return SOURCE_WHOIS
        return None

    def source_status(self, name: str) -> Optional[SourceStatus]:
        for source in self.sources:
            if source.name == name:
                return source
        return None


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _status_key(text: str) -> str:
    """Comparison key for an EPP status: letters only, lower-case, no URL."""
    head = _STATUS_SPLIT_RE.split(text.strip(), maxsplit=1)[0]
    return re.sub(r"[^a-z]", "", head.lower())


def _status_display_whois(text: str) -> str:
    head = _STATUS_SPLIT_RE.split(text.strip(), maxsplit=1)[0]
    spaced = re.sub(r"(?<!^)([A-Z])", r" \1", head)
    return " ".join(spaced.lower().split())


def _ns_key(text: str) -> str:
    return text.strip().rstrip(".").lower()


def _dedupe(values: List[str], key: Callable[[str], str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for value in values:
        k = key(value)
        if k and k not in seen:
            seen.add(k)
            out.append(value)
    return out


def _text_key(value: str) -> str:
    return " ".join(value.lower().split())


def _first(value: Any) -> Any:
    if isinstance(value, (list, tuple, set)):
        items = [item for item in value if item not in (None, "")]
        return items[0] if items else None
    return value


def _date_text(value: Any) -> Optional[str]:
    value = _first(value)
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, str):
        match = _DATE_RE.match(value.strip())
        if match:
            return match.group(1)
    return None


def _text(value: Any) -> Optional[str]:
    value = _first(value)
    if isinstance(value, str) and value.strip():
        return " ".join(value.split())
    return None


def _text_list(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if isinstance(v, str) and v.strip()]
    return []


# ---------------------------------------------------------------------------
# WHOIS source
# ---------------------------------------------------------------------------

def _default_whois(domain: str, **kwargs: Any) -> Dict[str, Any]:
    import whois  # local import: keeps module import light and test-friendly

    return whois.whois(domain, **kwargs)


_WHOIS_CONTACT_RE = re.compile(
    r"^(Registrant|Admin|Administrative|Tech|Technical|Billing|Abuse)\s+"
    r"(Name|Organi[sz]ation|Street\d*|City|State/Province|Postal Code|Country|Phone|Fax|Email|ID)"
    r"\s*:\s*(.*?)\s*$",
    re.IGNORECASE,
)
_WHOIS_REGISTRY_ID_RE = re.compile(
    r"^Registry\s+(Registrant|Admin|Tech|Billing)\s+ID\s*:\s*(.*?)\s*$", re.IGNORECASE
)
_WHOIS_DOMAIN_ID_RE = re.compile(r"^Registry\s+Domain\s+ID\s*:\s*(.*?)\s*$", re.IGNORECASE)
_WHOIS_REGISTRY_SERVER_RE = re.compile(
    r"^Registry\s+WHOIS\s+Server\s*:\s*(.*?)\s*$", re.IGNORECASE
)
_WHOIS_ROLE_MAP: Dict[str, str] = {
    "registrant": "registrant",
    "admin": "admin",
    "administrative": "admin",
    "tech": "tech",
    "technical": "tech",
    "billing": "billing",
    "abuse": "abuse",
}
_WHOIS_FIELD_MAP: Dict[str, str] = {
    "name": "name",
    "organization": "organization",
    "organisation": "organization",
    "city": "city",
    "state/province": "state",
    "postal code": "postal_code",
    "country": "country",
    "phone": "phone",
    "fax": "fax",
    "email": "email",
    "id": "handle",
}
_MASK_RE = re.compile(r"redact|privacy|masked|withheld|not\s+disclosed", re.IGNORECASE)


def _add_contact_value(card: Dict[str, Tuple[Optional[str], bool]], name: str, value: str) -> None:
    """Record one WHOIS contact line. A masked placeholder yields to a real value."""
    if not value:
        return
    if _MASK_RE.search(value):
        card.setdefault(name, (None, True))
        return
    if name == "email" and "@" not in value:
        return  # e.g. "Please query the RDDS service": not an address
    current = card.get(name)
    if current is None or current[1]:
        card[name] = (value, False)
    elif name == "street" and value not in current[0]:
        card[name] = (f"{current[0]}, {value}", False)


def parse_whois_contacts(raw: str) -> Dict[str, Any]:
    """Extract contacts and registry identifiers from raw WHOIS text.

    Returns {"contacts": {role: {field: (value | None, masked)}},
             "extra": {"domain_id": ..., "registry_server": ...}}.
    The raw text is only read here; it is never returned.
    """
    contacts: Dict[str, Dict[str, Tuple[Optional[str], bool]]] = {}
    extra: Dict[str, str] = {}
    for line in raw.splitlines():
        text = line.strip()
        match = _WHOIS_CONTACT_RE.match(text)
        if match:
            role = _WHOIS_ROLE_MAP[match.group(1).lower()]
            key = match.group(2).lower()
            name = "street" if key.startswith("street") else _WHOIS_FIELD_MAP[key]
            value = " ".join(match.group(3).split())
            _add_contact_value(contacts.setdefault(role, {}), name, value)
            continue
        match = _WHOIS_REGISTRY_ID_RE.match(text)
        if match:
            role = _WHOIS_ROLE_MAP[match.group(1).lower()]
            value = " ".join(match.group(2).split())
            if value and not _MASK_RE.search(value):
                card = contacts.setdefault(role, {})
                if "handle" not in card or card["handle"][1]:
                    card["handle"] = (value, False)
            continue
        match = _WHOIS_DOMAIN_ID_RE.match(text)
        if match and match.group(1):
            extra.setdefault("domain_id", match.group(1))
            continue
        match = _WHOIS_REGISTRY_SERVER_RE.match(text)
        if match and match.group(1):
            extra.setdefault("registry_server", match.group(1).lower())
    return {"contacts": contacts, "extra": extra}


def _whois_fields(entry: Dict[str, Any], raw: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Map a python-whois entry to NetLab fields. None when nothing is parseable."""
    if not _text(entry.get("domain_name")):
        return None
    parsed = parse_whois_contacts(raw) if raw else {"contacts": {}, "extra": {}}
    statuses = _text_list(entry.get("status"))
    nameservers = [_ns_key(ns) for ns in _text_list(entry.get("name_servers"))]
    dnssec_raw = (_text(entry.get("dnssec")) or "").lower()
    if "unsigned" in dnssec_raw or dnssec_raw == "no":
        dnssec = "non"
    elif dnssec_raw.startswith("signed") or dnssec_raw == "yes":
        dnssec = "oui"
    else:
        dnssec = None

    masked: List[str] = []
    org = _text(entry.get("org"))
    if org and "redact" in org.lower():
        org = None
        masked.append("organization")
    abuse = None
    for mail in _text_list(entry.get("emails")):
        if "redact" in mail.lower():
            if "abuse" not in masked:
                masked.append("abuse_contact")
            continue
        if "abuse" in mail.lower() and abuse is None:
            abuse = mail.strip().lower()

    return {
        "registrar": _text(entry.get("registrar")),
        "created": _date_text(entry.get("creation_date")),
        "updated": _date_text(entry.get("updated_date")),
        "expires": _date_text(entry.get("expiration_date")),
        "statuses": _dedupe(statuses, _status_key),
        "nameservers": _dedupe(nameservers, _ns_key),
        "dnssec": dnssec,
        "organization": org,
        "abuse_contact": abuse,
        "masked": masked,
        "contacts": parsed["contacts"],
        "extra": parsed["extra"],
    }


def query_whois(
    domain: str,
    whois_func: Optional[Callable[..., Dict[str, Any]]] = None,
) -> Tuple[SourceStatus, Optional[Dict[str, Any]]]:
    """Query WHOIS once, with an explicit timeout. Never raises."""
    func = whois_func or _default_whois
    try:
        entry = func(domain, inc_raw=True, timeout=WHOIS_TIMEOUT_SECONDS)
    except (socket.timeout, TimeoutError):
        return SourceStatus(SOURCE_WHOIS, "timeout"), None
    except Exception as exc:  # classified below; never propagated
        return SourceStatus(SOURCE_WHOIS, _classify_whois_error(exc)), None

    if not isinstance(entry, dict):
        return SourceStatus(SOURCE_WHOIS, "malformed"), None
    raw = entry.pop("raw", None)  # read below, never kept
    if isinstance(raw, str) and len(raw.encode("utf-8", "replace")) > WHOIS_MAX_RAW_BYTES:
        return SourceStatus(SOURCE_WHOIS, "malformed", "réponse trop volumineuse"), None

    fields = _whois_fields(entry, raw if isinstance(raw, str) else None)
    if fields is None:
        return SourceStatus(SOURCE_WHOIS, "no_data"), None
    return SourceStatus(SOURCE_WHOIS, "ok"), fields


def _classify_whois_error(exc: BaseException) -> str:
    try:
        from whois.exceptions import (
            UnknownTldError,
            WhoisDomainNotFoundError,
            WhoisQuotaExceededError,
            FailedParsingWhoisOutputError,
            WhoisUnknownDateFormatError,
        )
    except ImportError:  # pragma: no cover - dependency missing
        return "error"
    if isinstance(exc, WhoisDomainNotFoundError):
        return "not_found"
    if isinstance(exc, UnknownTldError):
        return "tld_unsupported"
    if isinstance(exc, WhoisQuotaExceededError):
        return "rate_limited"
    if isinstance(exc, (FailedParsingWhoisOutputError, WhoisUnknownDateFormatError)):
        return "malformed"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    return "error"


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------

def _rdap_fields(data: Optional[RdapData]) -> Dict[str, Any]:
    if data is None:
        return {}
    masked = []
    if "registrant" in data.masked:
        masked.append("organization")
    if "abuse" in data.masked:
        masked.append("abuse_contact")
    return {
        "contacts": data.contacts,
        "masked_roles": {r for r in data.masked if r in CONTACT_ROLES},
        "registrar": data.registrar,
        "created": data.created,
        "updated": data.updated,
        "expires": data.expires,
        "statuses": _dedupe(data.statuses, _status_key),
        "nameservers": _dedupe(data.nameservers, _ns_key),
        "dnssec": data.dnssec,
        "organization": data.organization,
        "abuse_contact": data.abuse_email,
        "masked": masked,
    }


def _display_value(name: str, value: Any) -> str:
    if name == "statuses":
        return ", ".join(value)
    if name == "nameservers":
        return ", ".join(value)
    return str(value)


def _same(name: str, a: Any, b: Any) -> bool:
    if name == "statuses":
        return {_status_key(x) for x in a} == {_status_key(x) for x in b}
    if name == "nameservers":
        return {_ns_key(x) for x in a} == {_ns_key(x) for x in b}
    return _text_key(str(a)) == _text_key(str(b))


def _merge_contacts(
    rdap_ok: bool,
    rdap_contacts: Dict[str, Dict[str, str]],
    rdap_masked_roles: FrozenSet[str],
    whois_ok: bool,
    whois_contacts: Dict[str, Dict[str, Tuple[Optional[str], bool]]],
) -> Tuple[Dict[str, Dict[str, FieldValue]], FrozenSet[str]]:
    """Contacts field by field: RDAP first, WHOIS completes. A role masked by
    RDAP is never completed from WHOIS (no contournement of RFC 9537 masks).
    Contact conflicts are not listed as divergences: they are personal data
    and must not reach the Finding evidence."""
    contacts: Dict[str, Dict[str, FieldValue]] = {}
    masked_roles = set()
    for role in CONTACT_ROLES:
        if rdap_ok and role in rdap_masked_roles:
            masked_roles.add(role)
            continue
        rdap_card = rdap_contacts.get(role, {}) if rdap_ok else {}
        whois_card = whois_contacts.get(role, {}) if whois_ok else {}
        out: Dict[str, FieldValue] = {}
        for name in CONTACT_FIELDS:
            if rdap_card.get(name):
                out[name] = FieldValue(rdap_card[name], SOURCE_RDAP)
            elif name in whois_card:
                value, masked = whois_card[name]
                if masked:
                    out[name] = FieldValue(MASKED_LABEL, SOURCE_WHOIS, masked=True)
                elif value:
                    out[name] = FieldValue(value, SOURCE_WHOIS)
        if out:
            contacts[role] = out
    return contacts, frozenset(masked_roles)


def merge_registration(
    domain: str,
    rdap: RdapResult,
    whois_status: SourceStatus,
    whois_fields: Optional[Dict[str, Any]],
    collected_at: str,
) -> RegistrationSummary:
    """Field-by-field merge: RDAP primary, WHOIS complement, conflicts shown."""
    rdap_status = rdap.status
    rdap_ok = rdap_status == "ok"
    rdap_notfound = rdap_status == "not_found"
    rf = _rdap_fields(rdap.data if rdap_ok else None)
    wf = whois_fields or {}
    whois_ok = whois_status.status == "ok"

    fields: Dict[str, Optional[FieldValue]] = {}
    divergences: List[str] = []
    contacts, masked_roles = _merge_contacts(
        rdap_ok,
        rf.get("contacts", {}),
        rf.get("masked_roles", frozenset()),
        whois_ok,
        wf.get("contacts", {}),
    )
    extra: Dict[str, FieldValue] = {}
    if whois_ok:
        for key in EXTRA_LABELS:
            value = wf.get("extra", {}).get(key)
            if value:
                extra[key] = FieldValue(value, SOURCE_WHOIS)

    for name in FIELD_ORDER:
        label = FIELD_LABELS[name]
        rdap_value = rf.get(name)
        whois_value = wf.get(name) if whois_ok else None
        rdap_masked = rdap_ok and name in rf.get("masked", [])
        whois_masked = whois_ok and name in wf.get("masked", [])

        if rdap_masked:
            fields[name] = FieldValue(MASKED_LABEL, SOURCE_RDAP, masked=True)
            continue
        if rdap_value:
            if whois_value and not _same(name, rdap_value, whois_value):
                divergences.append(
                    f"{label} : RDAP « {_display_value(name, rdap_value)} » "
                    f"≠ WHOIS « {_display_value(name, whois_value)} »"
                )
            fields[name] = FieldValue(rdap_value, SOURCE_RDAP)
            continue
        if whois_masked:
            fields[name] = FieldValue(MASKED_LABEL, SOURCE_WHOIS, masked=True)
            continue
        if whois_value:
            note = "à confirmer : RDAP introuvable" if rdap_notfound else ""
            fields[name] = FieldValue(whois_value, SOURCE_WHOIS, note)
            continue
        fields[name] = None

    if rdap_notfound and whois_ok and wf:
        divergences.insert(
            0,
            "RDAP : domaine introuvable ; WHOIS : données présentes (à confirmer)",
        )

    # Lists: an empty list means "not communicated", not an empty value.
    for name in _LIST_FIELDS:
        value = fields.get(name)
        if value is not None and not value.value:
            fields[name] = None
    for name in ("statuses",):
        value = fields.get(name)
        if value is not None and value.source == SOURCE_WHOIS:
            value.value = [_status_display_whois(v) for v in value.value]

    sources = [
        SourceStatus(SOURCE_RDAP, rdap_status),
        whois_status,
    ]
    return RegistrationSummary(
        domain=domain,
        collected_at=collected_at,
        sources=sources,
        fields=fields,
        divergences=divergences,
        contacts=contacts,
        masked_contact_roles=masked_roles,
        extra=extra,
    )


def lookup_registration(
    domain: str,
    rdap_client: Optional[RdapClient] = None,
    whois_func: Optional[Callable[..., Dict[str, Any]]] = None,
) -> RegistrationSummary:
    """Query RDAP and WHOIS independently, then merge. Never raises for network errors."""
    client = rdap_client or RdapClient()
    try:
        rdap = client.query_domain(domain)
    except Exception:  # defensive: a client bug must not hide the WHOIS source
        rdap = RdapResult(status="error")
    whois_status, whois_fields = query_whois(domain, whois_func)
    collected_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return merge_registration(domain, rdap, whois_status, whois_fields, collected_at)


# ---------------------------------------------------------------------------
# Presentation helpers (plain text, no markup)
# ---------------------------------------------------------------------------

def field_rows(summary: RegistrationSummary) -> List[Tuple[str, str, str]]:
    """One (label, value, source) row per registration field, in stable order."""
    rows: List[Tuple[str, str, str]] = []
    for name in FIELD_ORDER:
        label = FIELD_LABELS[name]
        value = summary.fields.get(name)
        if value is None:
            rows.append((label, empty_field_message(summary), "—"))
            continue
        if value.masked:
            rows.append((label, MASKED_LABEL, value.source))
            continue
        source = value.source
        if value.note:
            source = f"{value.source} ({value.note})"
        rows.append((label, _display_value(name, value.value), source))
    return rows


def summary_lines(summary: RegistrationSummary) -> List[str]:
    """Plain-text lines for the Finding evidence (no markup)."""
    return [
        f"{label} : {value} (source : {source})" if source != "—" else f"{label} : {value}"
        for label, value, source in field_rows(summary)
    ]


def empty_field_message(summary: RegistrationSummary) -> str:
    """Explain why no value exists, without treating a failed source as 'absent'."""
    if any(s.status == "ok" for s in summary.sources):
        return NOT_COMMUNICATED_LABEL
    if summary.sources and all(s.status == "timeout" for s in summary.sources):
        return TIMEOUT_LABEL
    return UNAVAILABLE_LABEL


def registration_evidence(summary: RegistrationSummary) -> str:
    lines = summary_lines(summary)
    lines.append(
        "Sources : "
        + " ; ".join(f"{s.name} {s.label}" for s in summary.sources)
    )
    lines.extend(f"Divergence : {d}" for d in summary.divergences)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Structured presentation (plain text; the CLI adds markup and escaping)
# ---------------------------------------------------------------------------

def absence_label(summary: RegistrationSummary) -> str:
    """Label for a contact value that no source supplied.

    'Absent du WHOIS' = a source answered without this value.
    'non fourni' = a source did not answer (timeout, error, no data).
    Masked values have their own label and never reach this function.
    """
    answered = [s.name for s in summary.sources if s.status == "ok"]
    if not answered:
        return empty_field_message(summary)
    text = "Absent du " + " et du ".join(answered)
    missing = [f"{s.name} ({s.label})" for s in summary.sources if s.status != "ok"]
    if missing:
        text += " ; non fourni par " + ", ".join(missing)
    return text


def _masked_row(label: str, source: str) -> Tuple[str, str, str]:
    return (label, MASKED_LABEL, source)


def _address_row(summary: RegistrationSummary, card: Dict[str, FieldValue]) -> Tuple[str, str, str]:
    label = "Adresse physique"
    present = [card[name] for name in ADDRESS_FIELDS if name in card and not card[name].masked]
    if not present:
        if any(card[name].masked for name in ADDRESS_FIELDS if name in card):
            return _masked_row(label, SOURCE_WHOIS)
        return (label, absence_label(summary), "—")
    def values(*names: str) -> List[str]:
        return [str(card[n].value) for n in names if n in card and not card[n].masked]

    parts = values("street") + [" ".join(values("postal_code", "city"))]
    parts = [p for p in parts if p] + values("state", "country")
    sources = sorted({fv.source for fv in present})
    return (label, ", ".join(parts), " / ".join(sources))


def contact_sections(summary: RegistrationSummary) -> List[Tuple[str, List[Tuple[str, str, str]]]]:
    """One (title, rows) section per contact role, in stable order.

    Row values: value, MASKED_LABEL, or an absence label (absent / non fourni).
    """
    sections: List[Tuple[str, List[Tuple[str, str, str]]]] = []
    for role in CONTACT_ROLES:
        title = CONTACT_ROLE_LABELS[role]
        if role in summary.masked_contact_roles:
            rows = [_masked_row(label, SOURCE_RDAP) for label, _ in CONTACT_ROW_SPEC]
            sections.append((title, rows))
            continue
        card = summary.contacts.get(role)
        if not card:
            sections.append((title, [("Contact", absence_label(summary), "—")]))
            continue
        rows: List[Tuple[str, str, str]] = []
        for label, name in CONTACT_ROW_SPEC:
            if name is None:
                rows.append(_address_row(summary, card))
                continue
            if name == "fax" and "fax" not in card:
                continue
            value = card.get(name)
            if value is None:
                rows.append((label, absence_label(summary), "—"))
            elif value.masked:
                rows.append(_masked_row(label, value.source))
            else:
                rows.append((label, str(value.value), value.source))
        sections.append((title, rows))
    return sections


def domain_rows(summary: RegistrationSummary, today: Optional[date] = None) -> List[Tuple[str, str, str]]:
    """Domain-level rows: field_rows without the contact fields (shown in
    their own sections), plus registry identifiers and the expiry countdown."""
    contact_labels = {FIELD_LABELS["organization"], FIELD_LABELS["abuse_contact"]}
    days = days_until_expiry(summary, today)
    rows: List[Tuple[str, str, str]] = []
    for label, value, source in field_rows(summary):
        if label in contact_labels:
            continue
        if label == FIELD_LABELS["expires"] and days is not None:
            value = f"{value} ({_expiry_text(days)})"
        rows.append((label, value, source))
    for key, label in EXTRA_LABELS.items():
        if key in summary.extra:
            rows.append((label, str(summary.extra[key].value), summary.extra[key].source))
    return rows


def days_until_expiry(summary: RegistrationSummary, today: Optional[date] = None) -> Optional[int]:
    value = summary.fields.get("expires")
    if value is None or value.masked or not isinstance(value.value, str):
        return None
    try:
        expires = date.fromisoformat(value.value)
    except ValueError:
        return None
    reference = today or datetime.now(timezone.utc).date()
    return (expires - reference).days


def _expiry_text(days: int) -> str:
    if days < 0:
        return f"expiré depuis {-days} jour(s)"
    return f"dans {days} jour(s)"


def expiry_notice(summary: RegistrationSummary, today: Optional[date] = None) -> Optional[str]:
    """Information line for an expiry within EXPIRY_WARNING_DAYS. Not a Finding."""
    days = days_until_expiry(summary, today)
    if days is None:
        return None
    if days < 0:
        return f"Date d'expiration dépassée ({_expiry_text(days)}) : information d'affichage, pas un constat."
    if days < EXPIRY_WARNING_DAYS:
        return (
            f"Expiration {_expiry_text(days)} (seuil : {EXPIRY_WARNING_DAYS} jours) : "
            "information d'affichage, pas un constat."
        )
    return None


def nameserver_gap(summary: RegistrationSummary, dns_nameservers: List[str]) -> Optional[str]:
    """Line describing a difference between DNS and registry name servers.

    Only when both sides answered. The registry side is the displayed NS field
    (RDAP first, WHOIS otherwise). Not a Finding.
    """
    registry = summary.fields.get("nameservers")
    if registry is None or registry.masked or not registry.value or not dns_nameservers:
        return None
    registry_keys = {_ns_key(ns) for ns in registry.value}
    dns_keys = {_ns_key(ns) for ns in dns_nameservers}
    if registry_keys == dns_keys:
        return None
    parts = []
    only_dns = sorted(dns_keys - registry_keys)
    only_registry = sorted(registry_keys - dns_keys)
    if only_dns:
        parts.append(f"présents en DNS seulement : {', '.join(only_dns)}")
    if only_registry:
        parts.append(
            f"présents chez le registre ({registry.source}) seulement : {', '.join(only_registry)}"
        )
    return "Écart des serveurs de noms : " + " ; ".join(parts) + " : à vérifier."
