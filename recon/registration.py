"""
recon/registration.py — domain registration summary (RDAP first, WHOIS complement).

Two independent sources, each with its own status, timeout and error handling:
- RDAP (recon/rdap.py) is the primary source.
- WHOIS (python-whois, inc_raw=True, explicit timeout) only fills fields that
  RDAP does not provide. It never overrides an RDAP value, and never reveals a
  field that the registry masked through RDAP (RFC 9537).

Conflicts are shown with their provenance. Raw JSON and raw WHOIS text are
parsed and dropped: they are not returned, displayed or persisted.

A network failure is a status, not evidence that the domain does not exist.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

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


def _whois_fields(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Map a python-whois entry to NetLab fields. None when nothing is parseable."""
    if not _text(entry.get("domain_name")):
        return None
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
    raw = entry.get("raw")
    if isinstance(raw, str) and len(raw.encode("utf-8", "replace")) > WHOIS_MAX_RAW_BYTES:
        return SourceStatus(SOURCE_WHOIS, "malformed", "réponse trop volumineuse"), None
    entry.pop("raw", None)  # raw text is never kept

    fields = _whois_fields(entry)
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
