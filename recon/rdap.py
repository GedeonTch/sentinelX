"""
recon/rdap.py — RDAP lookup of domain registration data.

Role: find the RDAP service declared for a domain's TLD in the IANA bootstrap
file (RFC 9224), fetch the domain object (RFC 9083) and extract the few
fields NetLab needs. Redacted fields (RFC 9537) are reported as masked.

Rules:
- HTTPS only: plain HTTP bootstrap URLs are never used, redirects must stay HTTPS.
- Bounded timeout, bounded response size, bounded redirects.
- A transport failure is never reported as "the domain does not exist".
- The bootstrap file is cached in memory for its lifetime (Cache-Control
  max-age, clamped to 1 h .. 7 days, default 24 h). Nothing is written to disk.
- Raw JSON is parsed here and dropped: it is never returned to the caller.

Network access is isolated in ``_default_fetch``; tests inject a fake fetch.
"""

from __future__ import annotations

import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Tuple

BOOTSTRAP_URL: str = "https://data.iana.org/rdap/dns.json"
HTTP_TIMEOUT_SECONDS: int = 10
MAX_RESPONSE_BYTES: int = 512 * 1024
MAX_REDIRECTS: int = 3
BOOTSTRAP_TTL_DEFAULT: int = 24 * 3600
BOOTSTRAP_TTL_MIN: int = 3600
BOOTSTRAP_TTL_MAX: int = 7 * 24 * 3600
USER_AGENT: str = "SentinelX-netlab (RDAP lookup)"

_DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})")
_MAX_AGE_RE = re.compile(r"max-age=(\d+)")


class RdapTransportError(Exception):
    """Transport-level failure. ``kind`` is 'timeout', 'unavailable' or 'too_large'."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


@dataclass
class FetchResult:
    """Minimal HTTP response: status code, lower-cased headers, bounded body."""

    status: int
    headers: Dict[str, str]
    body: bytes


@dataclass
class RdapData:
    """Fields extracted from one RDAP domain object.

    ``masked`` contains the categories redacted by the registry:
    'registrant' and/or 'abuse'. Absence of a value without a mask means
    'not communicated', which is different from 'masked'.
    """

    domain: Optional[str] = None
    statuses: List[str] = field(default_factory=list)
    created: Optional[str] = None
    updated: Optional[str] = None
    expires: Optional[str] = None
    registrar: Optional[str] = None
    organization: Optional[str] = None
    abuse_email: Optional[str] = None
    nameservers: List[str] = field(default_factory=list)
    dnssec: Optional[str] = None
    masked: FrozenSet[str] = frozenset()


@dataclass
class RdapResult:
    """Outcome of one RDAP query. ``status`` is always set, never an exception."""

    status: str
    data: Optional[RdapData] = None


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise RdapTransportError("unavailable")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _default_fetch(url: str) -> FetchResult:
    """Fetch one HTTPS URL with a bounded timeout and bounded body size."""
    if not url.startswith("https://"):
        raise RdapTransportError("unavailable")
    opener = urllib.request.build_opener(_HttpsOnlyRedirect())
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/rdap+json, application/json;q=0.8",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with opener.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise RdapTransportError("too_large")
            headers = {k.lower(): v for k, v in response.headers.items()}
            return FetchResult(status=response.status, headers=headers, body=body)
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_RESPONSE_BYTES) if exc.fp is not None else b""
        headers = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
        return FetchResult(status=exc.code, headers=headers, body=body)
    except (socket.timeout, TimeoutError):
        raise RdapTransportError("timeout")
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (socket.timeout, TimeoutError)):
            raise RdapTransportError("timeout")
        raise RdapTransportError("unavailable")
    except OSError:
        raise RdapTransportError("unavailable")


class RdapClient:
    """RDAP client with an in-memory bootstrap cache.

    Args:
        fetch: Callable(url) -> FetchResult. Defaults to the HTTPS fetcher.
        now: Monotonic clock, injectable for tests.
    """

    def __init__(
        self,
        fetch: Optional[Callable[[str], FetchResult]] = None,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        self._fetch = fetch or _default_fetch
        self._now = now
        self._cache: Optional[Tuple[float, Dict[str, str], FrozenSet[str]]] = None

    # -- bootstrap -----------------------------------------------------------

    def _bootstrap(self) -> Tuple[Optional[Dict[str, str]], Optional[FrozenSet[str]], str]:
        """Return (https_map, insecure_tlds, error_status). error_status '' on success."""
        if self._cache is not None and self._now() < self._cache[0]:
            return self._cache[1], self._cache[2], ""
        try:
            response = self._fetch(BOOTSTRAP_URL)
        except RdapTransportError as exc:
            return None, None, "timeout" if exc.kind == "timeout" else "bootstrap_unavailable"
        if response.status != 200:
            return None, None, "bootstrap_unavailable"
        try:
            document = json.loads(response.body.decode("utf-8"))
            services = document["services"]
            if not isinstance(services, list):
                raise ValueError("services")
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            return None, None, "malformed"

        https_map: Dict[str, str] = {}
        insecure: set = set()
        for entry in services:
            if not (isinstance(entry, list) and len(entry) == 2):
                continue
            tlds, urls = entry
            if not (isinstance(tlds, list) and isinstance(urls, list)):
                continue
            secure_urls = [u for u in urls if isinstance(u, str) and u.startswith("https://")]
            for tld in tlds:
                if not isinstance(tld, str):
                    continue
                key = tld.lower()
                if secure_urls:
                    base = secure_urls[0] if secure_urls[0].endswith("/") else secure_urls[0] + "/"
                    https_map.setdefault(key, base)
                elif urls:
                    insecure.add(key)

        ttl = self._ttl(response.headers)
        self._cache = (self._now() + ttl, https_map, frozenset(insecure))
        return https_map, frozenset(insecure), ""

    @staticmethod
    def _ttl(headers: Dict[str, str]) -> float:
        match = _MAX_AGE_RE.search(headers.get("cache-control", ""))
        if not match:
            return float(BOOTSTRAP_TTL_DEFAULT)
        return float(min(max(int(match.group(1)), BOOTSTRAP_TTL_MIN), BOOTSTRAP_TTL_MAX))

    # -- domain query --------------------------------------------------------

    def query_domain(self, domain: str) -> RdapResult:
        """Query the RDAP service of the domain's TLD. Never raises for network errors."""
        tld = domain.rsplit(".", 1)[-1].lower()
        https_map, insecure, error = self._bootstrap()
        if error:
            return RdapResult(status=error)
        assert https_map is not None and insecure is not None
        if tld in https_map:
            base = https_map[tld]
        elif tld in insecure:
            return RdapResult(status="rdap_non_https")
        else:
            return RdapResult(status="tld_without_rdap")

        url = f"{base}domain/{domain}"
        try:
            response = self._fetch(url)
        except RdapTransportError as exc:
            mapping = {"timeout": "timeout", "unavailable": "unavailable", "too_large": "malformed"}
            return RdapResult(status=mapping.get(exc.kind, "error"))

        if response.status == 404:
            return RdapResult(status="not_found")
        if response.status == 429:
            return RdapResult(status="rate_limited")
        if response.status >= 500:
            return RdapResult(status="unavailable")
        if response.status != 200:
            return RdapResult(status="error")
        try:
            document = json.loads(response.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return RdapResult(status="malformed")
        if not isinstance(document, dict) or document.get("objectClassName") != "domain":
            return RdapResult(status="malformed")
        return RdapResult(status="ok", data=parse_domain_object(document))


# ---------------------------------------------------------------------------
# RFC 9083 domain object parsing (pure functions, no I/O)
# ---------------------------------------------------------------------------

def _date10(value: Any) -> Optional[str]:
    if isinstance(value, str):
        match = _DATE_RE.match(value)
        if match:
            return match.group(1)
    return None


def _vcard_value(entity: Dict[str, Any], prop_name: str) -> Optional[str]:
    """Return the first string value of a vCard property (jCard), if any."""
    card = entity.get("vcardArray")
    if not (isinstance(card, list) and len(card) == 2 and isinstance(card[1], list)):
        return None
    for prop in card[1]:
        if isinstance(prop, list) and len(prop) >= 4 and prop[0] == prop_name:
            value = prop[3]
            if isinstance(value, str) and value.strip():
                return value.strip()
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item.strip():
                        return item.strip()
    return None


def _walk_entities(entities: Any) -> List[Dict[str, Any]]:
    """Flatten RFC 9083 entities, including nested ones, in document order."""
    flat: List[Dict[str, Any]] = []
    if not isinstance(entities, list):
        return flat
    for entity in entities:
        if isinstance(entity, dict):
            flat.append(entity)
            flat.extend(_walk_entities(entity.get("entities")))
    return flat


def parse_domain_object(document: Dict[str, Any]) -> RdapData:
    """Extract NetLab fields from an RFC 9083 domain object."""
    data = RdapData()
    ldh = document.get("ldhName")
    if isinstance(ldh, str) and ldh.strip():
        data.domain = ldh.strip().rstrip(".").lower()

    statuses = document.get("status")
    if isinstance(statuses, list):
        data.statuses = [s.strip() for s in statuses if isinstance(s, str) and s.strip()]

    events = document.get("events")
    if isinstance(events, list):
        for event in events:
            if not isinstance(event, dict):
                continue
            action = str(event.get("eventAction", "")).lower()
            date = _date10(event.get("eventDate"))
            if action == "registration" and date:
                data.created = data.created or date
            elif action == "last changed" and date:
                data.updated = data.updated or date
            elif action == "expiration" and date:
                data.expires = data.expires or date

    nameservers: List[str] = []
    raw_ns = document.get("nameservers")
    if isinstance(raw_ns, list):
        for ns in raw_ns:
            if isinstance(ns, dict) and isinstance(ns.get("ldhName"), str):
                name = ns["ldhName"].strip().rstrip(".").lower()
                if name and name not in nameservers:
                    nameservers.append(name)
    data.nameservers = nameservers

    secure = document.get("secureDNS")
    if isinstance(secure, dict) and isinstance(secure.get("delegationSigned"), bool):
        data.dnssec = "oui" if secure["delegationSigned"] else "non"

    for entity in _walk_entities(document.get("entities")):
        roles = entity.get("roles") if isinstance(entity.get("roles"), list) else []
        if "registrar" in roles and data.registrar is None:
            data.registrar = _vcard_value(entity, "fn") or _vcard_value(entity, "org")
        if "registrant" in roles and data.organization is None:
            data.organization = _vcard_value(entity, "org")
        if "abuse" in roles and data.abuse_email is None:
            data.abuse_email = _vcard_value(entity, "email")

    masked = set()
    redacted = document.get("redacted")
    if isinstance(redacted, list):
        for item in redacted:
            if not isinstance(item, dict):
                continue
            description = ""
            name = item.get("name")
            if isinstance(name, dict) and isinstance(name.get("description"), str):
                description = name["description"]
            text = " ".join(
                str(part) for part in (item.get("prePath"), item.get("postPath"), description)
                if part
            ).lower()
            if "registrant" in text:
                masked.add("registrant")
            if "abuse" in text:
                masked.add("abuse")
            if "email" in text and "registrant" not in text and "abuse" not in text:
                masked.add("abuse")
    data.masked = frozenset(masked)
    return data
