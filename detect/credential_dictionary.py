"""Bounded candidate loading. No network, output, persistence or secret repr."""
from dataclasses import dataclass, field
import json
from pathlib import Path
import stat
from typing import Optional, Sequence

MAX_BYTES = 1024 * 1024
MAX_LINE = 16 * 1024
MAX_ENTRIES = 500
KNOWN = frozenset(('ftp', 'snmp', 'ssh', 'telnet', 'http', 'https', 'smb', 'rdp'))
SUPPORTED = frozenset(('ftp', 'snmp'))
CATALOG = Path(__file__).parent.parent / 'knowledge' / 'default_credentials.json'


class DictionaryError(ValueError):
    """A public, value-free preparation error."""


@dataclass(frozen=True)
class DocumentaryReference:
    url: str
    section: str


@dataclass(frozen=True)
class CatalogProvenance:
    """Profile-level metadata only: never a candidate index/hash or credential."""
    profile_id: str
    catalog_version: str
    references: tuple[DocumentaryReference, ...]

    def as_evidence(self) -> dict:
        return {
            'profile_id': self.profile_id,
            'catalog_version': self.catalog_version,
            'documentation': [{'url': ref.url, 'section': ref.section} for ref in self.references],
        }


@dataclass(frozen=True, repr=False)
class Candidate:
    service: str
    username: str = field(default='', repr=False)
    password: str = field(default='', repr=False)
    domain: str = field(default='', repr=False)
    community: str = field(default='', repr=False)
    qualified: bool = False
    provenance: Optional[CatalogProvenance] = None

    def identity(self) -> tuple:
        # This is the conservative *attempt* identity, not the exact vault identity.
        return ('snmp', self.community) if self.service == 'snmp' else ('account', self.domain.casefold(), self.username.casefold())

    def secret(self) -> str:
        return self.community if self.service == 'snmp' else self.password


def _object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise DictionaryError('Duplicate field')
        result[key] = value
    return result


def _candidate(row: object) -> Candidate:
    if not isinstance(row, dict) or row.get('service') not in KNOWN:
        raise DictionaryError('Invalid service or object')
    service = row['service']
    required = {'service', 'community'} if service == 'snmp' else {'service', 'username', 'password'}
    optional = {'domain'} if service in ('smb', 'rdp') else set()
    if not required <= row.keys() or row.keys() - required - optional:
        raise DictionaryError('Missing, unknown or incompatible field')
    if any(not isinstance(value, str) for value in row.values()):
        raise DictionaryError('Fields must be strings')
    for key, value in row.items():
        limit = 1024 if key == 'password' else 256
        if len(value.encode('utf-8', errors='strict')) > limit:
            raise DictionaryError('Field exceeds size limit')
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise DictionaryError('Control characters are not supported')
    if service == 'snmp':
        value = row['community']
        if not 1 <= len(value) <= 64 or not value.isascii():
            raise DictionaryError('SNMP requires 1-64 printable ASCII bytes')
    else:
        if not row['username']:
            raise DictionaryError('An identity is required')
        if service == 'ftp' and (not row['username'].isascii() or not row['password'].isascii()):
            raise DictionaryError('FTP requires ASCII in this version')
        if service == 'ftp' and row['username'].lower() in ('anonymous', 'ftp-anonymous'):
            raise DictionaryError('Anonymous access is not a credential check')
    return Candidate(**row)


def load_dictionary(path: Path) -> tuple[Candidate, ...]:
    """Validate the entire regular file before returning any candidate."""
    try:
        import os
        if not stat.S_ISREG(path.stat().st_mode):
            raise DictionaryError('A regular file is required')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(fd, 'rb') as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise DictionaryError('A regular file is required')
            raw = handle.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise DictionaryError('Dictionary exceeds 1 MiB')
        # Only a leading UTF-8 BOM is accepted. CRLF and LF are supported.
        text = raw.decode('utf-8-sig', errors='strict')
    except (OSError, UnicodeError, ValueError):
        raise DictionaryError('Dictionary unavailable, oversized or invalid UTF-8') from None
    candidates = []
    seen = set()
    count = 0
    for number, line in enumerate(text.split('\n'), 1):
        try:
            if len(line.encode('utf-8')) > MAX_LINE:
                raise DictionaryError('Line too long')
            if not line.strip():
                continue
            count += 1
            if count > MAX_ENTRIES:
                raise DictionaryError('Too many entries')
            row = json.loads(line, object_pairs_hook=_object)
            candidate = _candidate(row)
            if candidate not in seen:
                seen.add(candidate)
                candidates.append(candidate)
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise DictionaryError(f'Invalid dictionary structure at line {number}') from None
    if not candidates:
        raise DictionaryError('Dictionary contains no candidates')
    return tuple(candidates)


def load_catalog(profile: Optional[str] = None) -> tuple[Candidate, ...]:
    """Legacy entries remain unqualified; only sourced, selected profiles qualify."""
    try:
        document = json.loads(CATALOG.read_text(encoding='utf-8'), object_pairs_hook=_object)
        if document['schema_version'] != 1:
            raise ValueError
        key = profile or 'legacy'
        selected = document['profiles'].get(key)
        if selected is None:
            raise DictionaryError('Unknown catalog profile')
        sourced = bool(selected['source']) and selected['provenance'] == 'verified'
        if selected.get('provenance') not in ('verified', 'unverified'):
            raise ValueError
        provenance = None
        if sourced and profile is not None:
            from urllib.parse import urlsplit
            references = []
            for source in [selected['source'], *selected.get('corroborating_sources', [])]:
                url, section = source['url'], source['section']
                if not isinstance(url, str) or not isinstance(section, str) or not section:
                    raise ValueError
                parsed = urlsplit(url)
                if parsed.scheme != 'https' or not parsed.netloc or parsed.username or parsed.password:
                    raise ValueError
                references.append(DocumentaryReference(url, section))
            version = document['catalog_version']
            if not isinstance(version, str) or not version:
                raise ValueError
            provenance = CatalogProvenance(key, version, tuple(references))
        from dataclasses import replace
        return tuple(replace(_candidate(row), qualified=provenance is not None, provenance=provenance)
                     for row in selected['candidates'])
    except (OSError, ValueError, KeyError, TypeError):
        raise DictionaryError('Catalog unavailable or profile invalid') from None


def prepare_candidates(path: Optional[Path], services: Sequence[str],
                       profile: Optional[str] = None) -> tuple[tuple[Candidate, ...], tuple[str, ...]]:
    """Selection never comes from the dictionary. Explicit gaps fail atomically."""
    selected = tuple(dict.fromkeys(services)) if services else ('ftp', 'snmp')
    if any(s not in SUPPORTED for s in selected):
        raise DictionaryError('Selected service is not supported in this version')
    if path is not None and profile is not None:
        raise DictionaryError('A custom dictionary cannot assert catalog provenance')
    candidates = load_dictionary(path) if path is not None else load_catalog(profile)
    available = {c.service for c in candidates}
    if services and any(s not in available for s in selected):
        raise DictionaryError('An explicitly selected service has no compatible candidates')
    if not available.intersection(selected):
        raise DictionaryError('No selected service has compatible candidates')
    return candidates, selected
