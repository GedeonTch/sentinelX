"""Local encrypted credential vault. Independent of Finding and session SQLite.

Only list_metadata() is non-secret output. reveal() is for an explicit CLI show.
The lock spans the whole context, including preparation and recording successes.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import base64
import json
import os
from pathlib import Path
import stat
import tempfile
import uuid
from typing import Iterator, Optional

MAX_VAULT = 16 * 1024 * 1024
AAD = b'SentinelX credential vault v1'
N, R, P = 2**17, 8, 1


class VaultError(RuntimeError):
    """Safe public error: never includes a key, record, path or backend message."""


class VaultWriteUncertain(VaultError):
    """Replacement started: commit/durability could not be acknowledged safely."""

    def __init__(self, interrupted: bool = False):
        super().__init__('Vault write outcome uncertain; testing stopped; inspect vault before retrying')
        self.interrupted = interrupted


def default_vault_path() -> Path:
    return Path.home() / '.netlab' / 'credentials' / 'vault.enc'


def _windows_acl(path: Path, create: bool) -> None:
    import win32api
    import win32con
    import win32security as ws
    token = ws.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        user = ws.GetTokenInformation(token, ws.TokenUser)[0]
    finally:
        token.Close()
    system = ws.CreateWellKnownSid(ws.WinLocalSystemSid, None)
    if create:
        acl = ws.ACL()
        flags = 3 if path.is_dir() else 0  # object/container inheritance
        for sid in (user, system):
            acl.AddAccessAllowedAceEx(ws.ACL_REVISION, flags, win32con.GENERIC_ALL, sid)
        ws.SetNamedSecurityInfo(str(path), ws.SE_FILE_OBJECT,
            ws.DACL_SECURITY_INFORMATION | ws.PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, acl, None)
    descriptor = ws.GetNamedSecurityInfo(str(path), ws.SE_FILE_OBJECT,
        ws.DACL_SECURITY_INFORMATION | ws.OWNER_SECURITY_INFORMATION)
    if descriptor.GetSecurityDescriptorOwner() != user:
        raise VaultError('Vault ownership is not private')
    acl = descriptor.GetSecurityDescriptorDacl()
    if acl is None:
        raise VaultError('Vault permissions are not private')
    allowed = {ws.ConvertSidToStringSid(user), ws.ConvertSidToStringSid(system)}
    for i in range(acl.GetAceCount()):
        ace = acl.GetAce(i)
        if ace[0][0] != ws.ACCESS_ALLOWED_ACE_TYPE or ws.ConvertSidToStringSid(ace[2]) not in allowed:
            raise VaultError('Vault permissions are not private')


def _private(path: Path, create: bool = False) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or (getattr(info, 'st_file_attributes', 0) & 0x400):
        raise VaultError('Vault links or reparse points are not allowed')
    if os.name == 'nt':
        _windows_acl(path, create)
    elif info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise VaultError('Vault permissions are not private')
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise VaultError('Vault path must be a regular file or private directory')


def _directory(path: Path) -> None:
    for part in (path, *path.parents):
        if part.is_symlink() or (part.exists() and getattr(part.lstat(), 'st_file_attributes', 0) & 0x400):
            raise VaultError('Vault directory links are not allowed')
    created = False
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
        created = True
    except FileExistsError:
        pass
    if not path.is_dir():
        raise VaultError('Vault directory is unavailable')
    _private(path, create=created)


def _derive(phrase: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    return Scrypt(salt=salt, length=32, n=N, r=R, p=P).derive(phrase.encode('utf-8'))


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode('ascii')


def _decode(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def _read(path: Path) -> bytes:
    _private(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise VaultError('Vault is not a regular file')
        data = handle.read(MAX_VAULT + 1)
    if len(data) > MAX_VAULT:
        raise VaultError('Vault exceeds size limit')
    return data


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CredentialVault:
    """Opened only via open_vault(). Secret data never appears in repr."""
    def __init__(self, path: Path, key: bytes, header: dict, data: dict) -> None:
        self._path, self._key, self._header, self._data = path, key, header, data
        self.ready = False
        self._open = True

    def _payload(self, raw: bytes) -> dict:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        envelope = json.loads(raw)
        if envelope['header'] != self._header:
            raise VaultError('Vault header changed')
        plain = AESGCM(self._key).decrypt(_decode(envelope['nonce']), _decode(envelope['data']),
                                        self._aad())
        data = json.loads(plain)
        if not isinstance(data, dict) or not isinstance(data.get('records'), list):
            raise VaultError('Vault content is invalid')
        return data

    def _aad(self) -> bytes:
        return AAD + json.dumps(self._header, sort_keys=True).encode('ascii')

    def _write(self) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        if not self._open:
            raise VaultError('Vault is closed')
        nonce = os.urandom(12)
        encrypted = AESGCM(self._key).encrypt(nonce, json.dumps(self._data).encode('utf-8'), self._aad())
        raw = json.dumps({'header': self._header, 'nonce': _encode(nonce), 'data': _encode(encrypted)}).encode('ascii')
        if len(raw) > MAX_VAULT:
            raise VaultError('Vault exceeds size limit')
        fd, temporary = tempfile.mkstemp(prefix='.vault-', dir=self._path.parent)
        temp = Path(temporary)
        replacing = False
        try:
            with os.fdopen(fd, 'wb') as handle:
                _private(temp, create=True)
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            # Set BEFORE invoking replace: a wrapper/OS can replace then fail
            # to acknowledge it. An exception from this boundary is not proof
            # that the old file remains (even when replace did not return).
            replacing = True
            os.replace(temp, self._path)
            if os.name != 'nt':
                directory = os.open(self._path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            if self._payload(_read(self._path)) != self._data:
                raise VaultError('Vault read-back failed')
        except BaseException as exc:
            if replacing:
                raise VaultWriteUncertain(isinstance(exc, (KeyboardInterrupt, SystemExit))) from None
            raise
        finally:
            # Cleanup must not overwrite the primary commit classification.
            try:
                if temp.exists():
                    temp.unlink()
            except OSError:
                pass  # encrypted temporary only; never a cleartext fallback

    def check_writable(self) -> None:
        """Encrypted synthetic marker, read-back, then removal before network."""
        try:
            self._data['write_check'] = uuid.uuid4().hex
            self._write()
            del self._data['write_check']
            self._write()
            self.ready = True
        except VaultWriteUncertain:
            self.ready = False
            raise
        except Exception:
            self.ready = False
            raise VaultError('Vault write/read check failed') from None

    def record(self, *, service: str, endpoint: str, context: str,
               username: str = '', domain: str = '', secret: str,
               kind: str = 'password', proof: str = '') -> bool:
        """Return True on creation, False on reconfirmation; match inside vault."""
        if not self.ready or not self._open:
            raise VaultError('Vault is not ready to record')
        identity = dict(service=service, endpoint=endpoint, context=context,
                        username=username, domain=domain, secret=secret, kind=kind)
        try:
            current = next((r for r in self._data['records']
                            if all(r.get(k) == v for k, v in identity.items())), None)
            created = current is None
            if created:
                current = dict(identity, id=uuid.uuid4().hex, first_confirmed=_now())
                self._data['records'].append(current)
            current['last_confirmed'] = _now()
            current['proof'] = proof
            self._write()
            return created
        except VaultWriteUncertain:
            self.ready = False
            raise
        except Exception:
            self.ready = False
            raise VaultError('Accepted authentication could not be saved before replacement; testing stopped') from None

    def list_metadata(self) -> list[dict]:
        keys = ('id', 'service', 'endpoint', 'kind', 'first_confirmed', 'last_confirmed')
        return [{k: r[k] for k in keys} for r in self._data.get('records', [])]

    def reveal(self, record_id: str) -> Optional[dict]:
        return next((dict(r) for r in self._data.get('records', []) if r['id'] == record_id), None)

    def close(self) -> None:
        self.ready = False
        self._open = False
        self._data = {}
        self._key = b''  # best effort only: Python does not guarantee zeroization


@contextmanager
def open_vault(path: Path, phrase: str, *, create: bool = False,
               writable: bool = False) -> Iterator[CredentialVault]:
    """Acquire exclusive lock, authenticate, optionally prove write readiness."""
    import portalocker
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    handle = None
    vault = None
    locked = False
    try:
        if path.is_symlink():
            raise VaultError('Vault links are not allowed')
        if not 1 <= len(phrase) <= 1024:
            raise VaultError('Invalid passphrase length')
        if not path.exists() and not create:
            raise VaultError('Vault absent; initialize through creds_check')
        _directory(path.parent)
        lock = path.parent / '.vault.lock'
        lock_existed = lock.exists()
        if lock_existed:
            _private(lock)
        fd = os.open(lock, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        handle = os.fdopen(fd, 'r+b')
        _private(lock, create=not lock_existed)
        portalocker.lock(handle, portalocker.LOCK_EX | portalocker.LOCK_NB)
        locked = True
        if path.exists():
            if writable:
                info = path.lstat()
                readonly = (not info.st_mode & stat.S_IWUSR) if os.name != 'nt' else bool(getattr(info, 'st_file_attributes', 0) & 1)
                if readonly:
                    raise VaultError('Vault is read-only')
            envelope = json.loads(_read(path))
            header = envelope['header']
            if header['version'] != 1 or header['kdf'] != [N, R, P]:
                raise VaultError('Unsupported vault format')
            salt = _decode(header['salt'])
            if len(salt) != 16:
                raise ValueError
            wrapping = _derive(phrase, salt)
            key = AESGCM(wrapping).decrypt(_decode(header['wrap_nonce']), _decode(header['wrapped_key']), AAD)
            vault = CredentialVault(path, key, header, {})
            vault._data = vault._payload(json.dumps(envelope).encode('ascii'))
        else:
            if not create or len(phrase) < 20 or len(set(phrase)) < 8 or len(phrase) > 1024:
                raise VaultError('Use a long non-trivial vault passphrase (20-1024 characters)')
            salt, key, nonce = os.urandom(16), os.urandom(32), os.urandom(12)
            wrapping = _derive(phrase, salt)
            header = dict(version=1, kdf=[N, R, P], salt=_encode(salt), wrap_nonce=_encode(nonce),
                          wrapped_key=_encode(AESGCM(wrapping).encrypt(nonce, key, AAD)))
            vault = CredentialVault(path, key, header, {'records': []})
            vault._write()
        if writable:
            vault.check_writable()
    except BaseException as exc:
        if vault:
            vault.close()
        if handle:
            if locked:
                portalocker.unlock(handle)
            handle.close()
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        if isinstance(exc, VaultWriteUncertain):
            raise VaultWriteUncertain(exc.interrupted) from None
        if isinstance(exc, VaultError):
            raise VaultError(str(exc)) from None
        if isinstance(exc, portalocker.exceptions.LockException):
            raise VaultError('Vault is locked by another process') from None
        raise VaultError('Vault cannot be authenticated or accessed; no automatic reset performed') from None
    try:
        yield vault
    finally:
        vault.close()
        portalocker.unlock(handle)
        handle.close()
