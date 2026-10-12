"""Private Sentinel control plane; no events, Findings or scan operations.

The stable lock is never unlinked. Control rows are retained per execution so a
late waiter cannot mistake a new owner's acknowledgement for its own.
"""
from __future__ import annotations

import contextlib
import os
from pathlib import Path
import select
import sys
import time
import uuid

import portalocker

from core import database as db

POLL_SECONDS = 0.1
DEFAULT_STOP_TIMEOUT = 30.0


LifecycleError = db.SentinelControlError


def _linux_identity(pid):
    try:
        # comm may contain spaces and parentheses; fields after the last ')'.
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        if fields[0] in ("Z", "X"):
            return None
    except FileNotFoundError:
        return None
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    return f"{boot}:{fields[19]}"


def _windows_birth(handle):
    # Preserve the full FILETIME (100 ns), not a formatted/rounded timestamp.
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    get_times = kernel.GetProcessTimes
    get_times.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    get_times.restype = wintypes.BOOL
    creation, end, kernel_time, user_time = (wintypes.FILETIME() for _ in range(4))
    if not get_times(int(handle), ctypes.byref(creation), ctypes.byref(end),
                     ctypes.byref(kernel_time), ctypes.byref(user_time)):
        raise ctypes.WinError(ctypes.get_last_error())
    return str((creation.dwHighDateTime << 32) | creation.dwLowDateTime)


class ProcessIdentity:
    """Pin a kernel process object, not just a numeric PID.

    Linux uses pidfd plus boot/start time; Windows uses a process handle plus
    creation time. Failure to inspect is an error, never evidence of death.
    """
    def __init__(self, pid, expected=None):
        self.fd = None
        self.handle = None
        self.dead = False
        self.birth = None
        try:
            if sys.platform == "linux":
                if not hasattr(os, "pidfd_open"):
                    raise LifecycleError("Linux pidfd support is required for confirmed stop")
                try:
                    self.fd = os.pidfd_open(pid)
                except ProcessLookupError:
                    self.dead = True
                    return
                self.birth = _linux_identity(pid)
                if self.birth is None and not select.select([self.fd], [], [], 0)[0]:
                    raise LifecycleError("Process identity unavailable; termination is unconfirmed")
                self.dead = self.birth is None or (expected is not None and self.birth != expected)
            elif sys.platform == "win32":
                import win32api
                import win32event
                import pywintypes
                self.win32event = win32event
                try:
                    self.handle = win32api.OpenProcess(0x100000 | 0x1000, False, pid)
                except pywintypes.error as exc:
                    if exc.winerror == 87:  # invalid PID, not access denied
                        self.dead = True
                        return
                    raise
                self.birth = _windows_birth(self.handle)
                self.dead = expected is not None and self.birth != expected
            else:
                raise LifecycleError("Confirmed Sentinel lifecycle supports Linux and Windows only")
        except Exception as exc:
            cleanup_error = None
            try:
                self.close()
            except Exception as cleanup:
                cleanup_error = type(cleanup).__name__
            if isinstance(exc, LifecycleError) and cleanup_error is None:
                raise
            suffix = f"; fermeture impossible ({cleanup_error})" if cleanup_error else ""
            raise LifecycleError(
                f"Identité du processus invérifiable ({type(exc).__name__}){suffix}; arrêt non confirmé"
            ) from None
        except BaseException:
            self.close()
            raise

    def exited(self):
        if self.dead:
            return True
        if self.fd is not None:
            return bool(select.select([self.fd], [], [], 0)[0])
        try:
            result = self.win32event.WaitForSingleObject(self.handle, 0)
        except Exception as exc:
            raise LifecycleError(
                f"Terminaison du processus invérifiable ({type(exc).__name__}); arrêt non confirmé"
            ) from None
        if result == self.win32event.WAIT_OBJECT_0:
            return True
        if result != self.win32event.WAIT_TIMEOUT:
            raise LifecycleError("Cannot verify process termination")
        return False

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.handle is not None:
            try:
                self.handle.Close()
            except Exception as exc:
                raise LifecycleError(
                    f"Fermeture du handle impossible ({type(exc).__name__}); arrêt non confirmé"
                ) from None
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _private_windows_path(path, directory=False):
    import win32api
    import win32security
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), 8)
    try:
        user = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    finally:
        token.Close()
    acl = win32security.ACL()
    acl.AddAccessAllowedAceEx(win32security.ACL_REVISION,
                             3 if directory else 0, 0x1F01FF, user)
    win32security.SetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None, None, acl, None)


def _lock_path(network_id):
    db.validate_sentinel_network_id(network_id)
    # Reuse the validated Sentinel root, with a separate private runtime folder.
    folder = db.get_sentinel_db_path(network_id).parent / "control"
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "nt":
        _private_windows_path(folder, directory=True)
    else:
        folder.chmod(0o700)
    return folder / f"{network_id}.lock"


@contextlib.contextmanager
def network_lock(network_id):
    path = _lock_path(network_id)
    # No truncate, no unlink, including on failure and crash recovery.
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    stream = os.fdopen(fd, "a+b")
    acquired = False
    try:
        if os.name == "nt":
            _private_windows_path(path)
        else:
            os.fchmod(fd, 0o600)
        try:
            portalocker.lock(stream, portalocker.LOCK_EX | portalocker.LOCK_NB)
            acquired = True
        except portalocker.exceptions.LockException as exc:
            raise LifecycleError("Une instance Sentinel possède déjà ce réseau") from exc
        yield
    finally:
        if acquired:
            portalocker.unlock(stream)
        stream.close()


def lock_is_free(network_id):
    try:
        with network_lock(network_id):
            return True
    except LifecycleError:
        return False


def records(network_id):
    return db.sentinel_control_records(network_id)


def resolve_owner(network_id=None, session_id=None):
    if (network_id is None) == (session_id is None):
        raise LifecycleError("Specify exactly one of --network or --session")
    if network_id is not None:
        db.validate_sentinel_network_id(network_id)
        rows = records(network_id)
        if rows:
            return rows[0]
    else:
        matches = []
        for network in db.list_sentinel_network_ids():
            for row in records(network):
                # Legacy network IDs accepted only with explicit control evidence.
                if session_id in (row["network_id"], row["run_session_id"]):
                    matches.append(row)
        if len({r["network_id"] for r in matches}) > 1:
            raise LifecycleError("Ambiguous session/network identifier; use --network")
        if matches:
            return matches[0]
    raise LifecycleError("Identité inconnue : aucune exécution Sentinel contrôlable")


class Owner:
    def __init__(self, network_id, run_session_id):
        self.network_id = network_id
        self.run_session_id = run_session_id
        self.instance = uuid.uuid4().hex
        with ProcessIdentity(os.getpid()) as process:
            if process.exited() or not process.birth:
                raise LifecycleError("Cannot register current process identity")
            self.birth = process.birth
        db.sentinel_control_register(network_id, self.instance, run_session_id, os.getpid(), self.birth)

    def requested(self):
        return bool(db.sentinel_control_get(self.network_id, self.instance)['stop_requested'])

    def admit_cycle(self):
        return db.sentinel_control_admit_cycle(self.network_id, self.instance)

    def end_cycle(self):
        db.sentinel_control_end_cycle(self.network_id, self.instance)

    def wait(self, seconds):
        deadline = time.monotonic() + seconds
        while True:
            if self.requested():
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(POLL_SECONDS, remaining))

    def finish(self, result, error=None):
        db.sentinel_control_finish(self.network_id, self.instance, result, error)


def request_stop(network_id=None, session_id=None, timeout=DEFAULT_STOP_TIMEOUT):
    if not 0 < timeout < float("inf"):
        raise LifecycleError("Stop timeout must be finite and positive")
    deadline = time.monotonic() + timeout
    owner = resolve_owner(network_id, session_id)
    network = owner["network_id"]
    instance = owner["instance"]
    with ProcessIdentity(owner["pid"], owner["birth"]) as process:
        if not process.exited():
            db.sentinel_control_request_stop(network, instance)
        while True:
            row = db.sentinel_control_get(network, instance)
            if process.exited() and lock_is_free(network):
                if row['result'] == "completed":
                    return
                if row['result'] in ("failed", "finalization_failed"):
                    raise LifecycleError("Instance terminée, mais arrêt non finalisé proprement")
                raise LifecycleError("Instance déjà morte : état périmé, pas d'arrêt propre confirmé; récupération au prochain démarrage")
            if time.monotonic() >= deadline:
                raise LifecycleError("Délai dépassé : arrêt non confirmé (la demande reste enregistrée)")
            time.sleep(min(POLL_SECONDS, max(0, deadline - time.monotonic())))
