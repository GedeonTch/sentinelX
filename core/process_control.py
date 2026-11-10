"""Run one external scanner process and let the caller interrupt it.

Used by the Sentinel Monitor so that a stop request is honoured while an Nmap
process is running. Without a stop predicate the call is exactly the historic
``subprocess.run`` call, so the pipeline and the baseline keep their behaviour.

Contract of ``run_process`` when a predicate is given:

- the process is polled at most every ``POLL_INTERVAL`` seconds;
- ``should_stop()`` returning True raises ``ScanInterrupted`` after the process
  has been stopped: ``terminate()``, then ``kill()`` after ``STOP_GRACE``
  seconds;
- the process is also stopped on any other exception (including Ctrl+C) and on
  timeout, so no child process outlives the call on a normal exit path;
- output goes to temporary files, never to a pipe, so a large XML document
  cannot block the child while the parent polls.

Not covered: if the parent process is killed with SIGKILL, no ``finally`` runs
and the child is not stopped by this module.
"""
from __future__ import annotations

import locale
import subprocess
import tempfile
import time
from typing import Callable, List, Optional

POLL_INTERVAL = 0.1   # seconds between two checks of the stop predicate
STOP_GRACE = 5.0      # seconds between terminate() and kill()


class ScanInterrupted(BaseException):
    """A stop was requested while an external scan was running.

    Derives from BaseException on purpose: the ``except Exception`` blocks that
    turn scan failures into ``None`` or into a degraded result must not catch
    a deliberate interruption.
    """


def run_process(
    cmd: List[str],
    timeout: float,
    should_stop: Optional[Callable[[], bool]] = None,
) -> subprocess.CompletedProcess:
    """Run ``cmd`` and return its text output, as ``subprocess.run`` would.

    Raises ``subprocess.TimeoutExpired`` after ``timeout`` seconds, ``OSError``
    (including ``FileNotFoundError``) when the program cannot run,
    ``UnicodeDecodeError`` when the output is not decodable, and
    ``ScanInterrupted`` when ``should_stop`` reports a stop request.
    """
    if should_stop is None:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return _run_interruptible(cmd, timeout, should_stop)


def _run_interruptible(
    cmd: List[str],
    timeout: float,
    should_stop: Callable[[], bool],
) -> subprocess.CompletedProcess:
    if should_stop():
        raise ScanInterrupted(f"scan interrupted before start: {cmd[0]}")
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(cmd, stdout=out, stderr=err)
        try:
            deadline = time.monotonic() + timeout
            while True:
                if should_stop():
                    raise ScanInterrupted(f"scan interrupted: {cmd[0]}")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(cmd, timeout)
                try:
                    returncode = proc.wait(timeout=min(POLL_INTERVAL, remaining))
                    break
                except subprocess.TimeoutExpired:
                    continue
        finally:
            if proc.poll() is None:
                _stop_child(proc)
        out.seek(0)
        err.seek(0)
        encoding = locale.getpreferredencoding(False)
        stdout = out.read().decode(encoding)
        stderr = err.read().decode(encoding)
    return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)


def _stop_child(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=STOP_GRACE)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
