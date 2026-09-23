"""Bounded subprocess capture for scanners and opt-in verification commands."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

__all__ = ["BoundedCompletedProcess", "run_bounded"]

_READ_CHUNK = 64 * 1024


@dataclass(frozen=True)
class BoundedCompletedProcess:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    stdout_truncated: bool = False
    stderr_truncated: bool = False


def _terminate_group(process: subprocess.Popen[bytes], *, force: bool) -> None:
    """Stop the child and anything that kept its output pipes open."""

    if os.name == "posix":
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL if force else signal.SIGTERM)
    elif process.poll() is None:  # pragma: no cover - exercised on Windows
        process.kill() if force else process.terminate()


def run_bounded(
    command: Sequence[str],
    *,
    cwd: str | Path | None = None,
    timeout: int | float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> BoundedCompletedProcess:
    """Run an argv command while draining but not retaining unbounded output.

    ``subprocess.run(capture_output=True)`` stores every byte until the child
    exits. Scanner output is derived from an untrusted checkout, so a repository
    that provokes gigabytes of diagnostics could exhaust the parent before a
    post-run size check executes. Two drain threads retain only the configured
    prefixes and discard the rest. A fresh process group lets a timeout also
    stop descendants that inherited the pipes.
    """

    argv = tuple(str(part) for part in command)
    if not argv:
        raise ValueError("command must not be empty")
    for value, label in (
        (max_stdout_bytes, "max_stdout_bytes"),
        (max_stderr_bytes, "max_stderr_bytes"),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{label} must be a non-negative integer")

    process = subprocess.Popen(
        argv,
        cwd=str(cwd) if cwd is not None else None,
        # Nothing run here is interactive. An inherited terminal would let a
        # prompting tool sit until its timeout instead of failing at once.
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name == "posix",
    )
    assert process.stdout is not None and process.stderr is not None
    captured: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = {"stdout": False, "stderr": False}

    def drain(name: str, stream, limit: int) -> None:
        try:
            while chunk := stream.read(_READ_CHUNK):
                room = max(0, limit - len(captured[name]))
                if room:
                    captured[name].extend(chunk[:room])
                if len(chunk) > room:
                    truncated[name] = True
        except (OSError, ValueError):
            truncated[name] = True
        finally:
            stream.close()

    threads = (
        threading.Thread(
            target=drain,
            args=("stdout", process.stdout, max_stdout_bytes),
            daemon=True,
        ),
        threading.Thread(
            target=drain,
            args=("stderr", process.stderr, max_stderr_bytes),
            daemon=True,
        ),
    )
    for thread in threads:
        thread.start()

    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _terminate_group(process, force=True)
        process.wait()
        for thread in threads:
            thread.join(timeout=5)
        raise subprocess.TimeoutExpired(argv, timeout) from None

    # The direct process is done. Stop any daemonized descendant that inherited
    # the pipes; otherwise a malicious verification command can keep drain
    # threads alive after its apparent completion.
    _terminate_group(process, force=False)
    for thread in threads:
        thread.join(timeout=1)
    if any(thread.is_alive() for thread in threads):
        _terminate_group(process, force=True)
        for thread in threads:
            thread.join(timeout=4)

    return BoundedCompletedProcess(
        args=argv,
        returncode=returncode,
        stdout=bytes(captured["stdout"]).decode("utf-8", errors="replace"),
        stderr=bytes(captured["stderr"]).decode("utf-8", errors="replace"),
        stdout_truncated=truncated["stdout"],
        stderr_truncated=truncated["stderr"],
    )
