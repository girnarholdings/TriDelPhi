"""Subprocess output is attacker-influenced and must be bounded while it runs."""

from __future__ import annotations

import subprocess
import sys

import pytest

from tridelphi.subprocessutil import run_bounded


def test_bounded_runner_drains_but_does_not_retain_output_bombs():
    result = run_bounded(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('o'*200000); sys.stderr.write('e'*200000)",
        ],
        timeout=10,
        max_stdout_bytes=1024,
        max_stderr_bytes=2048,
    )
    assert result.returncode == 0
    assert len(result.stdout.encode()) == 1024
    assert len(result.stderr.encode()) == 2048
    assert result.stdout_truncated and result.stderr_truncated


def test_bounded_runner_enforces_timeout():
    with pytest.raises(subprocess.TimeoutExpired):
        run_bounded(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            timeout=0.05,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )


@pytest.mark.parametrize("limit", (-1, True))
def test_bounded_runner_rejects_invalid_limits(limit):
    with pytest.raises(ValueError):
        run_bounded(
            [sys.executable, "-c", "pass"],
            timeout=1,
            max_stdout_bytes=limit,
            max_stderr_bytes=1,
        )
