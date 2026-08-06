from __future__ import annotations

import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def _buckets(name: str) -> list[Path]:
    root = FIXTURES / name
    return sorted(p for p in root.iterdir() if p.is_dir()) if root.is_dir() else []


def pytest_generate_tests(metafunc):
    for bucket in ("malicious", "two_cap", "clean", "realworld"):
        param = f"{bucket}_repo"
        if param in metafunc.fixturenames:
            repos = _buckets(bucket)
            metafunc.parametrize(param, repos, ids=[p.name for p in repos])


@pytest.fixture(scope="session")
def tables():
    from tridelphi.tables import load_tables

    return load_tables()


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def gating(findings) -> list:
    """Findings that count: critical and warning. Notes are informational and
    never affect the exit code."""
    return [f for f in findings if f.severity in ("critical", "warning")]


def run_cli(args: list[str], cwd: Path | None = None):
    """Invoke the CLI in a subprocess.

    Used only where a subprocess proves something in-process calls cannot: the
    exit-code contract and stdout being parseable JSON.
    """
    import subprocess

    return subprocess.run(
        [sys.executable, "-m", "tridelphi", *args],
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd else None,
    )
