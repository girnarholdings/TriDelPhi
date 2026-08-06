"""Byte-identical output, including across processes.

The in-process "run twice, diff empty" check the original spec implied is not
sufficient: ``str``-set iteration order is randomised per process by
``PYTHONHASHSEED``, so a single-process double call can pass while the property
is false. These tests spawn separate interpreters with different seeds.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

TARGETS = [
    "tests/fixtures/malicious/comment-and-control",
    "tests/fixtures/malicious/cross-job-laundering",
    "tests/fixtures/realworld/typical-app",
]


def _run_with_seed(target: str, seed: str, cwd: Path) -> str:
    env = dict(os.environ, PYTHONHASHSEED=seed)
    result = subprocess.run(
        [sys.executable, "-m", "tridelphi", target, "--format", "sarif"],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(cwd),
    )
    assert result.returncode in (0, 1), result.stderr
    return result.stdout


@pytest.mark.parametrize("target", TARGETS)
def test_identical_across_hash_seeds(target, repo_root):
    first = _run_with_seed(target, "0", repo_root)
    second = _run_with_seed(target, "12345", repo_root)
    assert first == second, f"{target}: output varies with PYTHONHASHSEED"


def test_no_sets_or_frozensets_on_model_fields():
    """A set on a dataclass field is a latent nondeterminism source, so it is
    banned outright rather than audited case by case."""
    import dataclasses

    from tridelphi import model

    for name in dir(model):
        obj = getattr(model, name)
        if not dataclasses.is_dataclass(obj) or not isinstance(obj, type):
            continue
        for field in dataclasses.fields(obj):
            annotation = str(field.type)
            assert "frozenset" not in annotation and "set[" not in annotation, (
                f"{obj.__name__}.{field.name} is a set type: iteration order is "
                "hash-seed dependent"
            )


def test_findings_sort_is_total(repo_root):
    """Ties on (file, line, rule) fall back to insertion order, which is
    filesystem walk order. job_id makes the key total."""
    from tridelphi.api import analyze

    result = analyze("tests/fixtures/realworld/typical-app")
    keys = [f.sort_key for f in result.findings]
    assert keys == sorted(keys)
    assert len(keys) == len(set(keys))


def test_workflow_discovery_is_sorted(tmp_path):
    from tridelphi.parse import _discover_workflows

    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    for name in ("b.yml", "a.yaml", "C.yml", "a.yml"):
        (workflows / name).write_text("on: push\njobs: {}\n")
    found = [p.name for p in _discover_workflows(tmp_path)]
    assert found == sorted(found)
