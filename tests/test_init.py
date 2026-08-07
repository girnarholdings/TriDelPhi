"""`tridelphi init` — the one-command onboarding for non-experts.

The generated workflow must be correct and must itself pass TriDelPhi: shipping
an onboarding file that our own tool flags would be indefensible.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import run_cli

from tridelphi.api import analyze
from tridelphi.init_cmd import WORKFLOW, run_init


def test_init_writes_the_workflow(tmp_path):
    assert run_init(str(tmp_path)) == 0
    wf = tmp_path / ".github/workflows/tridelphi.yml"
    assert wf.is_file()
    assert wf.read_text() == WORKFLOW


def test_init_is_idempotent(tmp_path):
    assert run_init(str(tmp_path)) == 0
    # Second run refuses rather than clobbering.
    assert run_init(str(tmp_path)) == 1
    # ...unless forced.
    assert run_init(str(tmp_path), force=True) == 0


def test_generated_workflow_is_valid_yaml_and_parses(tmp_path):
    run_init(str(tmp_path))
    result = analyze(tmp_path)
    assert not result.diagnostics, (
        "the generated workflow did not parse: "
        + "; ".join(f"{d.path}: {d.message}" for d in result.diagnostics)
    )
    assert result.contexts_scanned == 1


def test_generated_workflow_is_clean_by_our_own_rules(tmp_path):
    """The onboarding file must not trip the tool it installs."""
    run_init(str(tmp_path))
    result = analyze(tmp_path)
    gating = [f for f in result.findings if f.severity in ("critical", "warning")]
    assert not gating, "; ".join(f"{f.severity} {f.rule_id}" for f in gating)


def test_init_via_cli(repo_root, tmp_path):
    result = run_cli(["init", str(tmp_path)], cwd=repo_root)
    assert result.returncode == 0
    assert "wrote" in result.stdout
    assert (tmp_path / ".github/workflows/tridelphi.yml").is_file()


def test_init_rejects_a_file_target(tmp_path):
    f = tmp_path / "afile"
    f.write_text("x")
    assert run_init(str(f)) == 2


def test_composite_action_exists_and_is_yaml():
    action = Path(__file__).resolve().parents[1] / "action.yml"
    assert action.is_file(), "the one-line `uses:` action is missing"
    from ruamel.yaml import YAML

    doc = YAML().load(action.read_text())
    assert doc["runs"]["using"] == "composite"
    assert "tridelphi" in doc["name"].lower()
