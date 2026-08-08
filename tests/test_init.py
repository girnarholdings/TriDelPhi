"""`tridelphi init` — the one-command onboarding for non-experts.

The generated workflow must be correct and must itself pass TriDelPhi: shipping
an onboarding file that our own tool flags would be indefensible.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import run_cli

from tridelphi.api import analyze
from tridelphi.init_cmd import FIX_WORKFLOW, WORKFLOW, run_init


def test_init_writes_the_workflow(tmp_path):
    assert run_init(str(tmp_path)) == 0
    wf = tmp_path / ".github/workflows/tridelphi.yml"
    assert wf.is_file()
    assert wf.read_text() == WORKFLOW


def test_init_writes_the_fix_bot(tmp_path):
    assert run_init(str(tmp_path)) == 0
    wf = tmp_path / ".github/workflows/tridelphi-fix.yml"
    assert wf.is_file()
    assert wf.read_text() == FIX_WORKFLOW


def test_fix_bot_holds_its_trust_boundary():
    """The reply-to-fix workflow is the U∩P∩E shape this tool exists to catch,
    so its own guardrails are load-bearing: the association gate, the fork
    skip, and comment text never reaching a shell."""
    assert "author_association" in FIX_WORKFLOW
    assert "isCrossRepository" in FIX_WORKFLOW, "fork PRs must be skipped"
    # The comment body may appear only inside the job-level `if:` expression —
    # never in a run block or env value.
    for line in FIX_WORKFLOW.split("\n"):
        if "comment.body" in line:
            assert "contains(" in line, f"comment body outside the gate: {line!r}"


def test_init_is_idempotent(tmp_path):
    assert run_init(str(tmp_path)) == 0
    # Second run refuses rather than clobbering.
    assert run_init(str(tmp_path)) == 1
    # ...unless forced.
    assert run_init(str(tmp_path), force=True) == 0


def test_generated_workflows_are_valid_yaml_and_parse(tmp_path):
    run_init(str(tmp_path))
    result = analyze(tmp_path)
    assert not result.diagnostics, (
        "a generated workflow did not parse: "
        + "; ".join(f"{d.path}: {d.message}" for d in result.diagnostics)
    )
    assert result.contexts_scanned == 2  # the scan job and the fix-bot job


def test_generated_workflows_are_clean_by_our_own_rules(tmp_path):
    """The onboarding files must not trip the tool they install — including
    the fix bot, which is comment-triggered with write permission and passes
    only because it is built the way our own remediation demands."""
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
