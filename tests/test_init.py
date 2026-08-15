"""`tridelphi init` — the one-command onboarding for non-experts.

The generated workflow must be correct and must itself pass TriDelPhi: shipping
an onboarding file that our own tool flags would be indefensible.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from conftest import run_cli

from tridelphi.api import analyze
from tridelphi.init_cmd import (
    APP_WORKFLOW,
    FIX_WORKFLOW,
    WORKFLOW,
    render_action_workflow,
    run_init,
)
from tridelphi.release import ACTION_REF, install_command


def test_init_writes_the_short_action_workflow_by_default(tmp_path):
    """The default has to be the file a first-time user will actually commit.
    The long transparent workflow is ~140 lines of pipx, harden-runner and
    SARIF plumbing — correct, auditable, and the wrong thing to hand someone
    who has never opened `.github/`."""
    assert run_init(str(tmp_path)) == 0
    wf = tmp_path / ".github/workflows/tridelphi.yml"
    assert wf.is_file()
    assert wf.read_text() == render_action_workflow()
    assert len(wf.read_text().splitlines()) < 40


def test_init_from_source_writes_the_transparent_workflow(tmp_path):
    assert run_init(str(tmp_path), from_source=True) == 0
    wf = tmp_path / ".github/workflows/tridelphi.yml"
    assert wf.read_text() == WORKFLOW


def test_init_app_writes_the_exposure_workflow(tmp_path):
    """`--app` is the door for someone whose question is "did I leak my app?".
    It builds, then audits what the build ships — no ladder, no gate."""
    assert run_init(str(tmp_path), app=True) == 0
    wf = tmp_path / ".github/workflows/tridelphi-app.yml"
    assert wf.read_text() == APP_WORKFLOW
    assert "tridelphi expose" in APP_WORKFLOW
    assert "--fail-on none" in APP_WORKFLOW, "the app audit is advisory"
    assert "level" not in APP_WORKFLOW, "no ladder vocabulary on this path"
    # No fix bot: nothing `expose` reports is a workflow edit the bot can make.
    assert not (tmp_path / ".github/workflows/tridelphi-fix.yml").exists()


def test_generated_workflows_never_contain_a_broken_install(tmp_path):
    """Every install line we write into someone's CI comes from `release.py`.
    `pipx install tridelphi` was hard-coded in three templates while the package
    404'd on PyPI — an install that fails inside CI, where they cannot debug it."""
    for template in (WORKFLOW, FIX_WORKFLOW, APP_WORKFLOW):
        assert "__TRIDELPHI_INSTALL__" not in template, "placeholder left unsubstituted"
        assert install_command() in template
    assert ACTION_REF in render_action_workflow()


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


def test_fix_bot_checkbox_branch_is_edited_only():
    """The bypass this guards: without the `edited` restriction, a stranger can
    post a NEW comment merely containing the checkbox marker and `[x]`, satisfy
    the checkbox branch, and — because the Authorize step trusts every `created`
    event — drive the write-scoped fix job. The marker branch must require an
    `edited` action so `created` can only pass through the author_association
    branch."""
    lines = FIX_WORKFLOW.split("\n")
    marker_line = next(i for i, ln in enumerate(lines) if "<!--tridelphi-fix-->" in ln and "contains(" in ln)
    # The three lines of the checkbox disjunct must include the edited guard.
    window = "\n".join(lines[marker_line - 1: marker_line + 2])
    assert "github.event.action == 'edited'" in window, (
        "the checkbox branch must be gated to edited events"
    )


def test_fix_bot_template_blocks_egress():
    """The generated fix bot holds a write token beside pip's dependency tree,
    so a compromised package must have nowhere to send the credential — the same
    hardening the dogfood workflow uses. `audit` would only observe the theft."""
    assert "egress-policy: block" in FIX_WORKFLOW
    assert "egress-policy: audit" not in FIX_WORKFLOW
    assert "files.pythonhosted.org:443" in FIX_WORKFLOW


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


# ---------------------------------------------------------------------------
# the wizard / Setup Studio path — composite-action workflow with chosen inputs
# ---------------------------------------------------------------------------


def _yaml(text: str):
    from ruamel.yaml import YAML

    return YAML().load(text)


def test_render_action_workflow_carries_choices():
    wf = render_action_workflow(level=5, fail_on="warning", comment=False, expose=True)
    step = _yaml(wf)["jobs"]["harden"]["steps"][1]
    assert step["uses"] == ACTION_REF.split(" #")[0]
    assert step["with"]["level"] == "5"
    assert step["with"]["fail-on"] == "warning"
    assert step["with"]["comment"] == "false"
    assert step["with"]["expose"] == "true"


def test_render_action_workflow_omits_expose_by_default():
    step = _yaml(render_action_workflow())["jobs"]["harden"]["steps"][1]
    assert "expose" not in step["with"]
    assert step["with"]["level"] == "3"


def test_wizard_writes_the_action_workflow_and_fix_bot(tmp_path):
    # level 7 · expose yes · fail-on warning · comment no · fix bot yes
    answers = io.StringIO("7\ny\nwarning\nn\ny\n")
    code = run_init(str(tmp_path), wizard=True, input_stream=answers, out=io.StringIO())
    assert code == 0
    wf = (tmp_path / ".github/workflows/tridelphi.yml").read_text()
    step = _yaml(wf)["jobs"]["harden"]["steps"][1]
    assert step["with"]["level"] == "7" and step["with"]["expose"] == "true"
    assert step["with"]["fail-on"] == "warning" and step["with"]["comment"] == "false"
    assert (tmp_path / ".github/workflows/tridelphi-fix.yml").is_file()


def test_wizard_can_skip_the_fix_bot(tmp_path):
    answers = io.StringIO("3\nn\ncritical\ny\nn\n")  # fix bot = n
    run_init(str(tmp_path), wizard=True, input_stream=answers, out=io.StringIO())
    assert (tmp_path / ".github/workflows/tridelphi.yml").is_file()
    assert not (tmp_path / ".github/workflows/tridelphi-fix.yml").exists()


def test_wizard_takes_defaults_on_closed_stdin(tmp_path):
    # EOF immediately → all defaults (level 3, no expose, fail critical, comment, fix bot)
    code = run_init(str(tmp_path), wizard=True, input_stream=io.StringIO(""), out=io.StringIO())
    assert code == 0
    step = _yaml((tmp_path / ".github/workflows/tridelphi.yml").read_text())["jobs"]["harden"]["steps"][1]
    assert step["with"]["level"] == "3" and "expose" not in step["with"]
    assert (tmp_path / ".github/workflows/tridelphi-fix.yml").is_file()
