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


def test_read_only_scan_templates_do_not_persist_checkout_credentials():
    from ruamel.yaml import YAML

    for template in (WORKFLOW, APP_WORKFLOW, render_action_workflow()):
        document = YAML(typ="safe").load(template)
        for job in document["jobs"].values():
            for step in job["steps"]:
                if str(step.get("uses", "")).startswith("actions/checkout@"):
                    assert step["with"]["persist-credentials"] is False


def test_action_python_helpers_cannot_import_from_the_scanned_checkout(repo_root):
    action = (repo_root / "action.yml").read_text(encoding="utf-8")
    installer = (repo_root / "scripts/install-ladder.sh").read_text(encoding="utf-8")
    assert "python3 -I - <<'PY'" in action
    assert 'python3 -I -m pip install --quiet "$GITHUB_ACTION_PATH"' in action
    assert "python3 -m pip" not in installer


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
    assert "getCollaboratorPermissionLevel" in FIX_WORKFLOW
    assert "p.action === 'created'" not in FIX_WORKFLOW


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


def test_fix_bot_logs_cannot_inject_step_outputs_or_comments():
    """Repository-controlled finding text stays data, never workflow protocol."""

    assert "TRIDELPHI_EOF" not in FIX_WORKFLOW
    assert "fix-log.txt" in FIX_WORKFLOW and "fs.openSync" in FIX_WORKFLOW
    assert ".replaceAll('<', '&lt;')" in FIX_WORKFLOW
    assert ".replaceAll('@', '&#64;')" in FIX_WORKFLOW
    assert "relock-refused" in FIX_WORKFLOW and "push-changed" in FIX_WORKFLOW

    dogfood = (Path(__file__).resolve().parents[1] / ".github/workflows/tridelphi-fix.yml").read_text()
    assert "TRIDELPHI_EOF" not in dogfood
    assert "fs.openSync" in dogfood and ".replaceAll('@', '&#64;')" in dogfood


def test_scan_reports_never_cross_github_command_protocols():
    """Repository-derived report text stays in private files and summaries.

    It must never be a multiline step output, an environment value, or raw log
    output: all three surfaces interpret control syntax rather than plain data.
    """

    action = (Path(__file__).resolve().parents[1] / "action.yml").read_text()
    for body in (action, WORKFLOW, APP_WORKFLOW):
        assert "TRIDELPHI_EOF" not in body
        assert "REPORT_MD: ${{ steps." not in body
        assert "cat report" not in body
        assert "REPORT_FILE: ${{ runner.temp }}" in body
        assert "fs.openSync" in body and "Buffer.alloc" in body
        assert ".replaceAll('@', '&#64;')" in body

    assert 'sarif_file: ${{ runner.temp }}/tridelphi.sarif' in action
    assert "steps.scan.outputs.sarif_ready == 'true'" in action
    assert 'sarif_file: ${{ runner.temp }}/tridelphi-expose.sarif' in action
    assert "$RUNNER_TEMP/tridelphi-exit-code" in action


def test_fork_pull_requests_scan_without_attempting_an_impossible_comment():
    action = (Path(__file__).resolve().parents[1] / "action.yml").read_text()
    guard = "github.event.pull_request.head.repo.full_name == github.repository"
    assert guard in action
    assert guard in WORKFLOW
    assert guard in APP_WORKFLOW
    assert "Fork pull_request tokens are read-only" in action


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


def test_init_local_writes_an_executable_pre_push_hook(tmp_path):
    """The no-CI path. For repos that never see GitHub Actions, the same scans
    run at a git hook — on push, not commit, because a scan people bypass is no
    scan at all."""
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    assert run_init(str(tmp_path), local=True) == 0
    hook = tmp_path / ".git" / "hooks" / "pre-push"
    assert hook.is_file()
    body = hook.read_text()
    assert body.startswith("#!/bin/sh")
    assert "tridelphi ." in body
    assert "tridelphi expose ." in body
    assert hook.stat().st_mode & 0o111, "the hook must be executable"


def test_init_local_needs_a_git_repo(tmp_path):
    """--local installs a git hook, so it must refuse a directory that is not a
    repo rather than silently doing nothing."""
    assert run_init(str(tmp_path), local=True) == 2
    assert not (tmp_path / ".git").exists()


def test_init_local_refuses_to_clobber_an_existing_hook(tmp_path):
    hooks = tmp_path / ".git" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "pre-push").write_text("#!/bin/sh\necho mine\n")
    assert run_init(str(tmp_path), local=True) == 1
    assert "echo mine" in (hooks / "pre-push").read_text()
    assert run_init(str(tmp_path), local=True, force=True) == 0
    assert "tridelphi" in (hooks / "pre-push").read_text()


@pytest.mark.parametrize("kwargs", [{}, {"app": True}, {"from_source": True}])
def test_every_init_shape_is_clean_by_our_own_rules(tmp_path, kwargs):
    """All three doors, not just the default. Shipping an onboarding file that
    our own tool flags would be indefensible, and `--app` adds a `run:` build
    step — the one place a new template could pick up egress it shouldn't."""
    run_init(str(tmp_path), **kwargs)
    result = analyze(tmp_path)
    assert not result.diagnostics, "; ".join(
        f"{d.path}: {d.message}" for d in result.diagnostics
    )
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


def test_comment_disabled_workflow_does_not_request_pr_write():
    body = render_action_workflow(comment=False)
    assert "pull-requests: write" not in body
    assert "security-events: write" in body


def test_l6_and_l7_workflows_receive_only_the_required_attestation_permissions():
    for level in (6, 7):
        body = render_action_workflow(level=level)
        assert "id-token: write" in body
        assert "attestations: write" in body
    body = render_action_workflow(level=5)
    assert "id-token: write" not in body
    assert "attestations: write" not in body


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
