"""Executable matrix for GitHub Actions trust and permission semantics."""

from __future__ import annotations

import textwrap

import pytest

from tridelphi.api import analyze
from tridelphi.parse import grants_write, parse_repo


def _write(root, relative: str, body: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")


def _repo(tmp_path, caller_permissions: str, callee_permissions: str | None):
    root = tmp_path / "repo"
    _write(
        root,
        ".github/workflows/caller.yml",
        f"""
        on: issues
        jobs:
          call:
            permissions:
              contents: {caller_permissions}
            uses: ./.github/workflows/callee.yml
        """,
    )
    permission_block = f"permissions:\n  contents: {callee_permissions}\n" if callee_permissions else ""
    _write(
        root,
        ".github/workflows/callee.yml",
        "on: workflow_call\n"
        + permission_block
        + "jobs:\n"
        + "  inner:\n"
        + "    runs-on: ubuntu-latest\n"
        + "    steps:\n"
        + '      - run: echo "${{ github.event.issue.title }}"\n',
    )
    return root


@pytest.mark.parametrize(
    ("caller", "callee", "write_survives"),
    [
        ("read", "write", False),
        ("write", "read", False),
        ("write", "write", True),
        ("read", None, False),
        ("write", None, True),
    ],
)
def test_reusable_workflow_permissions_only_decrease(
    tmp_path, tables, caller, callee, write_survives
):
    contexts = parse_repo(_repo(tmp_path, caller, callee), tables).contexts
    merged = next(context for context in contexts if context.job_id.startswith("call ->"))
    assert (grants_write(dict(merged.effective_permissions)) is not None) is write_survives


@pytest.mark.parametrize(
    ("trigger", "expected_critical"),
    [("pull_request", False), ("pull_request_target", True), ("issue_comment", True)],
)
def test_trigger_permission_co_reachability(tmp_path, trigger, expected_critical):
    root = tmp_path / "repo"
    _write(
        root,
        ".github/workflows/ci.yml",
        f"""
        on: {trigger}
        jobs:
          risky:
            permissions:
              contents: write
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{{{ github.event.pull_request.title || github.event.comment.body }}}}"
        """,
    )
    critical = [finding for finding in analyze(root).findings if finding.severity == "critical"]
    assert bool(critical) is expected_critical


def test_dynamic_platform_features_are_reported_unknown(tmp_path, tables):
    root = tmp_path / "repo"
    _write(
        root,
        ".github/workflows/ci.yml",
        """
        on: pull_request_target
        jobs:
          dynamic:
            needs: ${{ matrix.dep }}
            strategy:
              matrix: {runner: [ubuntu-latest], dep: [build]}
            runs-on: ${{ matrix.runner }}
            environment: production
            steps:
              - uses: actions/checkout@0123456789012345678901234567890123456789
                with:
                  ref: ${{ inputs.ref }}
        """,
    )
    context = parse_repo(root, tables).contexts[0]
    details = " ".join(context.semantic_unknowns)
    assert "dynamic `needs`" in details
    assert "dynamic `runs-on`" in details
    assert "matrix legs" in details
    assert "environment approvals" in details
    assert "dynamic checkout" in details
    assert any(f.rule_id == "tridelphi/unresolved-context" for f in analyze(root).findings)


def test_checkout_defaults_distinguish_pr_and_target(tmp_path, tables):
    root = tmp_path / "repo"
    for name, trigger in (("pr", "pull_request"), ("target", "pull_request_target")):
        _write(
            root,
            f".github/workflows/{name}.yml",
            f"""
            on: {trigger}
            jobs:
              job:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@0123456789012345678901234567890123456789
            """,
        )
    contexts = {context.workflow_file: context for context in parse_repo(root, tables).contexts}
    assert contexts[".github/workflows/pr.yml"].untrusted_worktree
    assert not contexts[".github/workflows/target.yml"].untrusted_worktree


def test_symlinked_workflow_is_a_visible_blind_spot(tmp_path):
    root = tmp_path / "repo"
    workflows = root / ".github" / "workflows"
    workflows.mkdir(parents=True)
    outside = tmp_path / "outside.yml"
    outside.write_text("on: push\njobs: {}\n", encoding="utf-8")
    (workflows / "outside.yml").symlink_to(outside)
    result = analyze(root)
    assert result.diagnostics
    assert any(f.rule_id == "tridelphi/parse-error" for f in result.findings)


def test_oversized_workflow_is_a_visible_blind_spot(tmp_path):
    root = tmp_path / "repo"
    workflows = root / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "huge.yml").write_text("#" * (8 * 1024 * 1024 + 1), encoding="utf-8")
    result = analyze(root)
    assert result.diagnostics
    assert any(f.rule_id == "tridelphi/parse-error" for f in result.findings)
