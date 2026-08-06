"""Unit tests for the three detectors and the position machinery."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from tridelphi import detect_egress, detect_privilege, detect_untrusted
from tridelphi.detect_untrusted import expression_paths, matches_untrusted_path
from tridelphi.parse import parse_repo
from tridelphi.yamlnode import YamlNode


def build(tmp_path: Path, workflow: str, extra: dict[str, str] | None = None):
    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    (workflows / "w.yml").write_text(textwrap.dedent(workflow).lstrip(), encoding="utf-8")
    for name, body in (extra or {}).items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return tmp_path


# --------------------------------------------------------------------------
# expression matching
# --------------------------------------------------------------------------


def test_expression_paths_extracts_context_refs():
    paths = expression_paths('run: echo "${{ github.event.issue.title }}"')
    assert "github.event.issue.title" in paths


@pytest.mark.parametrize(
    "path,expected",
    [
        ("github.event.issue.body", True),
        ("github.event.comment.body", True),
        ("github.event.commits.0.message", True),
        ("github.event.review_comment.body", True),
        ("github.repository", False),
        ("github.event.pull_request.number", False),
    ],
)
def test_glob_segments_match(path, expected, tables):
    patterns = tables.tuple_of("untrusted_expressions", "paths")
    assert bool(matches_untrusted_path(path, patterns)) is expected


def test_object_filter_syntax_is_caught(tables):
    """`github.event.*.body` collapses a path level; a flat string list misses
    it, and it is a real injection path."""
    patterns = tables.tuple_of("untrusted_expressions", "paths")
    assert matches_untrusted_path("github.event.*.body", patterns)


# --------------------------------------------------------------------------
# U
# --------------------------------------------------------------------------


def test_trigger_alone_is_not_untrusted_ingress(tmp_path, tables):
    """A dangerous trigger is a precondition. Treating it as a source flags the
    most common job on GitHub."""
    repo = build(
        tmp_path,
        """
        on: pull_request_target
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: echo hello
        """,
    )
    ctx = parse_repo(repo, tables).contexts[0]
    assert detect_untrusted.detect(ctx, tables) == []


def test_env_indirection_is_not_a_finding(tmp_path, tables):
    """Flagging GitHub's documented mitigation is worse than missing the bug."""
    repo = build(
        tmp_path,
        """
        on: issues
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TITLE: ${{ github.event.issue.title }}
                run: ./s.sh "$TITLE"
        """,
    )
    ctx = parse_repo(repo, tables).contexts[0]
    assert detect_untrusted.detect(ctx, tables) == []


def test_env_indirection_with_eval_is_a_finding(tmp_path, tables):
    repo = build(
        tmp_path,
        """
        on: issues
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TITLE: ${{ github.event.issue.title }}
                run: eval "$TITLE"
        """,
    )
    ctx = parse_repo(repo, tables).contexts[0]
    kinds = {h.kind for h in detect_untrusted.detect(ctx, tables)}
    assert "expression-injection-via-env" in kinds


def test_data_sink_is_not_injection(tmp_path, tables):
    """`actions/cache` does not shell-expand its key."""
    repo = build(
        tmp_path,
        """
        on: pull_request_target
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with:
                  key: cache-${{ github.head_ref }}
        """,
    )
    ctx = parse_repo(repo, tables).contexts[0]
    assert detect_untrusted.detect(ctx, tables) == []


def test_checkout_ref_direction(tmp_path, tables):
    """Bare checkout on pull_request_target is base — the safe default and the
    reason the trigger exists."""
    safe = build(
        tmp_path / "safe",
        """
        on: pull_request_target
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        """,
    )
    unsafe = build(
        tmp_path / "unsafe",
        """
        on: pull_request_target
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
        """,
    )
    assert parse_repo(safe, tables).contexts[0].untrusted_worktree is False
    assert parse_repo(unsafe, tables).contexts[0].untrusted_worktree is True


def test_workflow_run_needs_upstream_consumption(tmp_path, tables):
    inert = build(
        tmp_path / "inert",
        """
        on:
          workflow_run:
            workflows: ["CI"]
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: echo done
        """,
    )
    consuming = build(
        tmp_path / "consuming",
        """
        on:
          workflow_run:
            workflows: ["CI"]
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4
              - run: ./dist/run.sh
        """,
    )
    assert detect_untrusted.detect(parse_repo(inert, tables).contexts[0], tables) == []
    kinds = {
        h.kind for h in detect_untrusted.detect(parse_repo(consuming, tables).contexts[0], tables)
    }
    assert "upstream-artifact" in kinds


# --------------------------------------------------------------------------
# P
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "reference",
    ["${{ secrets.TOKEN }}", "${{ secrets['TOKEN'] }}", "${{ secrets[matrix.name] }}"],
)
def test_secret_forms_are_all_matched(tmp_path, tables, reference):
    repo = build(
        tmp_path / reference[:12].replace("$", "").replace("{", "").replace(" ", ""),
        f"""
        on: issues
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: ./s.sh
                env:
                  TOKEN: "{reference}"
        """,
    )
    ctx = parse_repo(repo, tables).contexts[0]
    kinds = {h.kind for h in detect_privilege.detect(ctx, tables)}
    assert "secret-reference" in kinds


def test_workflow_level_env_secret_is_visible(tmp_path, tables):
    """Workflow-level env is not in the job body; without it being resolved onto
    the context this is a silent false negative."""
    repo = build(
        tmp_path,
        """
        on: issues
        env:
          DEPLOY: ${{ secrets.DEPLOY_KEY }}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: ./s.sh
        """,
    )
    ctx = parse_repo(repo, tables).contexts[0]
    reasons = " ".join(h.reason for h in detect_privilege.detect(ctx, tables))
    assert "DEPLOY_KEY" in reasons


def test_fork_pull_request_privilege_is_not_attacker_reachable(tmp_path, tables):
    """GitHub withholds secrets and forces a read-only token for fork PRs, so a
    declared write scope is not reachable by the attacker."""
    repo = build(
        tmp_path,
        """
        on: [push, pull_request]
        jobs:
          a:
            runs-on: ubuntu-latest
            permissions:
              security-events: write
            steps:
              - run: make
        """,
    )
    ctx = parse_repo(repo, tables).contexts[0]
    assert detect_privilege.attacker_reachable_privilege(ctx, tables) is False


def test_self_hosted_runner_is_privilege(tmp_path, tables):
    repo = build(
        tmp_path,
        """
        on: pull_request
        jobs:
          a:
            runs-on: [self-hosted, linux]
            steps:
              - run: make
        """,
    )
    ctx = parse_repo(repo, tables).contexts[0]
    kinds = {h.kind for h in detect_privilege.detect(ctx, tables)}
    assert "self-hosted-runner" in kinds


def test_hosted_runner_is_not_privilege(tmp_path, tables):
    repo = build(
        tmp_path,
        """
        on: pull_request
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: make
        """,
    )
    ctx = parse_repo(repo, tables).contexts[0]
    kinds = {h.kind for h in detect_privilege.detect(ctx, tables)}
    assert "self-hosted-runner" not in kinds


# --------------------------------------------------------------------------
# E
# --------------------------------------------------------------------------


def test_egress_tiers(tmp_path, tables):
    repo = build(
        tmp_path,
        """
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: make build
              - run: curl https://example.com
        """,
    )
    ctx = parse_repo(repo, tables).contexts[0]
    hits = detect_egress.detect(ctx, tables)
    assert detect_egress.highest_tier(hits) == "E2"
    assert {h.tier for h in hits} == {"E1", "E2"}


def test_read_only_actions_are_e0(tmp_path, tables):
    repo = build(
        tmp_path,
        """
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: actions/setup-node@v4
        """,
    )
    ctx = parse_repo(repo, tables).contexts[0]
    assert detect_egress.highest_tier(detect_egress.detect(ctx, tables)) == "E0"


# --------------------------------------------------------------------------
# parser robustness
# --------------------------------------------------------------------------


def test_trigger_shapes(tmp_path, tables):
    """`on:` is a string, a list, or a mapping. All three appear in the wild."""
    body = "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"
    shapes = (
        "on: push\n",
        "on: [push, pull_request]\n",
        "on:\n  push:\n    branches: [main]\n",
    )
    for index, shape in enumerate(shapes):
        workflows = tmp_path / f"t{index}" / ".github/workflows"
        workflows.mkdir(parents=True)
        (workflows / "w.yml").write_text(shape + body, encoding="utf-8")
        contexts = parse_repo(tmp_path / f"t{index}", tables).contexts
        assert contexts, f"shape {index} produced no contexts"
        assert "push" in contexts[0].triggers


def test_broken_yaml_does_not_stop_the_scan(tmp_path, tables):
    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "bad.yml").write_text("jobs:\n  a:\n   - [unclosed\n")
    (workflows / "good.yml").write_text(
        "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"
    )
    outcome = parse_repo(tmp_path, tables)
    assert [c.job_id for c in outcome.contexts] == ["b"]
    assert len(outcome.diagnostics) == 1


def test_empty_repo_is_not_an_error(tmp_path, tables):
    outcome = parse_repo(tmp_path, tables)
    assert outcome.contexts == () and outcome.files_scanned == 0


def test_null_job_body_does_not_crash(tmp_path, tables):
    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "w.yml").write_text("on: push\njobs:\n  a:\n  b:\n    runs-on: ubuntu-latest\n")
    assert len(parse_repo(tmp_path, tables).contexts) == 2


def test_merge_key_does_not_crash(tmp_path, tables):
    """Merge keys appear in the mapping but have no `.lc` entry, so a naive
    position lookup raises KeyError."""
    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "w.yml").write_text(
        "on: push\n"
        "x-base: &base\n"
        "  runs-on: ubuntu-latest\n"
        "  permissions:\n"
        "    contents: write\n"
        "jobs:\n"
        "  a:\n"
        "    <<: *base\n"
        "    steps:\n"
        "      - run: make\n"
    )
    contexts = parse_repo(tmp_path, tables).contexts
    assert len(contexts) == 1
    assert contexts[0].position.line >= 1


# --------------------------------------------------------------------------
# positions
# --------------------------------------------------------------------------


def test_literal_block_substring_position_is_exact(tmp_path, tables):
    source = (
        "on: push\n"
        "jobs:\n"
        "  a:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: |\n"
        "          echo one\n"
        "          cat CLAUDE.md\n"
        "          curl https://example.com\n"
    )
    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "w.yml").write_text(source)
    ctx = parse_repo(tmp_path, tables).contexts[0]
    run = ctx.body.get("steps")[0].get("run")
    assert run.find_substring("cat CLAUDE.md").line == 8
    assert run.find_substring("curl").line == 9


def test_positions_are_one_indexed(tmp_path, tables):
    repo = build(
        tmp_path,
        """
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: make
        """,
    )
    ctx = parse_repo(repo, tables).contexts[0]
    assert ctx.position.line == 3
