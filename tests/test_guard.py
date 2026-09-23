"""`tridelphi guard` and the fix engine — edits that must prove themselves.

Three invariants matter more than any feature:

1. **Nothing is edited without consent.** Skipping, quitting, and EOF all leave
   every byte untouched.
2. **Every accepted edit verifies or rolls back.** A fix survives only if a
   fresh scan shows the targeted finding cleared; otherwise the original file
   comes back exactly.
3. **The advice the tool gives is advice the tool accepts.** The
   author_association gate that rule.py recommends must clear the finding when
   applied — and weak or inverted gates must not.
"""

from __future__ import annotations

import io
import shutil
from pathlib import Path

import pytest

from tridelphi.api import analyze
from tridelphi.apply import AUTO_FIXABLE, apply_action
from tridelphi.guard_cmd import run_guard

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _clone(tmp_path: Path, *names: str) -> Path:
    """A scratch repo holding copies of the named malicious workflows."""
    root = tmp_path / "repo"
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True)
    for name in names:
        src = FIXTURES / "malicious" / name / ".github" / "workflows"
        for f in src.iterdir():
            shutil.copy(f, wf / f.name)
    return root


def _critical(root: Path):
    crits = [f for f in analyze(root).findings if f.severity == "critical"]
    assert crits, "fixture lost its critical"
    return crits[0]


def _snapshot(root: Path) -> dict[str, bytes]:
    return {str(p): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def _guard(root: Path, answers: str, **kw) -> tuple[int, str]:
    out = io.StringIO()
    code = run_guard(str(root), input_stream=io.StringIO(answers), out=out, **kw)
    return code, out.getvalue()


# ---------------------------------------------------------------------------
# the detector honours its own advice (gate semantics)
# ---------------------------------------------------------------------------


GATE = 'if: contains(fromJSON(\'["OWNER","MEMBER"]\'), github.event.comment.author_association)'


def _with_job_line(root: Path, workflow: str, job_key: str, line: str) -> None:
    wf = root / ".github" / "workflows" / workflow
    text = wf.read_text()
    assert f"  {job_key}:\n" in text
    wf.write_text(text.replace(f"  {job_key}:\n", f"  {job_key}:\n    {line}\n"))


def test_strong_association_gate_clears_prompt_injection(tmp_path):
    root = _clone(tmp_path, "comment-and-control")
    _with_job_line(root, "assist.yml", "assist", GATE)
    crits = [f for f in analyze(root).findings if f.severity == "critical"]
    assert not crits, "the gate rule.py recommends must clear the finding"


def test_weak_actor_gate_does_not_clear(tmp_path):
    root = _clone(tmp_path, "comment-and-control")
    _with_job_line(root, "assist.yml", "assist", "if: github.actor == 'torvalds'")
    assert [f for f in analyze(root).findings if f.severity == "critical"], (
        "an actor-name comparison is spoofable and must not count as a gate"
    )


def test_role_word_outside_association_allowlist_does_not_clear(tmp_path):
    root = _clone(tmp_path, "comment-and-control")
    gate = (
        "if: contains(fromJSON('[\"CONTRIBUTOR\"]'), "
        "github.event.comment.author_association) && github.actor == 'OWNER'"
    )
    _with_job_line(root, "assist.yml", "assist", gate)
    result = analyze(root)
    assert [f for f in result.findings if f.severity == "critical"]
    assert [
        f for f in result.findings
        if f.rule_id == "tridelphi/weak-actor-guard"
    ]


@pytest.mark.parametrize(
    "gate",
    [
        "if: ${{ !contains(fromJSON('[\"OWNER\",\"MEMBER\"]'), github.event.comment.author_association) }}",
        "if: github.event.comment.author_association != 'MEMBER'",
    ],
)
def test_inverted_gates_do_not_clear(tmp_path, gate):
    root = _clone(tmp_path, "comment-and-control")
    _with_job_line(root, "assist.yml", "assist", gate)
    assert [f for f in analyze(root).findings if f.severity == "critical"], (
        "an inverted association test admits strangers and must stay critical"
    )


# ---------------------------------------------------------------------------
# the fixers, one by one — applied, verified, and idiomatic
# ---------------------------------------------------------------------------


def test_env_indirect_fix_hoists_every_injected_expression(tmp_path):
    root = _clone(tmp_path, "issue-to-write-token")
    result = apply_action(root, _critical(root), "fix")
    assert result.status == "applied"
    text = (root / ".github/workflows/triage.yml").read_text()
    # Both expressions hoisted — fixing only one would fail verification.
    assert "ISSUE_TITLE: ${{ github.event.issue.title }}" in text
    assert "ISSUE_BODY: ${{ github.event.issue.body }}" in text
    # Quoted idiomatically: inside an open string the var is bare.
    assert 'echo "Triaging: $ISSUE_TITLE"' in text
    assert './scripts/triage.sh "$ISSUE_BODY"' in text
    fresh = analyze(root)
    assert not fresh.diagnostics
    assert not [f for f in fresh.findings if f.severity == "critical"]


def test_drop_ref_fix_removes_head_checkout(tmp_path):
    root = _clone(tmp_path, "pwn-request-target")
    result = apply_action(root, _critical(root), "fix")
    assert result.status == "applied"
    text = (root / ".github/workflows/integration.yml").read_text()
    assert "github.event.pull_request.head" not in text
    assert "with:" not in text, "an emptied with: block must be removed"
    assert not [f for f in analyze(root).findings if f.severity == "critical"]


def test_narrow_trigger_fix_inserts_the_gate(tmp_path):
    root = _clone(tmp_path, "comment-and-control")
    result = apply_action(root, _critical(root), "fix")
    assert result.status == "applied"
    text = (root / ".github/workflows/assist.yml").read_text()
    assert "author_association" in text
    assert not [f for f in analyze(root).findings if f.severity == "critical"]


_ISSUE_BODY_AGENT = """\
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
          prompt: "Fix the issue described here: ${{ github.event.issue.body }}"
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
"""


def _repo_with(tmp_path: Path, workflow: str) -> Path:
    root = tmp_path / "repo"
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "assist.yml").write_text(workflow, encoding="utf-8")
    return root


def test_narrow_trigger_gates_the_author_of_the_injected_text(tmp_path):
    """The job fires on comments, but the prompt carries the ISSUE body. A gate
    on the commenter lets a maintainer's comment run a stranger's issue, so the
    fix must vet the issue author — and the detectors must accept that gate."""
    root = _repo_with(tmp_path, _ISSUE_BODY_AGENT)
    finding = _critical(root)
    assert "github.event.issue.author_association" in finding.remediation.rendered
    result = apply_action(root, finding, "fix")
    assert result.status == "applied"
    text = (root / ".github/workflows/assist.yml").read_text()
    assert "github.event.issue.author_association" in text
    assert not [f for f in analyze(root).findings if f.severity == "critical"]


def test_a_commenter_gate_does_not_vouch_for_the_issue_body(tmp_path):
    gated = _ISSUE_BODY_AGENT.replace(
        "    runs-on: ubuntu-latest\n",
        "    runs-on: ubuntu-latest\n    if: contains(fromJSON('[\"OWNER\",\"MEMBER\"]'), "
        "github.event.comment.author_association)\n",
    )
    root = _repo_with(tmp_path, gated)
    assert any(
        f.rule_id == "tridelphi/agent-prompt-injection" and f.severity == "critical"
        for f in analyze(root).findings
    )


def test_unvettable_prompt_text_is_not_offered_a_gate(tmp_path):
    """No author_association vouches for an upstream run's title, so the advice
    must not promise that a gate fixes it."""
    workflow = _ISSUE_BODY_AGENT.replace(
        "on:\n  issue_comment:\n    types: [created]\n",
        "on:\n  workflow_run:\n    workflows: [ci]\n    types: [completed]\n",
    ).replace("github.event.issue.body", "github.event.workflow_run.display_title")
    root = _repo_with(tmp_path, workflow)
    finding = next(f for f in analyze(root).findings if f.rule_id == "tridelphi/agent-prompt-injection")
    assert finding.remediation.kind == "drop-prompt-input"
    assert "if: contains(" not in finding.remediation.rendered


def test_comment_out_neutralises_the_step(tmp_path):
    root = _clone(tmp_path, "comment-and-control")
    result = apply_action(root, _critical(root), "comment-out")
    assert result.status == "applied"
    text = (root / ".github/workflows/assist.yml").read_text()
    assert "# tridelphi: step disabled" in text
    assert not [f for f in analyze(root).findings if f.severity == "critical"]


def test_disable_renames_the_workflow(tmp_path):
    root = _clone(tmp_path, "pwn-request-target")
    result = apply_action(root, _critical(root), "disable")
    assert result.status == "applied"
    wf_dir = root / ".github" / "workflows"
    assert not (wf_dir / "integration.yml").exists()
    disabled = wf_dir / "integration.yml.disabled"
    assert disabled.is_file()
    assert disabled.read_text().startswith("# tridelphi: workflow disabled")
    assert not analyze(root).findings


def test_failed_fix_rolls_back_to_exact_bytes(tmp_path, monkeypatch):
    """If verification fails, the original file must come back untouched."""
    root = _clone(tmp_path, "issue-to-write-token")
    before = _snapshot(root)
    monkeypatch.setattr("tridelphi.apply._verify_cleared", lambda *_: False)
    result = apply_action(root, _critical(root), "fix")
    assert result.status == "failed"
    assert _snapshot(root) == before


def test_fix_that_breaks_yaml_is_rejected_and_rolled_back(tmp_path, monkeypatch):
    """Making the original finding disappear via a parse error is not a fix."""
    from tridelphi import apply as apply_module

    root = _clone(tmp_path, "issue-to-write-token")
    finding = _critical(root)
    before = _snapshot(root)
    monkeypatch.setitem(
        apply_module._TRANSFORMS,
        "env-indirect",
        lambda *_args: "name: broken\non: [\n",
    )
    result = apply_action(root, finding, "fix")
    assert result.status == "failed"
    assert _snapshot(root) == before


def test_drop_ref_fix_never_edits_multiple_steps_at_once(tmp_path):
    """A finding may cover multiple unsafe checkouts; one consented fix edits
    one step, then verification rolls back because another remains."""
    root = _clone(tmp_path, "pwn-request-target")
    workflow = root / ".github/workflows/integration.yml"
    text = workflow.read_text()
    checkout = """\
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
          repository: ${{ github.event.pull_request.head.repo.full_name }}
"""
    assert checkout in text
    workflow.write_text(text.replace(checkout, checkout + checkout))
    before = workflow.read_bytes()
    result = apply_action(root, _critical(root), "fix")
    assert result.status == "failed"
    assert workflow.read_bytes() == before


def test_disable_refuses_to_overwrite_existing_backup(tmp_path):
    root = _clone(tmp_path, "pwn-request-target")
    finding = _critical(root)
    workflow = root / ".github/workflows/integration.yml"
    disabled = workflow.with_name(workflow.name + ".disabled")
    disabled.write_text("existing backup\n")
    original = workflow.read_bytes()

    result = apply_action(root, finding, "disable")

    assert result.status == "unavailable"
    assert workflow.read_bytes() == original
    assert disabled.read_text() == "existing backup\n"


def test_fixer_refuses_a_workflow_directory_swapped_to_a_symlink(tmp_path):
    root = _clone(tmp_path, "pwn-request-target")
    finding = _critical(root)
    workflow_dir = root / ".github" / "workflows"
    original_dir = root / ".github" / "workflows-original"
    workflow_dir.rename(original_dir)
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_file = outside / "integration.yml"
    outside_file.write_text("do not edit\n", encoding="utf-8")
    workflow_dir.symlink_to(outside, target_is_directory=True)

    result = apply_action(root, finding, "fix")

    assert result.status == "unavailable"
    assert outside_file.read_text(encoding="utf-8") == "do not edit\n"


def test_failed_disable_rolls_back(tmp_path, monkeypatch):
    root = _clone(tmp_path, "pwn-request-target")
    before = _snapshot(root)
    monkeypatch.setattr("tridelphi.apply._verify_cleared", lambda *_: False)
    result = apply_action(root, _critical(root), "disable")
    assert result.status == "failed"
    assert _snapshot(root) == before


# ---------------------------------------------------------------------------
# the interactive loop — consent, batch mode, exit codes
# ---------------------------------------------------------------------------


def test_guard_fixes_three_shapes_interactively(tmp_path):
    root = _clone(
        tmp_path, "issue-to-write-token", "pwn-request-target", "comment-and-control"
    )
    code, out = _guard(root, "y\ny\ny\n")
    assert code == 0
    assert out.count("✓") == 3
    assert "No criticals remain" in out
    assert not [f for f in analyze(root).findings if f.severity == "critical"]


def test_guard_skip_edits_nothing_and_exits_one(tmp_path):
    root = _clone(tmp_path, "pwn-request-target")
    before = _snapshot(root)
    code, out = _guard(root, "s\n")
    assert code == 1
    assert _snapshot(root) == before
    assert "still open" in out


def test_guard_eof_means_no_consent(tmp_path):
    """A closed stdin must never be read as a yes."""
    root = _clone(tmp_path, "pwn-request-target")
    before = _snapshot(root)
    code, _out = _guard(root, "")
    assert code == 1
    assert _snapshot(root) == before


def test_guard_yes_batch_applies_auto_fixes_only(tmp_path):
    root = _clone(tmp_path, "issue-to-write-token", "pwn-request-target")
    code, out = _guard(root, "", yes=True)
    assert code == 0
    assert out.count("✓") == 2
    # Batch mode never renames or comments out — both files still active .yml.
    names = {p.name for p in (root / ".github" / "workflows").iterdir()}
    assert names == {"triage.yml", "integration.yml"}


def test_guard_clean_repo_is_a_noop(tmp_path):
    root = tmp_path / "clean"
    shutil.copytree(FIXTURES / "clean" / "hardened-agent", root)
    before = _snapshot(root)
    code, out = _guard(root, "", yes=True)
    assert code == 0
    assert "Nothing to fix" in out
    assert _snapshot(root) == before


def test_guard_disable_choice_disables(tmp_path):
    root = _clone(tmp_path, "pwn-request-target")
    code, _out = _guard(root, "d\n")
    assert code == 0
    assert (root / ".github/workflows/integration.yml.disabled").is_file()


def test_auto_fixable_covers_the_mechanical_kinds():
    assert {"env-indirect", "drop-untrusted-ref", "narrow-trigger"} == AUTO_FIXABLE


# --- optional tooling: say what is missing, never fetch it silently ---------


def _guard_tools(tmp_path, monkeypatch, *, present, answer="q\n", yes=False, scripts=True):
    """Run guard in a scratch repo with a chosen set of tools 'installed'."""
    import shutil as _shutil

    from tridelphi import guard_cmd

    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
    )
    if scripts:
        (repo / "scripts").mkdir()
        for name in ("install-ladder.sh", "install-privatize.sh"):
            (repo / "scripts" / name).write_text("#!/bin/sh\nexit 0\n")

    monkeypatch.setattr(guard_cmd.shutil if hasattr(guard_cmd, "shutil") else _shutil,
                        "which", lambda name: "/usr/bin/" + name if name in present else None)
    # privatize's obfuscator is found in its own install directory, never PATH.
    monkeypatch.setattr(
        "tridelphi.privatize._find_obfuscator",
        lambda _root: ["/opt/obf"] if "javascript-obfuscator" in present else None,
    )
    out = io.StringIO()
    guard_cmd.run_guard(str(repo), yes=yes, input_stream=io.StringIO(answer), out=out,
                        err=io.StringIO())
    return out.getvalue()


def test_guard_names_the_tools_it_is_missing(tmp_path, monkeypatch):
    out = _guard_tools(tmp_path, monkeypatch, present={"zizmor"})
    assert "Optional tools not installed" in out
    assert "gitleaks" in out and "semgrep" in out
    assert "zizmor" not in out.split("Optional tools not installed")[1].split("\n\n")[0]


def test_guard_is_silent_when_every_tool_is_present(tmp_path, monkeypatch):
    present = {"gitleaks", "osv-scanner", "zizmor", "scorecard", "semgrep",
               "javascript-obfuscator"}
    out = _guard_tools(tmp_path, monkeypatch, present=present)
    assert "Optional tools not installed" not in out


def test_guard_never_installs_without_an_explicit_yes(tmp_path, monkeypatch):
    """Even an affirmative input cannot run scripts from the scanned project."""
    calls = []
    import subprocess

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: calls.append(a) or None)
    out = _guard_tools(tmp_path, monkeypatch, present={"zizmor"}, answer="y\n")
    assert not calls, "a target repository must never supply an installer"
    assert "never runs installer scripts from the project" in out


def test_dash_y_does_not_authorise_downloading_binaries(tmp_path, monkeypatch):
    """-y means 'apply fixes without asking'. Fetching and running binaries is a
    different class of act and must not ride along on it."""
    calls = []
    import subprocess

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: calls.append(a) or None)
    out = _guard_tools(tmp_path, monkeypatch, present=set(), yes=True)
    assert not calls, "-y must never trigger an install"
    assert "-y` only authorizes verified code fixes" in out


def test_guard_never_offers_target_repo_installers(tmp_path, monkeypatch):
    """Target-owned installer names never become executable authority."""
    out = _guard_tools(tmp_path, monkeypatch, present={"zizmor"}, scripts=False)
    assert "Install them now?" not in out
    assert "official" in out and "checksum-verified installer" in out


# ---------------------------------------------------------------------------
# a verified fix must also leave the step doing what it did
# ---------------------------------------------------------------------------


_ISSUE_RUN = """\
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: RUNNER
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        if: github.event.issue.number > 0
      - SHELLrun: |
          SCRIPT
"""


def _issue_repo(tmp_path: Path, script: str, *, runner="ubuntu-latest", shell="") -> Path:
    workflow = (_ISSUE_RUN.replace("RUNNER", runner).replace("SHELL", shell)
                .replace("SCRIPT", script))
    return _repo_with(tmp_path, workflow)


def _run_line(root: Path) -> str:
    text = (root / ".github/workflows/assist.yml").read_text()
    return next(ln.strip() for ln in text.splitlines() if "curl" in ln)


@pytest.mark.parametrize("script,expected", [
    # `$ISSUE_TITLE_x` would read a different, unset variable.
    ('echo "${{ github.event.issue.title }}_x" && curl https://x.example',
     'echo "${ISSUE_TITLE}_x" && curl https://x.example'),
    # Nothing expands inside single quotes: close them around the reference.
    ("echo 'T: ${{ github.event.issue.title }}!' && curl https://x.example",
     "echo 'T: '\"$ISSUE_TITLE\"'!' && curl https://x.example"),
    ("echo ${{ github.event.issue.title }} && curl https://x.example",
     'echo "$ISSUE_TITLE" && curl https://x.example'),
])
def test_env_indirect_keeps_the_scripts_meaning(tmp_path, script, expected):
    root = _issue_repo(tmp_path, script)
    assert apply_action(root, _critical(root), "fix").status == "applied"
    assert _run_line(root) == expected


@pytest.mark.parametrize("runner,shell", [
    ("ubuntu-latest", "shell: pwsh\n        "),
    ("windows-latest", ""),
    ("${{ matrix.os }}", ""),
])
def test_env_indirect_declines_a_shell_that_reads_variables_differently(tmp_path, runner, shell):
    """PowerShell reads `$env:NAME`; `"$NAME"` there is an unset variable. The
    re-scan would pass and the step would quietly stop working."""
    root = _issue_repo(tmp_path, 'echo "${{ github.event.issue.title }}"; curl https://x.example',
                       runner=runner, shell=shell)
    before = _snapshot(root)
    result = apply_action(root, _critical(root), "fix")
    assert result.status == "unavailable" and "PowerShell" in result.detail
    assert _snapshot(root) == before


def test_explicit_bash_on_windows_is_still_fixed(tmp_path):
    root = _issue_repo(tmp_path, 'echo "${{ github.event.issue.title }}"; curl https://x.example',
                       runner="windows-latest", shell="shell: bash\n        ")
    assert apply_action(root, _critical(root), "fix").status == "applied"


def test_fix_keeps_crlf_line_endings(tmp_path):
    root = _issue_repo(tmp_path, 'echo "${{ github.event.issue.title }}" && curl https://x.example')
    wf = root / ".github/workflows/assist.yml"
    wf.write_bytes(wf.read_bytes().replace(b"\n", b"\r\n"))
    assert apply_action(root, _critical(root), "fix").status == "applied"
    data = wf.read_bytes()
    assert b"ISSUE_TITLE" in data and data.count(b"\n") == data.count(b"\r\n")


def test_rollback_restores_crlf_bytes_exactly(tmp_path, monkeypatch):
    root = _issue_repo(tmp_path, 'echo "${{ github.event.issue.title }}" && curl https://x.example')
    wf = root / ".github/workflows/assist.yml"
    wf.write_bytes(wf.read_bytes().replace(b"\n", b"\r\n"))
    before = wf.read_bytes()
    monkeypatch.setattr("tridelphi.apply._verify_cleared", lambda *a, **k: False)
    assert apply_action(root, _critical(root), "fix").status == "failed"
    assert wf.read_bytes() == before


def test_workflow_that_is_not_utf8_is_left_alone(tmp_path):
    root = _issue_repo(tmp_path, 'echo "${{ github.event.issue.title }}" && curl https://x.example')
    wf = root / ".github/workflows/assist.yml"
    wf.write_bytes(wf.read_bytes().replace(b"triage:", b"triage:  # caf\xe9", 1))
    before = wf.read_bytes()
    finding = _critical(root)
    for action in ("fix", "comment-out", "disable"):
        result = apply_action(root, finding, action)
        assert result.status in ("unavailable", "failed") and "UTF-8" in result.detail
    assert wf.read_bytes() == before


def test_narrow_trigger_is_not_blocked_by_a_steps_own_if(tmp_path):
    """Only a job-level `if:` is a gate to preserve; nearly every real job has
    steps with their own conditions."""
    workflow = _ISSUE_BODY_AGENT.replace(
        "      - uses: anthropics/claude-code-action@v1\n",
        "      - uses: actions/checkout@v4\n        if: github.event.issue.number > 0\n"
        "      - uses: anthropics/claude-code-action@v1\n",
    )
    root = _repo_with(tmp_path, workflow)
    assert apply_action(root, _critical(root), "fix").status == "applied"
    assert not [f for f in analyze(root).findings if f.severity == "critical"]


def test_a_nested_key_named_like_the_job_is_not_the_job(tmp_path):
    """A service container called `assist` in an earlier job is not job
    `assist`; the gate belongs under the job key."""
    workflow = _ISSUE_BODY_AGENT.replace(
        "jobs:\n",
        "jobs:\n  lint:\n    runs-on: ubuntu-latest\n    services:\n      assist:\n"
        "        image: redis:7\n    steps:\n      - run: make lint\n",
    )
    root = _repo_with(tmp_path, workflow)
    assert apply_action(root, _critical(root), "fix").status == "applied"
    text = (root / ".github/workflows/assist.yml").read_text()
    assert text.index("author_association") > text.index("\n  assist:")
