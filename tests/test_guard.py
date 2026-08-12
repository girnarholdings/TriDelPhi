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
    assert not [f for f in analyze(root).findings if f.severity == "critical"]


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
    """Declining must leave the machine untouched — and say what that costs."""
    calls = []
    import subprocess

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: calls.append(a) or None)
    out = _guard_tools(tmp_path, monkeypatch, present={"zizmor"}, answer="n\n")
    assert not calls, "declining must not run an installer"
    assert "Left alone" in out


def test_dash_y_does_not_authorise_downloading_binaries(tmp_path, monkeypatch):
    """-y means 'apply fixes without asking'. Fetching and running binaries is a
    different class of act and must not ride along on it."""
    calls = []
    import subprocess

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: calls.append(a) or None)
    out = _guard_tools(tmp_path, monkeypatch, present=set(), yes=True)
    assert not calls, "-y must never trigger an install"
    assert "-y covers applying fixes, not downloading tools" in out


def test_guard_does_not_offer_what_it_cannot_run(tmp_path, monkeypatch):
    """The wheel does not ship scripts/, so the offer only appears where the
    installers actually exist."""
    out = _guard_tools(tmp_path, monkeypatch, present={"zizmor"}, scripts=False)
    assert "Install them now?" not in out
    assert "checksum-verified scripts" in out
