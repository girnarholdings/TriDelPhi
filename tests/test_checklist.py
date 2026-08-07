"""The `--format checklist` renderer — the plain-language output a first-time
user reads. It must state pass/fail without jargon, never leak exit codes, and
always assert the offline/no-copy guarantee."""

from __future__ import annotations

import io

from conftest import run_cli

from tridelphi.api import analyze
from tridelphi.checklist import ExternalStatus, render_checklist

MALICIOUS = "tests/fixtures/malicious/comment-and-control"
CLEAN = "tests/fixtures/clean/deploy-on-push"


def _render(repo, **kw):
    result = analyze(repo)
    buf = io.StringIO()
    render_checklist(
        result,
        repo_label=repo.name,
        files_scanned=result.files_scanned,
        jobs_scanned=result.contexts_scanned,
        elapsed=0.1,
        fail_on=kw.pop("fail_on", "critical"),
        external=kw.pop("external", None),
        stream=buf,
    )
    return buf.getvalue()


def test_offline_guarantee_is_always_stated(repo_root):
    out = _render(repo_root / MALICIOUS)
    assert "Nothing was uploaded, copied, or shared" in out
    assert "entirely on your machine" in out


def test_critical_reads_as_not_safe_with_a_plain_fix(repo_root):
    out = _render(repo_root / MALICIOUS)
    assert "NOT YET SAFE" in out
    assert "🚫" in out
    # names the job, gives a plain "do this", and never shows an exit code
    assert 'job "assist"' in out
    assert "Do this:" in out
    assert "exit" not in out.lower()
    assert "critical" not in out.lower()  # the word severity never appears


def test_clean_repo_reads_as_good(repo_root):
    out = _render(repo_root / CLEAN)
    assert "YOU'RE GOOD" in out
    assert "✅" in out


def test_ladder_rows_show_run_and_not_run(repo_root):
    external = {
        "gitleaks": ExternalStatus(ran=True, counts={"critical": 0, "warning": 0, "note": 0}),
        "osv-scanner": ExternalStatus(ran=True, counts={"critical": 2, "warning": 0, "note": 0}),
    }
    out = _render(repo_root / CLEAN, external=external)
    assert "all clear" in out                       # gitleaks ran clean
    assert "2 to fix" in out                         # osv found two
    assert "not run — add --level 3" in out          # zizmor not run
    assert "known-broken dependency" in out          # the plain external-fix line


def test_warnings_only_is_good_but_acknowledged(repo_root):
    # fail_on note demotes nothing, but warnings should soften the verdict text
    external = {
        "zizmor": ExternalStatus(ran=True, counts={"critical": 0, "warning": 3, "note": 0}),
    }
    out = _render(repo_root / CLEAN, external=external)
    assert "YOU'RE GOOD" in out
    assert "minor items" in out or "worth a look" in out


def test_no_double_separator_when_nothing_to_fix(repo_root):
    out = _render(repo_root / CLEAN)
    assert "─\n\n  ─" not in out  # no empty section between two rules


def test_cli_checklist_end_to_end(repo_root):
    result = run_cli([MALICIOUS, "--format", "checklist"], cwd=repo_root)
    assert result.returncode == 1  # exit code still honest for CI
    assert "TriDelPhi security checklist" in result.stdout
    assert "NOT YET SAFE" in result.stdout
    # stdout stays clean of the machine formats
    assert "sarif" not in result.stdout.lower()
