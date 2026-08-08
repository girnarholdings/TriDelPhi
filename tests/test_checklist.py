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


def test_worth_a_look_is_explained_and_itemized(repo_root):
    """A bare count teaches nothing: the log itself must say what the phrase
    means and show the actual items with their locations."""
    external = {
        "zizmor": ExternalStatus(
            ran=True,
            counts={"critical": 0, "warning": 2, "note": 0},
            items=[
                ("warning", ".github/workflows/ci.yml:25 — does not set persist-credentials"),
                ("warning", ".github/workflows/ci.yml:41 — does not set persist-credentials"),
            ],
        ),
    }
    out = _render(repo_root / CLEAN, external=external)
    # the legend, once, in plain words
    assert 'What "worth a look" means' in out
    assert "Not an open door" in out
    # the per-rung gloss and the concrete items
    assert "hardening habit in your automation files" in out
    assert ".github/workflows/ci.yml:25" in out
    assert ".github/workflows/ci.yml:41" in out
    # still a pass — advisory items never flip the verdict
    assert "YOU'RE GOOD" in out


def test_items_are_capped_with_a_pointer_to_the_full_report(repo_root):
    items = [("warning", f"file.txt:{i} — advisory item {i}") for i in range(9)]
    external = {
        "osv-scanner": ExternalStatus(
            ran=True, counts={"critical": 0, "warning": 9, "note": 0}, items=items
        ),
    }
    out = _render(repo_root / CLEAN, external=external)
    assert "file.txt:0" in out and "file.txt:3" in out
    assert "file.txt:4" not in out, "more than 4 items must collapse into a pointer"
    assert "…and 5 more" in out


def test_no_legend_when_everything_passes(repo_root):
    out = _render(repo_root / CLEAN)
    assert 'What "worth a look" means' not in out


def test_items_from_sarif_sanitizes_untrusted_text():
    """Tool output is untrusted: control characters go, length is bounded,
    malformed results are skipped rather than fatal."""
    from tridelphi.checklist import items_from_sarif

    sarif = {
        "runs": [
            {
                "results": [
                    {
                        "level": "warning",
                        "message": {"text": "evil\x1b[31m\ntext  " + "x" * 500},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "a.yml"},
                                    "region": {"startLine": 7},
                                }
                            }
                        ],
                    },
                    {"level": 42, "message": "not a dict"},
                    "not even a result",
                ]
            },
            "not a run",
        ]
    }
    items = items_from_sarif(sarif)
    assert len(items) == 2  # the malformed string result is skipped
    severity, text = items[0]
    assert severity == "warning"
    assert text.startswith("a.yml:7 — evil")
    assert "\x1b" not in text and "\n" not in text
    assert len(text) <= 100 + len("a.yml:7 — ")


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
