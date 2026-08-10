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
                ("warning", ".github/workflows/ci.yml:25", "does not set persist-credentials"),
                ("warning", ".github/workflows/other.yml:41", "uses a mutable action tag"),
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
    assert ".github/workflows/other.yml:41" in out
    # still a pass — advisory items never flip the verdict
    assert "YOU'RE GOOD" in out


def test_items_are_capped_with_a_pointer_to_the_full_report(repo_root):
    items = [("warning", f"file{i}.txt:1", f"advisory item {i}") for i in range(9)]
    external = {
        "zizmor": ExternalStatus(
            ran=True, counts={"critical": 0, "warning": 9, "note": 0}, items=items
        ),
    }
    out = _render(repo_root / CLEAN, external=external)
    assert "advisory item 0" in out and "advisory item 3" in out
    assert "advisory item 4" not in out, "more than 4 items must collapse into a pointer"
    assert "…and 5 more" in out


def test_repeated_messages_group_into_one_line_with_all_locations(repo_root):
    """Eight copies of the same lint message is a data dump; one line naming
    every location is a report."""
    msg = "does not set persist-credentials: false"
    items = [
        ("warning", ".github/workflows/ci.yml:25", msg),
        ("warning", ".github/workflows/ci.yml:41", msg),
        ("warning", ".github/workflows/ci.yml:41", msg),  # exact dupe drops
        ("warning", ".github/workflows/pages.yml:32", msg),
    ]
    external = {
        "zizmor": ExternalStatus(
            ran=True, counts={"critical": 0, "warning": 4, "note": 0}, items=items
        ),
    }
    out = _render(repo_root / CLEAN, external=external)
    assert out.count(msg) == 1, "the repeated message must appear exactly once"
    assert "ci.yml lines 25, 41" in out
    assert "pages.yml line 32" in out


def test_cve_lists_group_per_package(repo_root):
    where = "scripts/reqs.txt"
    items = [
        ("warning", where, "Package 'mcp@1.23.3' is vulnerable to 'CVE-2026-52870'"),
        ("warning", where, "Package 'mcp@1.23.3' is vulnerable to 'CVE-2026-52869'"),
        ("warning", where, "Package 'mcp@1.23.3' is vulnerable to 'CVE-2026-52870'"),  # dupe
        ("warning", where, "Package 'mcp@1.23.3' is vulnerable to 'CVE-2026-59950'"),
    ]
    external = {
        "osv-scanner": ExternalStatus(
            ran=True, counts={"critical": 0, "warning": 4, "note": 0}, items=items
        ),
    }
    out = _render(repo_root / CLEAN, external=external)
    assert "mcp 1.23.3 has 3 known flaws" in out
    assert "CVE-2026-52869" in out and "CVE-2026-59950" in out
    assert out.count("CVE-2026-52870") == 1


def test_alias_spam_is_stripped_from_sarif_messages():
    from tridelphi.checklist import items_from_sarif

    sarif = {
        "runs": [
            {
                "results": [
                    {
                        "level": "warning",
                        "message": {
                            "text": "Package 'x@1' is vulnerable to 'CVE-1' "
                            "(also known as 'PYSEC-1', 'GHSA-aaaa-bbbb')"
                        },
                    }
                ]
            }
        ]
    }
    (_sev, _where, message), = items_from_sarif(sarif)
    assert "also known as" not in message
    assert message.endswith("'CVE-1'")


def test_markdown_checklist_is_inbox_ready(repo_root):
    """The PR comment is what the email renders: verdict in the heading, a
    status table, and the minor items folded — not a monospace dump."""
    from tridelphi.api import analyze
    from tridelphi.checklist import render_checklist_markdown

    result = analyze(repo_root / CLEAN)
    external = {
        "zizmor": ExternalStatus(
            ran=True,
            counts={"critical": 0, "warning": 1, "note": 0},
            items=[("warning", "a.yml:3", "uses a mutable action tag")],
        ),
    }
    md = render_checklist_markdown(
        result,
        repo_label="demo",
        files_scanned=result.files_scanned,
        jobs_scanned=result.contexts_scanned,
        fail_on="critical",
        external=external,
    )
    assert md.startswith("### 🔺 TriDelPhi — ✅")
    assert "| Check | Result |" in md
    assert "<details>" in md and "</details>" in md
    assert "a.yml:3" in md
    assert "tridelphi fix" in md  # the reply-to-fix invitation
    assert "```" not in md, "no monospace dumps"


def _md_with_advisory(repo_root):
    from tridelphi.api import analyze
    from tridelphi.checklist import render_checklist_markdown

    result = analyze(repo_root / CLEAN)
    external = {
        "zizmor": ExternalStatus(
            ran=True, counts={"critical": 0, "warning": 3, "note": 0},
            items=[("warning", f"a.yml:{i}", "uses a mutable action tag") for i in range(3)],
        ),
        "osv-scanner": ExternalStatus(
            ran=True, counts={"critical": 0, "warning": 2, "note": 0},
            items=[("warning", "reqs.txt:1", "CVE-2026-0001 in foo 1.0")],
        ),
    }
    return render_checklist_markdown(
        result, repo_label="demo", files_scanned=result.files_scanned,
        jobs_scanned=result.contexts_scanned, fail_on="critical", external=external,
    )


def test_minor_items_summary_shows_outside_the_fold_for_email(repo_root):
    """The email collapses <details> to its summary, so a breakdown of the minor
    items must appear *before* the fold — not only the bare count."""
    md = _md_with_advisory(repo_root)
    summary_at = md.find("Worth a look (5), nothing urgent:")
    fold_at = md.find("<details>")
    assert summary_at != -1, "the email-visible summary line is missing"
    assert fold_at != -1 and summary_at < fold_at, "the summary must be outside the fold"
    # it names what the items are, not just how many
    assert "workflow-hardening gaps" in md
    assert "vulnerable dependencies" in md


def test_one_click_fix_checkbox_is_present_and_marked(repo_root):
    md = _md_with_advisory(repo_root)
    assert "<!--tridelphi-fix-->" in md, "the fix bot's checkbox marker must be present"
    assert "- [ ] <!--tridelphi-fix-->" in md, "an unchecked task-list checkbox"
    assert "Fix these for me" in md
    assert "tridelphi fix" in md  # the typed fallback still offered


def test_markdown_checklist_keeps_criticals_in_the_open(repo_root):
    from tridelphi.api import analyze
    from tridelphi.checklist import render_checklist_markdown

    result = analyze(repo_root / MALICIOUS)
    md = render_checklist_markdown(
        result,
        repo_label="demo",
        files_scanned=result.files_scanned,
        jobs_scanned=result.contexts_scanned,
        fail_on="critical",
        external=None,
    )
    assert "🚫" in md and "to fix before this is safe" in md
    assert "**Fix these first:**" in md
    # the critical must NOT be inside the details fold
    fold_at = md.find("<details>")
    crit_at = md.find("**Fix these first:**")
    assert fold_at == -1 or crit_at < fold_at


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
    severity, where, message = items[0]
    assert severity == "warning"
    assert where == "a.yml:7"
    assert message.startswith("evil")
    assert "\x1b" not in message and "\n" not in message
    assert len(message) <= 100


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
