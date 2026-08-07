"""Checklist output — the scan as a plain-language safety checklist.

The default text renderer is written for someone who already knows what a CI
job, a secret, and an exit code are. This renderer is for everyone else: it
answers "is my repo safe, and if not, what do I actually do?" in words a
non-technical builder can act on, framed as a corporate-style checklist. It is
what the generated PR-bot comment posts, because that is the output a first-time
user actually reads.

It reports the same findings as every other format — nothing is hidden or
softened — only the vocabulary changes. Exit codes, severities, and rule ids
still exist for the CI path; here they become ✅ / ⚠️ / 🚫 and a plain verdict.
"""

from __future__ import annotations

from typing import TextIO

from .model import AnalysisResult
from .render import SEVERITY_ORDER

__all__ = ["ExternalStatus", "render_checklist"]

# name → (ladder level, the plain question the check answers)
_LADDER_ROWS: tuple[tuple[str, int, str], ...] = (
    ("gitleaks", 1, "Any passwords left sitting in your files?"),
    ("osv-scanner", 2, "Any known-broken building blocks in use?"),
    ("zizmor", 3, "Are your automations set up safely?"),
    ("scorecard", 4, "Do your repo settings follow safe defaults?"),
    ("semgrep", 5, "Does your app code have risky patterns?"),
    ("trust", 7, "Did any trusted outside tool get swapped?"),
)

# which capability the fix removes → what a person actually does
_PLAIN_FIX = {
    "U": "gate this job so only trusted people can trigger it",
    "P": "take away the secret or permission this job doesn't need",
    "E": "stop this job from reaching the internet",
}


class ExternalStatus:
    """One wrapped-tool's outcome, reduced to what the checklist needs."""

    __slots__ = ("counts", "ran")

    def __init__(self, ran: bool, counts: dict[str, int] | None = None) -> None:
        self.ran = ran
        self.counts = counts or {"critical": 0, "warning": 0, "note": 0}


def _plain_why(capabilities: set[str]) -> str:
    parts = []
    if "U" in capabilities:
        parts.append("a stranger's input can reach this job")
    if "P" in capabilities:
        parts.append("it holds your secrets or permissions")
    if "E" in capabilities:
        parts.append("it can reach the internet")
    if not parts:
        return "this job holds a risky combination of powers."
    if len(parts) == 1:
        return parts[0] + "."
    return ", ".join(parts[:-1]) + ", and " + parts[-1] + "."


def _row(status: str, question: str, note: str, width: int = 56) -> str:
    icon = {"pass": "✅", "warn": "⚠️ ", "fail": "🚫", "skip": "⬜"}[status]
    q = question if len(question) <= width else question[: width - 1] + "…"
    return f"  {icon}  {q.ljust(width)}  {note}"


def render_checklist(
    result: AnalysisResult,
    *,
    repo_label: str,
    files_scanned: int,
    jobs_scanned: int,
    elapsed: float,
    fail_on: str,
    external: dict[str, ExternalStatus] | None = None,
    stream: TextIO,
) -> None:
    external = external or {}
    threshold = SEVERITY_ORDER.get(fail_on, 0) if fail_on != "none" else 99

    core_findings = [f for f in result.findings if f.rule_id != "tridelphi/parse-error"]
    core_crit = [f for f in core_findings if f.severity == "critical"]
    core_warn = [f for f in core_findings if f.severity == "warning"]

    bar = "─" * 60
    print(bar, file=stream)
    print("  🔺 TriDelPhi security checklist", file=stream)
    scanned = (
        f"  {repo_label} · {jobs_scanned} job{'s' if jobs_scanned != 1 else ''} "
        f"across {files_scanned} workflow{'s' if files_scanned != 1 else ''} "
        f"· scanned in {elapsed:.1f}s"
    )
    print(scanned, file=stream)
    print("  ✓ Ran entirely on your machine. Nothing was uploaded, copied, or shared.", file=stream)
    print(bar, file=stream)
    print("", file=stream)

    # --- the checklist rows ---
    def note_for(counts: dict[str, int]) -> tuple[str, str]:
        c, w = counts["critical"], counts["warning"]
        if c:
            return "fail", f"{c} to fix"
        if w:
            return "warn", f"{w} worth a look"
        return "pass", "all clear"

    any_warn = False

    # Core: the Rule of Two — always runs.
    if core_crit:
        status, cnote = "fail", f"{len(core_crit)} to fix"
    elif core_warn:
        status, cnote = "warn", f"{len(core_warn)} worth a look"
    else:
        status, cnote = "pass", "all clear"
    any_warn = any_warn or status == "warn"
    print(_row(status, "Can a stranger trick a robot into leaking your keys?", cnote), file=stream)

    for name, level, question in _LADDER_ROWS:
        st = external.get(name)
        if st is None or not st.ran:
            print(_row("skip", question, f"not run — add --level {level}"), file=stream)
        else:
            status, cnote = note_for(st.counts)
            any_warn = any_warn or status == "warn"
            print(_row(status, question, cnote), file=stream)

    # --- what to fix ---
    actionable = sorted(
        [f for f in core_findings if SEVERITY_ORDER[f.severity] <= threshold],
        key=lambda f: (SEVERITY_ORDER[f.severity], f.sort_key),
    )
    external_fixes = [
        (name, st.counts["critical"])
        for name, _lvl, _q in _LADDER_ROWS
        if (st := external.get(name)) and st.ran and st.counts["critical"]
    ]

    total_to_fix = len(actionable) + sum(n for _n, n in external_fixes)

    if actionable or external_fixes:
        print("", file=stream)
        print(f"  {'─' * 54}", file=stream)
        noun = "thing needs" if total_to_fix == 1 else "things need"
        print(f"\n  {total_to_fix} {noun} your attention before this repo is safe:\n", file=stream)
    if actionable:
        for finding in actionable:
            caps = {h.capability for h in finding.hits if h.observed}
            where = f"{finding.primary_position.file}, job \"{finding.context.job_id}\""
            headline = (
                "A job can be tricked into leaking your keys"
                if finding.severity == "critical"
                else "A job is one small change away from being risky"
            )
            print(f"  {'🚫' if finding.severity == 'critical' else '⚠️ '} {headline}", file=stream)
            print(f"      Where:   {where}", file=stream)
            print(f"      Why:     {_plain_why(caps)}", file=stream)
            if finding.remediation is not None:
                fix = _PLAIN_FIX.get(finding.remediation.strip, "remove one of the three powers")
                print(f"      Do this: {fix}.", file=stream)
            print("", file=stream)

    for name, n in external_fixes:
        label = {
            "gitleaks": "password(s) found in your files",
            "osv-scanner": "known-broken dependency/dependencies",
            "zizmor": "unsafe workflow setting(s)",
            "scorecard": "weak repo setting(s)",
            "semgrep": "risky code pattern(s)",
            "trust": "outside tool(s) that changed hands",
        }.get(name, "issue(s)")
        print(f"  🚫 {n} {label} — see the full report for the exact spots.", file=stream)

    # --- verdict, in plain words ---
    print(f"\n  {'─' * 54}\n", file=stream)
    safe = total_to_fix == 0
    if safe and not any_warn:
        print("  Result:  ✅  YOU'RE GOOD — every check passed.", file=stream)
        print("           Run this again whenever you change your workflows.", file=stream)
    elif safe:
        print("  Result:  ✅  YOU'RE GOOD — nothing urgent to fix.", file=stream)
        print("           A few minor items are flagged above if you'd like to tidy up.", file=stream)
    else:
        item = "item" if total_to_fix == 1 else "items"
        print(f"  Result:  ⚠️  NOT YET SAFE — fix the {total_to_fix} {item} above, then run this again.", file=stream)
        print("           None of it is hard; each fix is usually one setting.", file=stream)

    if result.diagnostics:
        n = len(result.diagnostics)
        print(f"\n  Note: {n} file{'s' if n != 1 else ''} couldn't be read and were skipped.", file=stream)
