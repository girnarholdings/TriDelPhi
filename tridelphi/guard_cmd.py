"""`tridelphi guard` — find it, explain it, and fix it, with your say-so.

The scan and the fix plan already exist; guard closes the loop. For every
finding it shows the exact solution, then asks one question: fix it now?

    [y] apply the automatic fix        (only where one exists)
    [c] comment out the offending step
    [d] disable this workflow file     (rename to .yml.disabled — reversible)
    [s] skip                           [q] quit

Consent is per finding and nothing is edited without it. Every accepted edit
goes through `apply.py`'s verify-or-rollback contract: the file is changed only
if a fresh scan proves the finding cleared; otherwise the original bytes come
back and guard says so. `--yes` is the non-interactive spelling: it applies the
automatic fixers only — it never comments out or disables anything, because
those change what your CI does and deserve a human eye.

With `--level N` the wrapped rungs run too. Their findings come from tools we
do not control, so guard does not pretend to auto-fix them — it prints each
tool's result with the exact next step a person should take.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TextIO

from .api import AnalysisError, analyze
from .apply import AUTO_FIXABLE, apply_action, finding_key
from .fix_cmd import _cost, _plan_order
from .model import Finding

__all__ = ["run_guard"]

_RULE = "─" * 62

# The exact next step for each wrapped rung, in plain language. These tools'
# findings are not ours to auto-edit; the value we add is the translation.
_EXTERNAL_ADVICE = {
    "gitleaks": (
        "A committed password/key cannot be fixed by deleting the line — it is "
        "already in your git history. Rotate the credential (make a new one, "
        "revoke the old), then remove it from the file and store it in "
        "Settings → Secrets instead."
    ),
    "osv-scanner": (
        "A known-broken dependency is fixed by upgrading: bump the version in "
        "your lockfile/manifest to the fixed release named in the finding, "
        "reinstall, and re-run the scan."
    ),
    "zizmor": (
        "These are workflow-hardening findings. Most are one-line changes; "
        "zizmor's message names the file and line."
    ),
    "scorecard": (
        "These are repository-settings improvements (branch protection, "
        "review requirements). They are changed in GitHub Settings, not in "
        "files — the check name tells you which page."
    ),
    "semgrep": (
        "These are code patterns in your application source. Each message "
        "names the file, line and pattern; fix the code or add a reviewed "
        "ignore comment if it is a false positive."
    ),
}


def _prompt(*, has_auto: bool, stream: TextIO, out: TextIO) -> str:
    options = []
    if has_auto:
        options.append("[y] fix it now")
    options += ["[c] comment out the step", "[d] disable this workflow", "[s] skip", "[q] quit"]
    print("  " + "   ".join(options), file=out)
    print("  > ", end="", file=out, flush=True)
    line = stream.readline()
    if not line:  # EOF — treat as quit, never guess consent
        return "q"
    return line.strip().lower()[:1] or "s"


def _card(finding: Finding, index: int, total: int, out: TextIO) -> None:
    rem = finding.remediation
    _rank, label = _cost(finding)
    print(_RULE, file=out)
    print(
        f"  {index}/{total} · {finding.severity.upper()} · {label}",
        file=out,
    )
    print(
        f'  {finding.primary_position.file}:{finding.primary_position.line}   '
        f'job "{finding.context.job_id}"',
        file=out,
    )
    print(file=out)
    if rem is not None:
        for ln in rem.rendered.split("\n"):
            print(f"  {ln}" if ln.strip() else "", file=out)
        print(f"\n  Trade-off: {rem.breaks}", file=out)
    else:
        print(f"  {finding.message}", file=out)
    print(file=out)


def _gating(findings, include_warnings: bool) -> list[Finding]:
    wanted = ("critical", "warning") if include_warnings else ("critical",)
    return sorted((f for f in findings if f.severity in wanted), key=_plan_order)


def run_guard(
    path: str,
    *,
    yes: bool = False,
    include_warnings: bool = False,
    level: int | None = None,
    offline: bool = False,
    input_stream: TextIO | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    input_stream = input_stream or sys.stdin
    root = Path(path)

    try:
        result = analyze(root)
    except AnalysisError as exc:
        print(f"tridelphi: {exc}", file=err)
        return 2

    todo = _gating(result.findings, include_warnings)
    total = len(todo)
    print(f"tridelphi guard · {root.resolve().name or path}", file=out)
    if not todo:
        print("\n  Nothing to fix — no job holds all three powers.\n", file=out)
    else:
        print(
            f"\n  {total} finding{'s' if total != 1 else ''}. For each one: the exact "
            "solution, and the choice is yours.\n"
            "  Every accepted edit is re-scanned before it sticks; if the fix does "
            "not verify, your file comes back untouched.\n",
            file=out,
        )

    handled = 0
    skipped: set[tuple[str, str, str]] = set()
    quit_early = False
    index = 0
    while not quit_early:
        todo = [f for f in _gating(analyze(root).findings, include_warnings)
                if finding_key(f) not in skipped]
        if not todo:
            break
        finding = todo[0]
        index += 1
        kind = finding.remediation.kind if finding.remediation else ""
        has_auto = kind in AUTO_FIXABLE
        _card(finding, index, total, out)

        if yes:
            choice = "y" if has_auto else "s"
        else:
            choice = _prompt(has_auto=has_auto, stream=input_stream, out=out)

        if choice == "q":
            quit_early = True
            skipped.add(finding_key(finding))
            continue
        if choice == "s" or (choice == "y" and not has_auto):
            skipped.add(finding_key(finding))
            print("  ↷ skipped\n", file=out)
            continue

        action = {"y": "fix", "c": "comment-out", "d": "disable"}.get(choice)
        if action is None:
            skipped.add(finding_key(finding))
            print("  ↷ unrecognised choice — skipped\n", file=out)
            continue

        outcome = apply_action(root, finding, action)
        if outcome.status == "applied":
            handled += 1
            print(f"  ✓ {outcome.detail}\n", file=out)
        else:
            skipped.add(finding_key(finding))
            print(f"  ✗ {outcome.detail}\n", file=out)

    # ----- wrapped rungs: translate, don't pretend to auto-fix -------------
    if level is not None:
        from .ladder import run_ladder

        print(_RULE, file=out)
        print(f"  Ladder rungs up to L{level}:", file=out)
        for ext in run_ladder(str(root), level=level, offline=offline):
            if ext.diagnostic is not None:
                print(f"  · {ext.spec.name}: {ext.diagnostic.message}", file=out)
                continue
            counts = ext.severity_counts
            worth = sum(counts.values())
            if not worth:
                print(f"  · {ext.spec.name}: all clear", file=out)
                continue
            print(f"  · {ext.spec.name}: {worth} finding{'s' if worth != 1 else ''}", file=out)
            advice = _EXTERNAL_ADVICE.get(ext.spec.name)
            if advice:
                print(f"      Do this: {advice}", file=out)

    # ----- the verdict is the fresh state, not the session log -------------
    remaining = _gating(analyze(root).findings, include_warnings=False)
    print(_RULE, file=out)
    if handled:
        print(f"  {handled} fix{'es' if handled != 1 else ''} applied and verified.", file=out)
    if remaining:
        print(
            f"  {len(remaining)} critical{'s' if len(remaining) != 1 else ''} still "
            "open — run `tridelphi fix` for the written plan.\n",
            file=out,
        )
        return 1
    print("  No criticals remain. You're good.\n", file=out)
    return 0
