"""`tridelphi launch` — lawsuit traps in the app you are about to ship.

Same discipline as expose: verdict first, plain English, the cheapest fix,
and a scope line that refuses to turn a pattern match into legal advice or a
certificate. Warnings are patterns. Notes are checklists for what files
cannot prove.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TextIO

from .expose import ExposureLimits
from .fsutil import atomic_write_text
from .launch import CATEGORIES, NOT_LEGAL_ADVICE, LaunchFinding, LaunchResult, analyze_launch
from .reportutil import grouped_lines, md_escape, wrap
from .sarif import dumps
from .severity import should_fail

__all__ = ["run_launch"]

_MAX_ITEMS = 5


def _more(hidden: int) -> str:
    return f"…and {hidden} more — `--format sarif` lists every one."


def _status(findings: list[LaunchFinding]) -> tuple[str, str]:
    crit = sum(1 for finding in findings if finding.severity == "critical")
    warn = sum(1 for finding in findings if finding.severity == "warning")
    if crit:
        return "fail", f"{crit} to fix"
    if warn:
        return "warn", f"{warn} worth a look"
    if findings:
        return "note", "checklist"
    return "pass", "nothing found"


def _by_category(findings: list[LaunchFinding]) -> dict[str, list[LaunchFinding]]:
    owned: dict[str, list[LaunchFinding]] = {}
    for finding in findings:
        owned.setdefault(finding.category, []).append(finding)
    return owned


def _render_text(result: LaunchResult, repo: str, out: TextIO) -> None:
    bar = "─" * 60
    print(bar, file=out)
    print(f"  🔺 TriDelPhi launch audit · {repo}", file=out)
    for line in wrap(NOT_LEGAL_ADVICE, 66):
        print(f"  {line}", file=out)
    print(bar, file=out)
    print("", file=out)

    if not result.coverage.complete:
        reasons = "; ".join(result.coverage.incomplete_reasons)
        print("  ⬜  Coverage: PARTIAL — this is not a clean result.", file=out)
        for line in wrap(reasons or "one or more files could not be fully checked", 66):
            print(f"      {line}", file=out)
        print("", file=out)

    by_cat = _by_category(result.findings)
    icon = {"pass": "✅", "warn": "⚠️ ", "fail": "🚫", "note": "🔎", "unknown": "⬜"}
    for letter, question, _gloss in CATEGORIES:
        status, note = _status(by_cat.get(letter, []))
        if status == "pass" and not result.coverage.complete:
            status, note = "unknown", "not fully checked"
        shown = question if len(question) <= 52 else question[:51] + "…"
        print(f"  {icon[status]}  {shown.ljust(52)}  {note}", file=out)
    print("", file=out)

    warnings = [finding for finding in result.findings if finding.severity == "warning"]
    notes = [finding for finding in result.findings if finding.severity == "note"]
    criticals = [finding for finding in result.findings if finding.severity == "critical"]

    if criticals or warnings:
        print(f"  {'─' * 54}", file=out)
        n = len(criticals) + len(warnings)
        print(f"\n  {n} pattern{'s' if n != 1 else ''} to look at before you ship:\n", file=out)
        for letter, question, _gloss in CATEGORIES:
            group = [finding for finding in criticals + warnings if finding.category == letter]
            if not group:
                continue
            print(f"  ⚠️  {question}", file=out)
            for _sev, text, fix in grouped_lines(group):
                for index, line in enumerate(wrap(text, 64)):
                    print(f"      {'· ' if index == 0 else '  '}{line}", file=out)
                for line in wrap(f"Do this: {fix}", 64):
                    print(f"        {line}", file=out)
            print("", file=out)

    if notes:
        print(f"  {'─' * 54}\n", file=out)
        print("  Checklists — a file read could not prove these. They are next", file=out)
        print("  steps, not a ruling that you broke a law.\n", file=out)
        lines = grouped_lines(notes)
        for _sev, text, fix in lines[:_MAX_ITEMS]:
            for index, line in enumerate(wrap(text, 64)):
                print(f"      {'· ' if index == 0 else '  '}{line}", file=out)
            for line in wrap(f"Do this: {fix}", 64):
                print(f"        {line}", file=out)
        if len(lines) > _MAX_ITEMS:
            print(f"      · {_more(len(lines) - _MAX_ITEMS)}", file=out)
        print("", file=out)

    print(f"  {'─' * 54}\n", file=out)
    if not result.coverage.complete:
        print("  Result:  ⬜  PARTIAL — some files were not fully checked.", file=out)
    elif criticals or warnings:
        print("  Result:  ⚠️  LOOK BEFORE YOU SHIP — patterns above can become", file=out)
        print("           per-visitor, per-session, per-email, or per-child liability.", file=out)
    elif notes:
        print("  Result:  🔎  No hard pattern. Checklists above still need a human.", file=out)
    else:
        print("  Result:  ✅  No launch-trap patterns in the files we could read.", file=out)
    for line in wrap(NOT_LEGAL_ADVICE, 66):
        print(f"           {line}", file=out)
    print("", file=out)


def _render_markdown(result: LaunchResult, repo: str) -> str:
    warnings = [finding for finding in result.findings if finding.severity == "warning"]
    notes = [finding for finding in result.findings if finding.severity == "note"]
    criticals = [finding for finding in result.findings if finding.severity == "critical"]
    out: list[str] = []
    if not result.coverage.complete:
        out.append("### 🔺 TriDelPhi launch audit — ⬜ partial scan")
    elif criticals or warnings:
        out.append(f"### 🔺 TriDelPhi launch audit — ⚠️ {len(criticals) + len(warnings)} to look at")
    elif notes:
        out.append("### 🔺 TriDelPhi launch audit — 🔎 checklists only")
    else:
        out.append("### 🔺 TriDelPhi launch audit — ✅ no launch-trap patterns")
    out.append(f"_{md_escape(repo)} · {md_escape(NOT_LEGAL_ADVICE)}_")
    out.append("")
    if not result.coverage.complete:
        reasons = md_escape("; ".join(result.coverage.incomplete_reasons))
        out.append(f"> ⬜ **Partial scan:** {reasons}. Do not treat this as a clean result.")
        out.append("")
    out.append("| Check | Result |")
    out.append("|---|---|")
    by_cat = _by_category(result.findings)
    for letter, question, _gloss in CATEGORIES:
        status, note = _status(by_cat.get(letter, []))
        if status == "pass" and not result.coverage.complete:
            status, note = "unknown", "not fully checked"
        cell = {
            "fail": f"🚫 **{note}**",
            "warn": f"⚠️ {note}",
            "note": f"🔎 {note}",
            "pass": "✅ nothing found",
            "unknown": f"⬜ {note}",
        }[status]
        out.append(f"| {question} | {cell} |")
    out.append("")
    actionable = criticals + warnings
    if actionable:
        out.append("**Look at these before you ship:**")
        for letter, _question, _gloss in CATEGORIES:
            for _sev, text, fix in grouped_lines(
                [finding for finding in actionable if finding.category == letter],
                markdown=True,
            ):
                out.append(f"- ⚠️ {text} **Do this:** {fix}")
        out.append("")
    if notes:
        out.append("<details>")
        out.append(f"<summary><b>{len(notes)} checklist item{'s' if len(notes) != 1 else ''}</b> — not proven from files</summary>")
        out.append("")
        for _sev, text, fix in grouped_lines(notes, markdown=True)[:_MAX_ITEMS]:
            out.append(f"- {text} **Do this:** {fix}")
        hidden = len(notes) - _MAX_ITEMS
        if hidden > 0:
            out.append(f"- {_more(hidden)}")
        out.append("")
        out.append("</details>")
        out.append("")
    out.append(f"_{md_escape(NOT_LEGAL_ADVICE)}_")
    return "\n".join(out) + "\n"


def run_launch(
    path: str = ".",
    *,
    fmt: str = "checklist",
    sarif_file: str | None = None,
    checklist_md_file: str | None = None,
    fail_on: str = "critical",
    tool_version: str = "0",
    limits: ExposureLimits | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    """Audit ``path`` for launch-time legal patterns. Exit 1 at ``--fail-on``,
    2 when the scan is incomplete or the path is unusable, else 0.

    Warnings do not fail the default ``critical`` threshold. ``--fail-on
    warning`` is the strict launch gate. A 0 is not a compliance certificate.
    """
    out = out or sys.stdout
    err = err or sys.stderr
    root = Path(path)
    if root.is_symlink() or not root.is_dir():
        print(f"tridelphi: {root} is not a directory", file=err)
        return 2
    try:
        result = analyze_launch(root, tool_version=tool_version, limits=limits)
    except ValueError as exc:
        print(f"tridelphi: {exc}", file=err)
        return 2
    repo = root.resolve().name or path

    if fmt in ("sarif", "json"):
        out.write(dumps(result.sarif or {"version": "2.1.0", "runs": []}))
    elif fmt == "markdown":
        out.write(_render_markdown(result, repo))
    else:
        _render_text(result, repo, out)

    try:
        if sarif_file and result.sarif is not None:
            atomic_write_text(sarif_file, dumps(result.sarif))
        if checklist_md_file:
            atomic_write_text(checklist_md_file, _render_markdown(result, repo))
    except OSError as exc:
        print(f"tridelphi: could not write launch output: {exc}", file=err)
        return 2

    if not result.coverage.complete:
        return 2
    return 1 if should_fail((finding.severity for finding in result.findings), fail_on) else 0
