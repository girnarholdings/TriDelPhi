"""`tridelphi expose` — render the exposure audit as a plain-language report.

Same discipline as the security checklist: verdict first, plain English, the
exact fix, and an honest scope line that never lets the reader mistake a static
audit for a live penetration test. Criticals stay in the open; advisory items
are grouped so the report is a report, not a data dump.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TextIO

from .checklist import _compact_wheres, _md_escape
from .expose import CATEGORIES, ExposeFinding, ExposureResult, analyze_exposure
from .render import SEVERITY_ORDER
from .sarif import dumps

__all__ = ["run_expose"]

_SCOPE = (
    "Read your committed code and config only — TriDelPhi can't reach a running "
    "database or server. A clean result isn't a penetration test, and a flagged "
    "config may already be firewalled; verify anything network-facing against "
    "your live deployment."
)
_MAX_ITEMS = 5


def _status(findings: list[ExposeFinding]) -> tuple[str, str]:
    crit = sum(1 for f in findings if f.severity == "critical")
    warn = sum(1 for f in findings if f.severity == "warning")
    if crit:
        return "fail", f"{crit} to fix"
    if warn:
        return "warn", f"{warn} worth a look"
    if findings:  # notes only
        return "note", "informational"
    return "pass", "all clear"


def _grouped_lines(
    findings: list[ExposeFinding], *, markdown: bool = False
) -> list[tuple[str, str, str]]:
    """Collapse identical messages across locations. Returns (severity, text, fix).

    ``markdown`` escapes the message and location before they are composed, since
    both carry repo-derived text (a file path, an env var name, a masked key) and
    the markdown form is posted as a comment where GitHub renders it as HTML."""
    esc = _md_escape if markdown else (lambda s: s)
    order: list[str] = []
    by_msg: dict[str, dict] = {}
    for f in findings:
        slot = by_msg.get(f.message)
        if slot is None:
            slot = {"sev": f.severity, "fix": f.fix, "wheres": []}
            by_msg[f.message] = slot
            order.append(f.message)
        if f.where and f.where not in slot["wheres"]:
            slot["wheres"].append(f.where)
    out: list[tuple[str, str, str]] = []
    for msg in order:
        slot = by_msg[msg]
        wheres = slot["wheres"]
        if not wheres:
            text = esc(msg)
        elif len(wheres) == 1:
            text = f"{esc(wheres[0])} — {esc(msg)}"
        else:
            text = f"{esc(msg)} — at {esc(_compact_wheres(wheres))}"
        out.append((slot["sev"], text, slot["fix"]))
    return out


def _render_text(result: ExposureResult, repo: str, out: TextIO) -> None:
    bar = "─" * 60
    print(bar, file=out)
    print(f"  🔺 TriDelPhi exposure audit · {repo}", file=out)
    for line in _wrap(_SCOPE, 66):
        print(f"  {line}", file=out)
    print(bar, file=out)
    print("", file=out)

    by_cat: dict[str, list[ExposeFinding]] = {c[0]: [] for c in CATEGORIES}
    for f in result.findings:
        by_cat.setdefault(f.category, []).append(f)

    icon = {"pass": "✅", "warn": "⚠️ ", "fail": "🚫", "note": "🔎", "skip": "⬜"}
    for letter, question, _gloss in CATEGORIES:
        st, note = _status(by_cat.get(letter, []))
        q = question if len(question) <= 52 else question[:51] + "…"
        print(f"  {icon[st]}  {q.ljust(52)}  {note}", file=out)
    if not result.semgrep_ran:
        why = "install semgrep to add it" if result.semgrep_note else "not run"
        print(f"  ⬜  (code-pattern checks — {why})", file=out)
    print("", file=out)

    # Criticals in the open.
    crits = [f for f in result.findings if f.severity == "critical"]
    if crits:
        print(f"  {'─' * 54}", file=out)
        n = len(crits)
        print(f"\n  {n} thing{'s' if n != 1 else ''} to fix before this is safe:\n", file=out)
        for letter, question, _gloss in CATEGORIES:
            group = [f for f in crits if f.category == letter]
            if not group:
                continue
            print(f"  🚫 {question}", file=out)
            for _sev, text, fix in _grouped_lines(group):
                for i, wl in enumerate(_wrap(text, 64)):
                    print(f"      {'· ' if i == 0 else '  '}{wl}", file=out)
                for fl in _wrap(f"Do this: {fix}", 64):
                    print(f"        {fl}", file=out)
            print("", file=out)

    # Advisory items, grouped, with the legend once.
    warns = [f for f in result.findings if f.severity == "warning"]
    notes = [f for f in result.findings if f.severity == "note"]
    if warns:
        print(f"  {'─' * 54}\n", file=out)
        print('  What "worth a look" means: not an open door — a good-practice gap.', file=out)
        print("  A stranger can't use these to get in today; tidy them when you can.\n", file=out)
        for letter, question, gloss in CATEGORIES:
            group = [f for f in warns if f.category == letter]
            if not group:
                continue
            print(f"  ⚠️  {question}", file=out)
            print(f"      {gloss}", file=out)
            for _sev, text, fix in _grouped_lines(group)[:_MAX_ITEMS]:
                for i, wl in enumerate(_wrap(text, 64)):
                    print(f"      {'· ' if i == 0 else '  '}{wl}", file=out)
                for fl in _wrap(f"Do this: {fix}", 64):
                    print(f"        {fl}", file=out)
            print("", file=out)

    for f in notes:
        for i, wl in enumerate(_wrap(f.message, 66)):
            print(f"  {'🔎 ' if i == 0 else '   '}{wl}", file=out)
    if notes:
        print("", file=out)

    print(f"  {'─' * 54}\n", file=out)
    if crits:
        n = len(crits)
        print(f"  Result:  ⚠️  NOT YET SAFE — fix the {n} item{'s' if n != 1 else ''} above.", file=out)
    elif warns:
        print("  Result:  ✅  Nothing urgent leaking — a few items worth tidying above.", file=out)
    else:
        print("  Result:  ✅  Nothing in your committed code or config looks exposed.", file=out)
    print("           Static audit — verify network-facing config against your deployment.\n", file=out)


def _render_markdown(result: ExposureResult, repo: str) -> str:
    crits = [f for f in result.findings if f.severity == "critical"]
    warns = [f for f in result.findings if f.severity == "warning"]
    out: list[str] = []
    if crits:
        out.append(f"### 🔺 TriDelPhi exposure audit — 🚫 {len(crits)} to fix")
    elif warns:
        out.append("### 🔺 TriDelPhi exposure audit — ✅ nothing urgent, a few to tidy")
    else:
        out.append("### 🔺 TriDelPhi exposure audit — ✅ nothing looks exposed")
    out.append(f"_{repo} · {_SCOPE}_")
    out.append("")
    out.append("| Check | Result |")
    out.append("|---|---|")
    by_cat: dict[str, list[ExposeFinding]] = {}
    for f in result.findings:
        by_cat.setdefault(f.category, []).append(f)
    for letter, question, _gloss in CATEGORIES:
        st, note = _status(by_cat.get(letter, []))
        cell = {"fail": f"🚫 **{note}**", "warn": f"⚠️ {note}",
                "note": f"🔎 {note}", "pass": "✅ all clear"}[st]
        out.append(f"| {question} | {cell} |")
    out.append("")
    if crits:
        out.append("**Fix these first:**")
        for letter, _question, _g in CATEGORIES:
            for _sev, text, fix in _grouped_lines(
                [f for f in crits if f.category == letter], markdown=True
            ):
                out.append(f"- 🚫 {text} **Do this:** {fix}")
        out.append("")
    if warns:
        total = len(warns)
        out.append("<details>")
        out.append(f"<summary><b>{total} worth a look</b> — nothing urgent, tap to read</summary>")
        out.append("")
        for letter, question, gloss in CATEGORIES:
            group = [f for f in warns if f.category == letter]
            if not group:
                continue
            out.append(f"**{question}**  ")
            out.append(f"_{gloss}_")
            for _sev, text, fix in _grouped_lines(group, markdown=True)[:_MAX_ITEMS]:
                out.append(f"- {text} **Do this:** {fix}")
            out.append("")
        out.append("</details>")
        out.append("")
    out.append("_Static audit of committed code + config — verify network-facing config "
               "against your live deployment._")
    return "\n".join(out) + "\n"


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    cur = ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}" if cur else w
    if cur:
        lines.append(cur)
    return lines or [""]


def run_expose(
    path: str = ".",
    *,
    fmt: str = "checklist",
    sarif_file: str | None = None,
    checklist_md_file: str | None = None,
    fail_on: str = "critical",
    tool_version: str = "0",
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    """Audit ``path`` for exposure and render it. Exit 1 if a critical exists
    (unless ``fail_on`` is 'none'), else 0."""
    out = out or sys.stdout
    err = err or sys.stderr
    root = Path(path)
    if not root.is_dir():
        print(f"tridelphi: {root} is not a directory", file=err)
        return 2

    result = analyze_exposure(root, tool_version=tool_version)
    repo = root.resolve().name or path

    if fmt in ("sarif", "json"):
        out.write(dumps(result.sarif or {"version": "2.1.0", "runs": []}))
    elif fmt == "markdown":
        out.write(_render_markdown(result, repo))
    else:
        _render_text(result, repo, out)

    if sarif_file and result.sarif is not None:
        Path(sarif_file).write_text(dumps(result.sarif), encoding="utf-8", newline="\n")
    if checklist_md_file:
        Path(checklist_md_file).write_text(_render_markdown(result, repo),
                                           encoding="utf-8", newline="\n")

    if fail_on == "none":
        return 0
    threshold = SEVERITY_ORDER.get(fail_on, 0)
    if any(SEVERITY_ORDER[f.severity] <= threshold for f in result.findings):
        return 1
    return 0
