"""`tridelphi fix` — turn findings into a prioritized, paste-ready fix plan.

The scanner already computes, for every critical, the single cheapest capability
to strip and the exact change that strips it (``Finding.remediation``). What was
missing was a view that answers the only question a developer actually has once
the scan is red: *what do I do first, and what does it cost me?*

This command is deliberately **read-only** — it never edits a file. That keeps it
honest with the rest of the tool's promise ("we only read your code"), and it
means the plan is safe to run anywhere. The plan is ordered by remediation cost
(a one-line change before a job restructure) so the shortest path back to green
is at the top, and it renders to Markdown so it can be pasted straight into a
pull request, an issue, or a ticket.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TextIO

from .api import AnalysisError, analyze
from .model import Finding
from .severity import SEVERITY_ORDER as _SEVERITY_RANK

__all__ = ["run_fix"]

# Cost of each remediation kind, lowest first. The ordering mirrors the removal
# cost that rule.py already reasons about; the label is what the user sees.
_COST: dict[str, tuple[int, str]] = {
    "env-indirect": (0, "one-line change"),
    "drop-untrusted-ref": (0, "one-line change"),
    "drop-env-file-write": (1, "small change"),
    "drop-step": (1, "small change"),
    "narrow-trigger": (1, "small change"),
    "split-job": (2, "restructure"),
    "move-secret": (2, "restructure"),
    "narrow-runner": (2, "restructure"),
}
_DEFAULT_COST = (1, "small change")


def _cost(finding: Finding) -> tuple[int, str]:
    kind = finding.remediation.kind if finding.remediation else ""
    return _COST.get(kind, _DEFAULT_COST)


def _plan_order(finding: Finding) -> tuple:
    rank, _label = _cost(finding)
    return (
        rank,
        _SEVERITY_RANK.get(finding.severity, 3),
        finding.primary_position.file,
        finding.primary_position.line,
        finding.context.job_id,
    )


def _location(finding: Finding) -> str:
    pos = finding.remediation.target_position if finding.remediation else None
    pos = pos or finding.primary_position
    return f"{pos.file}:{pos.line}"


def _md_segments(rendered: str) -> list[str]:
    """Split a rendered remediation into Markdown paragraphs and code fences.

    ``rendered`` interleaves prose with 4-space-indented YAML snippets. Emit the
    prose as paragraphs and each run of indented lines as a fenced ```yaml block
    so it survives a paste into GitHub verbatim.
    """
    out: list[str] = []
    prose: list[str] = []
    code: list[str] = []

    def flush_prose() -> None:
        if prose:
            out.append(" ".join(s.strip() for s in prose).strip())
            prose.clear()

    def flush_code() -> None:
        if code:
            out.append("```yaml\n" + "\n".join(code) + "\n```")
            code.clear()

    for line in rendered.split("\n"):
        if line.startswith("    "):
            flush_prose()
            code.append(line[4:])
        else:
            flush_code()
            if line.strip():
                prose.append(line)
            else:
                flush_prose()
    flush_prose()
    flush_code()
    return [seg for seg in out if seg]


def _render_text(findings: list[Finding], repo: str, out: TextIO) -> None:
    rule = "─" * 58
    n = len(findings)
    print(f"tridelphi fix plan · {repo}", file=out)
    if not n:
        print("\n  Nothing to fix — no jobs hold all three powers. You're good.\n", file=out)
        return
    print(
        f"\n  {n} thing{'s' if n != 1 else ''} to fix, easiest first. "
        "This is a checklist — no files are changed.\n",
        file=out,
    )
    for i, finding in enumerate(findings, 1):
        _rank, label = _cost(finding)
        rem = finding.remediation
        strip = f"strip {rem.strip}" if rem else "review"
        print(rule, file=out)
        print(f"  {i} · {label:<16}{strip}", file=out)
        print(f'    {_location(finding)}   job "{finding.context.job_id}"', file=out)
        print("", file=out)
        if rem:
            for line in rem.rendered.split("\n"):
                print(f"    {line}" if line.strip() else "", file=out)
            print(f"\n    Trade-off: {rem.breaks}", file=out)
        else:
            print(f"    {finding.message}", file=out)
        print("", file=out)
    print(rule, file=out)
    print(
        "\n  Work top-down. After each fix, run `tridelphi .` again — a fixed "
        "item drops off the list.\n",
        file=out,
    )


def _render_markdown(findings: list[Finding], repo: str, out: TextIO) -> None:
    n = len(findings)
    print(f"# TriDelPhi fix plan — {repo}", file=out)
    if not n:
        print(
            "\n✅ **Nothing to fix.** No job holds untrusted input, privilege and "
            "egress at once.\n",
            file=out,
        )
        return
    print(
        f"\n**{n} thing{'s' if n != 1 else ''} to fix, easiest first.** This is a "
        "read-only checklist — TriDelPhi never edits your files.\n",
        file=out,
    )
    for i, finding in enumerate(findings, 1):
        _rank, label = _cost(finding)
        rem = finding.remediation
        strip = f"strip&nbsp;{rem.strip}" if rem else "review"
        print(f"### {i}. {strip} · {label}", file=out)
        print(f"`{_location(finding)}` — job `{finding.context.job_id}`\n", file=out)
        if rem:
            for seg in _md_segments(rem.rendered):
                print(seg + "\n", file=out)
            print(f"> **Trade-off:** {rem.breaks}\n", file=out)
        else:
            print(finding.message + "\n", file=out)
        print("---\n", file=out)
    print(
        "_Work top-down. After each fix, re-run `tridelphi .` and the item drops "
        "off the list._",
        file=out,
    )


def run_fix(
    path: str,
    *,
    markdown: bool = False,
    include_warnings: bool = False,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    """Print an ordered remediation plan. Exit 1 while criticals remain, else 0."""
    out = out or sys.stdout
    err = err or sys.stderr
    try:
        result = analyze(path)
    except AnalysisError as exc:
        print(f"tridelphi: {exc}", file=err)
        return 2

    wanted = ("critical", "warning") if include_warnings else ("critical",)
    findings = [
        f for f in result.findings if f.severity in wanted and f.remediation is not None
    ]
    # Findings without a structured remediation still belong on the plan, but
    # only when they gate — a note never does.
    findings += [
        f
        for f in result.findings
        if f.severity in wanted and f.remediation is None
    ]
    findings.sort(key=_plan_order)

    repo = Path(path).resolve().name or path
    if markdown:
        _render_markdown(findings, repo, out)
    else:
        _render_text(findings, repo, out)

    return 1 if any(f.severity == "critical" for f in result.findings) else 0
