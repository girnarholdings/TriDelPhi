"""Human-readable output — the default, because SARIF is unreadable at a terminal.

SARIF is the right *contract* and the wrong *default*; those are separable
decisions. With ``sort_keys=True`` the severity of a result sorts below its
locations and message, so a JSON dump literally buries the one field a reader
needs first. This renderer answers three questions the dump cannot: which finding
to fix first, why that one, and does it fit on a screen.
"""

from __future__ import annotations

import os
from typing import TextIO

from .model import AnalysisResult, Finding
from .severity import SEVERITY_ORDER

__all__ = ["SEVERITY_ORDER", "render_text"]

_RULE = "─" * 71


class _Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def critical(self, text: str) -> str:
        return self(text, "1;31")

    def warning(self, text: str) -> str:
        return self(text, "1;33")

    def note(self, text: str) -> str:
        return self(text, "1;36")

    def dim(self, text: str) -> str:
        return self(text, "2")

    def bold(self, text: str) -> str:
        return self(text, "1")


def _color_enabled(stream: TextIO, no_color: bool) -> bool:
    if no_color or os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _severity_label(style: _Style, severity: str) -> str:
    return {
        "critical": style.critical("CRITICAL"),
        "warning": style.warning("WARNING "),
        "note": style.note("NOTE    "),
    }[severity]


def _wrap(text: str, width: int = 69, indent: str = "  ") -> list[str]:
    lines: list[str] = []
    for paragraph in text.split("\n"):
        if not paragraph.strip():
            lines.append("")
            continue
        if paragraph.startswith("    "):
            lines.append(indent + paragraph)
            continue
        current = ""
        for word in paragraph.split():
            if current and len(current) + len(word) + 1 > width:
                lines.append(indent + current)
                current = word
            else:
                current = f"{current} {word}".strip()
        if current:
            lines.append(indent + current)
    return lines


def _render_finding(finding: Finding, style: _Style, index: int) -> list[str]:
    out: list[str] = []
    location = f"{finding.primary_position.file}:{finding.primary_position.line}"
    out.append(
        f"{_severity_label(style, finding.severity)} {location}   "
        f'job "{finding.context.job_id}"'
    )
    out.append(style.dim(f"  {finding.rule_id}"))
    out.append("")

    by_capability: dict[str, list] = {}
    for hit in finding.hits:
        by_capability.setdefault(hit.capability, []).append(hit)
    for capability in ("U", "P", "E"):
        for hit in by_capability.get(capability, [])[:2]:
            marker = capability if hit.observed else f"{capability}?"
            wrapped = _wrap(hit.reason, width=62, indent="     ")
            out.append(f"  {style.bold(marker)}  {wrapped[0].lstrip()}")
            out.extend(wrapped[1:])
            out.append(style.dim(f"     {hit.position.file}:{hit.position.line}"))
    out.append("")
    out.extend(_wrap(finding.message))

    if finding.remediation is not None:
        out.append("")
        out.append(style.bold("  Cheapest fix:") + f" strip {finding.remediation.strip}")
        out.extend(_wrap(finding.remediation.rendered))
        out.extend(_wrap(style.dim(f"Breaks: {finding.remediation.breaks}")))
    out.append(style.dim(f"  Explain: tridelphi --explain {finding.rule_id}"))
    return out


def render_text(
    result: AnalysisResult,
    *,
    stream: TextIO,
    tool_version: str,
    min_severity: str,
    elapsed: float,
    no_color: bool = False,
    new_count: int | None = None,
    external_summary: str | None = None,
) -> None:
    style = _Style(_color_enabled(stream, no_color))
    threshold = SEVERITY_ORDER[min_severity]
    shown = [f for f in result.findings if SEVERITY_ORDER[f.severity] <= threshold]
    hidden = len(result.findings) - len(shown)

    header = (
        f"tridelphi {tool_version} · Agents Rule of Two · "
        f"{result.files_scanned} workflow{'s' if result.files_scanned != 1 else ''}, "
        f"{result.contexts_scanned} job{'s' if result.contexts_scanned != 1 else ''}, "
        f"{elapsed:.1f}s, offline"
    )
    print(header, file=stream)

    if shown:
        print(f"\n{style.bold('START HERE')} {_RULE[:60]}", file=stream)
        for index, finding in enumerate(sorted(shown, key=lambda f: (SEVERITY_ORDER[f.severity], f.sort_key))):
            if index:
                print("", file=stream)
            for line in _render_finding(finding, style, index):
                print(line, file=stream)
            if index == 0:
                print(_RULE, file=stream)
        print("", file=stream)

    counts = {"critical": 0, "warning": 0, "note": 0}
    for finding in result.findings:
        counts[finding.severity] += 1

    summary = (
        f"  {counts['critical']} critical · {counts['warning']} warning · "
        f"{counts['note']} note"
    )
    if new_count is not None:
        summary += f" · {new_count} new since baseline"
    print(summary, file=stream)

    if external_summary:
        print(style.dim(f"  {external_summary}"), file=stream)

    if hidden:
        print(
            style.dim(
                f"  {hidden} finding{'s' if hidden != 1 else ''} below --min-severity "
                f"{min_severity} not shown"
            ),
            file=stream,
        )
    if result.suppressed:
        print(style.dim(f"  {result.suppressed} suppressed inline"), file=stream)
    if result.diagnostics:
        print(
            style.dim(f"  {len(result.diagnostics)} file(s) could not be analysed"),
            file=stream,
        )
    if not result.findings:
        # Distinguish "we looked and it was clean" from "there was nothing to
        # look at". Both used to print the same reassuring line, so a repo with
        # no CI at all — the common case for a deployed web app — got a clean
        # bill of health for a scan that never opened a file.
        if result.files_scanned == 0:
            print(
                style.dim(
                    "  nothing scanned — no .github/workflows here. This checks GitHub\n"
                    "  Actions only; it has not looked at your app. For what your app\n"
                    "  ships, run: tridelphi expose ."
                ),
                file=stream,
            )
        else:
            print(
                style.dim(
                    "  no findings — every job holds at most two of three capabilities.\n"
                    "  Scope: your GitHub Actions. For what your app ships (keys in\n"
                    "  browser bundles, source maps, open database rules), run:\n"
                    "  tridelphi expose ."
                ),
                file=stream,
            )
