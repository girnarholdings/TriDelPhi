"""Text helpers shared by the human-facing report renderers.

The sibling audits (``scan``, ``expose``) and the checklist all print the same
shapes: word-wrapped paragraphs, ``file:line`` lists compacted for reading, and
identical messages collapsed across locations. Before this module they shared
them by reaching into each other's underscore-private names — ``scan_cmd``
imported ``expose_cmd._wrap`` and ``checklist._md_escape`` — which works until
someone reasonably renames a "private" helper. These are the public spellings.

Everything here treats its input as repo-derived and therefore untrusted:
``md_escape`` exists precisely because a file path or env var name ends up in
a PR comment that GitHub renders as HTML.
"""

from __future__ import annotations

import re

__all__ = ["compact_wheres", "grouped_lines", "md_escape", "wrap"]

# The checklist/report text is already flattened and bounded upstream; this
# escapes only the characters that would change its meaning as Markdown.
_MD_META = re.compile(r"([\\`*_{}\[\]<>|~])")


def md_escape(text: str) -> str:
    """Backslash-escape Markdown/HTML metacharacters in untrusted text so it
    renders as the literal characters, never as markup, in a posted comment."""
    return _MD_META.sub(r"\\\1", text)


def wrap(text: str, width: int) -> list[str]:
    """Greedy word-wrap with no indent logic — the renderer adds its own."""
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


def compact_wheres(wheres: list[str]) -> str:
    """`a.yml:25, a.yml:41, b.yml:3` -> `a.yml lines 25, 41 · b.yml line 3`."""
    by_file: dict[str, list[str]] = {}
    file_order: list[str] = []
    for where in wheres:
        file, _sep, line = where.partition(":")
        if file not in by_file:
            by_file[file] = []
            file_order.append(file)
        if line:
            by_file[file].append(line)
    parts = []
    for file in file_order:
        lines = by_file[file]
        if not lines:
            parts.append(file)
        elif len(lines) == 1:
            parts.append(f"{file} line {lines[0]}")
        else:
            parts.append(f"{file} lines {', '.join(lines)}")
    return " · ".join(parts)


def grouped_lines(findings, *, markdown: bool = False) -> list[tuple[str, str, str]]:
    """Collapse identical messages across locations: (severity, text, fix).

    Works for any finding with ``message`` / ``severity`` / ``fix`` / ``where``
    attributes — scan and expose findings both qualify, and both commands had
    grown a byte-identical copy of this. ``markdown`` escapes the message and
    location before they are composed, since both carry repo-derived text (a
    file path, an env var name, a masked key) and the markdown form is posted
    as a comment where GitHub renders it as HTML.
    """
    esc = md_escape if markdown else (lambda s: s)
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
            text = f"{esc(msg)} — at {esc(compact_wheres(wheres))}"
        out.append((slot["sev"], text, slot["fix"]))
    return out
