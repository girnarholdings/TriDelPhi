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
from typing import TextIO

__all__ = [
    "TerminalSafeWriter",
    "compact_wheres",
    "grouped_lines",
    "md_escape",
    "split_where",
    "terminal_safe",
    "wrap",
]

# Escapes the characters that would change inline text's meaning as Markdown.
_MD_META = re.compile(r"([\\`*_{}\[\]<>|~])")
# Line breaks and other controls. Inline text has no use for them, and a file
# name may carry one (git allows it): a newline would let a pull request's
# file name open a heading, a quote or a fake checklist item in the comment.
_MD_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029]+")

# The only escape sequences TriDelPhi itself writes: render.py's bold, dim,
# red, yellow and cyan, and the reset. Colour cannot hide or move text.
_OWN_SGR = re.compile(r"\x1b\[(?:0|1|2|1;31|1;33|1;36)m")
# A line whose first non-blank characters are `::` (or the legacy `##[`) is a
# GitHub Actions workflow command when it reaches a runner's log \u2014 the runner
# trims leading whitespace before it looks.
_WORKFLOW_COMMAND = re.compile(r"(?m)^( *)(:(?=:)|#(?=#\[))")


def _escape_char(char: str) -> str:
    code = ord(char)
    return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"


def _visible(text: str, keep_newlines: bool) -> str:
    if text.isprintable():
        return text
    return "".join(
        char if char.isprintable() or (keep_newlines and char == "\n") else _escape_char(char)
        for char in text
    )


def terminal_safe(text: str, *, keep_newlines: bool = False, allow_color: bool = False) -> str:
    """Untrusted text headed for a terminal or a CI log: shown, never obeyed.

    Every non-printable character becomes a visible ``\\uXXXX`` escape: ESC and
    the rest of C0/C1, carriage return, bidi and other format controls, line
    separators, and the lone surrogate that stands in for an undecodable file
    name. A scanned package picks the text quoted from its own install script,
    and ``ESC[8m`` there would hide everything printed after it \u2014 the verdict
    included \u2014 while a cursor move can overwrite a finding already shown and
    OSC 52 asks some terminals to replace the clipboard.

    ``keep_newlines`` is for output that is laid out in lines; a field such as
    a path or a job id has no business starting a new one. ``allow_color``
    passes TriDelPhi's own colour codes, and only those, through unchanged.
    Either way, a line that would read as a workflow command gets its first
    character escaped, so a hostile file name cannot add a mask, forge an
    annotation, or switch command processing off in the runner's log.
    """
    if allow_color and "\x1b" in text:
        pieces: list[str] = []
        last = 0
        for match in _OWN_SGR.finditer(text):
            pieces.append(_visible(text[last : match.start()], keep_newlines))
            pieces.append(match.group(0))
            last = match.end()
        pieces.append(_visible(text[last:], keep_newlines))
        shown = "".join(pieces)
    else:
        shown = _visible(text, keep_newlines)
    if "::" not in shown and "##[" not in shown:
        return shown
    return _WORKFLOW_COMMAND.sub(lambda m: m.group(1) + _escape_char(m.group(2)), shown)


class TerminalSafeWriter:
    """A text stream that applies :func:`terminal_safe` to everything written.

    The CLI installs it over stdout and stderr, so no report, diagnostic or
    error message can pass a scanned file's bytes to the terminal raw. Each
    ``write`` is treated as able to start a line \u2014 ``print`` hands over whole
    strings, so the only extra escapes that costs are on hostile text.
    """

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    def write(self, text: str) -> int:
        return self._stream.write(terminal_safe(text, keep_newlines=True, allow_color=True))

    def writelines(self, lines) -> None:
        for line in lines:
            self.write(line)

    def __getattr__(self, name: str):
        return getattr(self._stream, name)


def md_escape(text: str) -> str:
    """Backslash-escape Markdown/HTML metacharacters in untrusted text so it
    renders as the literal characters, never as markup, in a posted comment.

    Control characters, line breaks included, become spaces first: the text is
    always inline, and a newline in a file name would start a new block.

    GitHub's ``@name`` syntax is not Markdown, but it has the externally visible
    side effect of notifying another account. Encode the at-sign as an HTML
    entity so an attacker-chosen filename or scanner message cannot mention-spam
    people from a security bot comment.
    """
    flat = _MD_CONTROL.sub(" ", text)
    return _MD_META.sub(r"\\\1", flat).replace("@", "&#64;")


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


def split_where(where: str) -> tuple[str, int | None]:
    """``"path:12"`` -> ``("path", 12)``; ``"path"`` -> ``("path", None)``.

    The path is a scanned file name — attacker-chosen in a downloaded package —
    and may itself contain colons, so the split is at the LAST colon and only
    when what follows is plain ASCII digits (``"²".isdigit()`` is true and
    ``int("²")`` raises). A line below 1 is clamped to 1, SARIF's minimum.
    """
    path, sep, tail = where.rpartition(":")
    if not sep or not path or not (tail.isascii() and tail.isdigit()):
        return where, None
    return path, max(1, int(tail))


def compact_wheres(wheres: list[str]) -> str:
    """`a.yml:25, a.yml:41, b.yml:3` -> `a.yml lines 25, 41 · b.yml line 3`."""
    by_file: dict[str, list[str]] = {}
    file_order: list[str] = []
    for where in wheres:
        file, line_no = split_where(where)
        if file not in by_file:
            by_file[file] = []
            file_order.append(file)
        if line_no is not None:
            by_file[file].append(str(line_no))
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
