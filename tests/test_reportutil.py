"""Report text is built from file names the scan did not choose.

A downloaded package or a pull request picks its own file names, so the
helpers that turn `path:line` into SARIF and Markdown must not trust them.
"""

from __future__ import annotations

import io
from types import SimpleNamespace

import pytest

from tridelphi.reportutil import (
    TerminalSafeWriter,
    compact_wheres,
    md_escape,
    split_where,
    terminal_safe,
)
from tridelphi.sarif import simple_sarif


@pytest.mark.parametrize(
    "where,expected",
    [
        ("a.js:12", ("a.js", 12)),
        ("dir/a:b.js:12", ("dir/a:b.js", 12)),  # a colon inside the name
        ("dir/a:b.js", ("dir/a:b.js", None)),
        ("README.md", ("README.md", None)),
        ("a.js:0", ("a.js", 1)),  # SARIF lines start at 1
        ("a.js:²", ("a.js:²", None)),  # isdigit() is true, int() would raise
        (":7", (":7", None)),
    ],
)
def test_split_where(where, expected):
    assert split_where(where) == expected


def test_compact_wheres_keeps_colon_names_whole():
    assert compact_wheres(["a:b.js:3", "a:b.js:9", "c.py"]) == "a:b.js lines 3, 9 · c.py"


def test_markdown_escape_flattens_line_breaks():
    """A newline in a file name would open a new Markdown block in the posted
    comment — a fake heading, quote or checked box."""
    escaped = md_escape("dist/a\n# Fake heading\r\n- [x] all clear @someone")
    assert "\n" not in escaped and "\r" not in escaped
    assert "\\[x\\]" in escaped and "&#64;someone" in escaped


def test_simple_sarif_locations_are_valid():
    findings = [
        SimpleNamespace(rule="r", severity="warning", where="pkg/a:b.js:12", message="m"),
        SimpleNamespace(rule="r", severity="critical", where="pkg/z.js:0", message="n"),
    ]
    doc = simple_sarif(findings, tool="t", audit_label="audit", tool_version="0", help_uri="https://x")
    locations = [r["locations"][0]["physicalLocation"] for r in doc["runs"][0]["results"]]
    assert locations[0]["artifactLocation"]["uri"] == "pkg/a:b.js"
    assert locations[0]["region"]["startLine"] == 12
    assert locations[1]["region"]["startLine"] == 1


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("plain text · ✅ 🔺 — “quoted”", "plain text · ✅ 🔺 — “quoted”"),
        ("x \x1b[8m hidden", "x \\u001b[8m hidden"),  # conceal the rest
        ("\x1b]52;c;cm0gLXJmIH4=\x07", "\\u001b]52;c;cm0gLXJmIH4=\\u0007"),  # clipboard
        ("ok\rCRITICAL erased", "ok\\u000dCRITICAL erased"),
        ("csi \x9b2J", "csi \\u009b2J"),
        ("rtl \u202egpj.exe", "rtl \\u202egpj.exe"),
        ("bad\udcff.yml", "bad\\udcff.yml"),  # an undecodable file name
        ("a\nb", "a\\u000ab"),  # one field never starts a line
        ("std::vector and ::1", "std::vector and ::1"),  # mid-line is harmless
        ("::add-mask::critical", "\\u003a:add-mask::critical"),
        ("##[error]forged", "\\u0023#[error]forged"),
    ],
)
def test_terminal_safe_shows_controls_instead_of_obeying_them(raw, expected):
    assert terminal_safe(raw) == expected


def test_terminal_safe_line_mode_keeps_layout_but_not_commands():
    text = "report\n  ::error::forged\n::stop-commands::x\nkeep: this::that\n"
    assert terminal_safe(text, keep_newlines=True) == (
        "report\n  \\u003a:error::forged\n\\u003a:stop-commands::x\nkeep: this::that\n"
    )


def test_terminal_safe_passes_only_our_own_colours():
    ours = "\x1b[1;31mCRITICAL\x1b[0m \x1b[2mdim\x1b[0m"
    assert terminal_safe(ours, allow_color=True) == ours
    hostile = "\x1b[8mgone\x1b[0m \x1b[2A"
    assert terminal_safe(hostile, allow_color=True) == "\\u001b[8mgone\x1b[0m \\u001b[2A"


def test_terminal_safe_writer_escapes_what_print_sends():
    class Tty(io.StringIO):
        def isatty(self):
            return True

    stream = Tty()
    writer = TerminalSafeWriter(stream)
    print("\x1b[1;31mCRITICAL\x1b[0m", "pkg/\x1b[8m.js", file=writer)
    assert stream.getvalue() == "\x1b[1;31mCRITICAL\x1b[0m pkg/\\u001b[8m.js\n"
    assert writer.isatty(), "colour detection must still see the terminal"
