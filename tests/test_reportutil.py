"""Report text is built from file names the scan did not choose.

A downloaded package or a pull request picks its own file names, so the
helpers that turn `path:line` into SARIF and Markdown must not trust them.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tridelphi.reportutil import compact_wheres, md_escape, split_where
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
