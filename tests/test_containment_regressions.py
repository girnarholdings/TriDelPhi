"""Regressions from the pre-merge code review of the ladder bundle.

Each test here reproduces a crash or containment bypass that survived the
first adversarial pass and was caught by review. They are kept separate from
test_ladder_adversarial.py so the review's findings stay individually
traceable.
"""

from __future__ import annotations

import json
import os
import stat
import textwrap

from tridelphi.ladder import (
    GITLEAKS,
    ZIZMOR,
    ExternalRun,
    _git_prefix,
    _normalize_uris,
    _relativize,
    run_tool,
)
from tridelphi.orchestrate import sarif_shape_error


def _repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ok.yml").write_text(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n"
    )
    return repo


def _stub(bin_dir, name: str, payload: str, exit_code: int = 0) -> None:
    script = textwrap.dedent(
        f"""\
        #!/usr/bin/env python3
        import sys
        args = sys.argv[1:]
        out = None
        for flag in ("--report-path", "--output"):
            if flag in args:
                out = args[args.index(flag) + 1]
        if out:
            with open(out, "w") as f:
                f.write({payload!r})
        else:
            sys.stdout.write({payload!r})
        sys.exit({exit_code})
        """
    )
    path = bin_dir / name
    path.write_text(script)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def test_unhashable_level_is_counted_not_crashed():
    """A result with `level: ["error"]` used to raise TypeError inside
    severity accounting (dict lookup on an unhashable key)."""
    doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "x"}},
                "results": [
                    {"level": ["error"]},
                    {"level": 42},
                    {"level": None},
                    {"level": "error"},
                ],
            }
        ],
    }
    run = ExternalRun(GITLEAKS, sarif=doc)
    # Non-string levels fall back to the SARIF default, warning.
    assert run.severity_counts == {"critical": 1, "warning": 3, "note": 0}


def test_malformed_locations_are_rejected_by_the_shape_gate():
    """`locations: "xy"` passed the old shape gate and then crashed
    _normalize_uris with AttributeError while iterating the string."""
    for hostile in ("xy", {"a": 1}, ["not-a-dict"], 7):
        doc = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "x"}}, "results": [{"locations": hostile}]}],
        }
        assert sarif_shape_error(doc) is not None, repr(hostile)


def test_normalize_uris_survives_shapes_the_gate_never_saw(tmp_path):
    """Post-processing must be safe even for documents that did not pass
    through the gate (internally constructed runs, future call sites)."""
    doc = {
        "runs": [
            "not-a-dict",
            {"results": "xy"},
            {"results": [{"locations": "xy"}, {"locations": [{"physicalLocation": "s"}]}]},
        ]
    }
    _normalize_uris(doc, tmp_path)  # must simply not raise


def test_git_prefix_strip_cannot_reintroduce_traversal(tmp_path):
    """uri = git_prefix + "../../.." used to be returned verbatim after the
    prefix strip, bypassing the escape rewrite the else-branch applies."""
    root = tmp_path / "mono" / "sub" / "dir"
    root.mkdir(parents=True)
    out = _relativize("sub/dir/../../../../etc/passwd", root.resolve(), "sub/dir/")
    assert out is not None
    assert not out.startswith("../")
    assert out.startswith("file://")


def test_git_root_itself_gets_no_prefix(tmp_path):
    """A repo whose parent directory also contains a .git (dotfiles-in-HOME)
    used to be assigned a bogus prefix from the outer repository."""
    outer = tmp_path / "home"
    inner = outer / "projects" / "myrepo"
    (outer / ".git").mkdir(parents=True)
    (inner / ".git").mkdir(parents=True)
    assert _git_prefix(inner.resolve()) is None
    # A plain subdirectory (no .git of its own) still gets the enclosing prefix.
    plain = outer / "projects" / "plain"
    plain.mkdir()
    assert _git_prefix(plain.resolve()) == "projects/plain/"


def test_zizmor_rung_contains_json_valid_non_sarif(tmp_path, monkeypatch):
    """The L3 rung used to bypass the shape gate entirely: JSON-valid,
    non-SARIF zizmor stdout crashed run_zizmor or _normalize_uris."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    repo = _repo(tmp_path)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    for hostile in ("[1, 2, 3]", '{"runs": ["x"]}', '{"runs": [{"results": "xy"}]}'):
        _stub(bin_dir, "zizmor", hostile)
        res = run_tool(ZIZMOR, repo)
        assert not res.ok, hostile
        assert res.diagnostic is not None


def test_zizmor_rung_still_accepts_real_shaped_output(tmp_path, monkeypatch):
    """The new gate must not reject well-formed zizmor output."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    repo = _repo(tmp_path)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    good = json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "zizmor", "rules": []}},
                    "results": [
                        {
                            "ruleId": "unpinned-uses",
                            "level": "error",
                            "message": {"text": "x"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "ok.yml"}
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )
    _stub(bin_dir, "zizmor", good)
    res = run_tool(ZIZMOR, repo)
    assert res.ok
    assert res.severity_counts["critical"] == 1
    uri = res.sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert uri == ".github/workflows/ok.yml"
