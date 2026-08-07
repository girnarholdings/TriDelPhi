"""Red-team ladder.py: the wrapped scanners run over hostile repositories, so
their OUTPUT is attacker-influenced too, not just the input tree.

Every attack below must land as a Diagnostic-carrying ``ExternalRun``
(``res.ok is False``) or a safely-contained SARIF document. None of them may
ever raise, hang, or corrupt the merged document — a crash here would mean a
malicious repo can take down the scanner that is supposed to be judging it,
and a corrupted merge would mean hostile content reached the output GitHub
code scanning renders.

Reuses ``make_stub``/``stub_sarif``/``stub_path`` from test_ladder.py so both
files plant fake scanners the same way; only the payloads differ.
"""

from __future__ import annotations

import json
import os
import stat
import textwrap

from conftest import run_cli
from test_ladder import make_stub, stub_path, stub_sarif  # stub_path is a fixture

from tridelphi.ladder import (
    GITLEAKS,
    MAX_OUTPUT_BYTES,
    OSV_SCANNER,
    ExternalRun,
    _contained_parse,
    run_tool,
)

MALICIOUS = "tests/fixtures/malicious/comment-and-control"


def make_raw_stub(bin_dir, name: str, script_body: str) -> None:
    """Plant a scanner whose Python body is supplied verbatim.

    Used for attacks ``make_stub`` cannot express: writing an oversized file
    without holding it as a Python string literal, writing garbage that is not
    even valid Python-escaped text, or not writing a report at all.
    """
    path = bin_dir / name
    path.write_text(script_body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _report_out_flag(args_expr: str = "args") -> str:
    return textwrap.dedent(
        f"""\
        out = None
        for flag in ("--report-path", "--output"):
            if flag in {args_expr}:
                out = {args_expr}[{args_expr}.index(flag) + 1]
        """
    )


# --- 1. non-JSON garbage -------------------------------------------------------


def test_non_json_garbage_report_is_a_diagnostic(stub_path):
    bin_dir, repo = stub_path
    make_stub(bin_dir, "gitleaks", "\x00not json at all {{{ garbage \xff\xfe", exit_code=0)
    res = run_tool(GITLEAKS, repo)
    assert not res.ok
    assert res.diagnostic is not None
    assert "not valid SARIF JSON" in res.diagnostic.message


def test_binary_garbage_report_never_raises(stub_path):
    """Bytes that are not even valid UTF-8 in the strict sense: run_tool reads
    with errors="replace", so this must degrade to a diagnostic, not a
    UnicodeDecodeError bubbling out of the runner."""
    bin_dir, repo = stub_path
    script = textwrap.dedent(
        """\
        #!/usr/bin/env python3
        import sys
        args = sys.argv[1:]
        out = None
        for flag in ("--report-path", "--output"):
            if flag in args:
                out = args[args.index(flag) + 1]
        if out:
            with open(out, "wb") as f:
                f.write(b"\\xff\\xfe\\x00\\x01not-json-and-not-utf8")
        sys.exit(0)
        """
    )
    make_raw_stub(bin_dir, "gitleaks", script)
    res = run_tool(GITLEAKS, repo)
    assert not res.ok
    assert "not valid SARIF JSON" in res.diagnostic.message


# --- 2. valid JSON, not a SARIF document ---------------------------------------


def test_json_list_is_rejected(stub_path):
    bin_dir, repo = stub_path
    make_stub(bin_dir, "gitleaks", json.dumps([1, 2, 3]))
    res = run_tool(GITLEAKS, repo)
    assert not res.ok
    assert "not a SARIF document" in res.diagnostic.message


def test_json_dict_without_runs_is_rejected(stub_path):
    bin_dir, repo = stub_path
    make_stub(bin_dir, "gitleaks", json.dumps({"version": "2.1.0", "hello": "world"}))
    res = run_tool(GITLEAKS, repo)
    assert not res.ok
    assert "not a SARIF document" in res.diagnostic.message


def test_runs_as_a_string_is_rejected(stub_path):
    bin_dir, repo = stub_path
    make_stub(bin_dir, "gitleaks", json.dumps({"version": "2.1.0", "runs": "not-a-list"}))
    res = run_tool(GITLEAKS, repo)
    assert not res.ok
    assert "not a SARIF document" in res.diagnostic.message


def test_runs_as_a_dict_is_rejected(stub_path):
    """A dict is truthy and iterable-of-keys in some careless code paths; make
    sure ``runs`` being a mapping instead of a list is caught explicitly."""
    bin_dir, repo = stub_path
    make_stub(bin_dir, "gitleaks", json.dumps({"version": "2.1.0", "runs": {"results": []}}))
    res = run_tool(GITLEAKS, repo)
    assert not res.ok
    assert "not a SARIF document" in res.diagnostic.message


def test_top_level_json_scalar_is_rejected(stub_path):
    bin_dir, repo = stub_path
    make_stub(bin_dir, "gitleaks", "42")
    res = run_tool(GITLEAKS, repo)
    assert not res.ok
    assert "not a SARIF document" in res.diagnostic.message


def test_top_level_json_null_is_rejected(stub_path):
    bin_dir, repo = stub_path
    make_stub(bin_dir, "gitleaks", "null")
    res = run_tool(GITLEAKS, repo)
    assert not res.ok
    assert "not a SARIF document" in res.diagnostic.message


# --- 3. malformed SARIF internals ----------------------------------------------


def test_run_not_a_dict_is_rejected(stub_path):
    bin_dir, repo = stub_path
    make_stub(bin_dir, "gitleaks", json.dumps({"version": "2.1.0", "runs": ["not-a-dict"]}))
    res = run_tool(GITLEAKS, repo)
    assert not res.ok
    assert "malformed run" in res.diagnostic.message


def test_results_not_a_list_is_rejected(stub_path):
    bin_dir, repo = stub_path
    doc = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "gitleaks"}}, "results": "not-a-list"}],
    }
    make_stub(bin_dir, "gitleaks", json.dumps(doc))
    res = run_tool(GITLEAKS, repo)
    assert not res.ok
    assert "malformed results" in res.diagnostic.message


def test_result_entry_is_a_string_is_rejected(stub_path):
    bin_dir, repo = stub_path
    doc = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "gitleaks"}}, "results": ["not-a-dict", {}]}],
    }
    make_stub(bin_dir, "gitleaks", json.dumps(doc))
    res = run_tool(GITLEAKS, repo)
    assert not res.ok
    assert "malformed results" in res.diagnostic.message


def test_missing_tool_driver_is_rejected(stub_path):
    bin_dir, repo = stub_path
    doc = {"version": "2.1.0", "runs": [{"results": []}]}
    make_stub(bin_dir, "gitleaks", json.dumps(doc))
    res = run_tool(GITLEAKS, repo)
    assert not res.ok
    assert "no tool.driver" in res.diagnostic.message


def test_tool_not_a_dict_is_rejected(stub_path):
    bin_dir, repo = stub_path
    doc = {"version": "2.1.0", "runs": [{"tool": "gitleaks", "results": []}]}
    make_stub(bin_dir, "gitleaks", json.dumps(doc))
    res = run_tool(GITLEAKS, repo)
    assert not res.ok
    assert "no tool.driver" in res.diagnostic.message


def test_driver_not_a_dict_is_rejected(stub_path):
    bin_dir, repo = stub_path
    doc = {"version": "2.1.0", "runs": [{"tool": {"driver": "gitleaks"}, "results": []}]}
    make_stub(bin_dir, "gitleaks", json.dumps(doc))
    res = run_tool(GITLEAKS, repo)
    assert not res.ok
    assert "no tool.driver" in res.diagnostic.message


def test_second_run_malformed_still_rejects_whole_document(stub_path):
    """A hostile tool could front-load one valid run to look clean and hide the
    poison in a later element of ``runs``; every run must be checked."""
    bin_dir, repo = stub_path
    doc = {
        "version": "2.1.0",
        "runs": [
            {"tool": {"driver": {"name": "gitleaks", "rules": []}}, "results": []},
            "not-a-dict",
        ],
    }
    make_stub(bin_dir, "gitleaks", json.dumps(doc))
    res = run_tool(GITLEAKS, repo)
    assert not res.ok
    assert "malformed run" in res.diagnostic.message


# --- 4. oversized report ---------------------------------------------------


def test_oversized_report_is_refused_without_being_parsed(stub_path):
    """Written programmatically and kept out of the repo tree by the stub
    script itself (the report path is a tempdir picked by run_tool, never a
    file under the fixture repo) -- this test never materializes the giant
    string in *this* process, only in the subprocess that writes it."""
    bin_dir, repo = stub_path
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
            target = {MAX_OUTPUT_BYTES} + 1024
            with open(out, "w") as f:
                # Valid JSON that would parse fine if it were ever read --
                # the point is that it must be refused by size *before* that.
                f.write('{{"version": "2.1.0", "runs": [], "pad": "')
                written = 0
                chunk = "A" * 65536
                while written < target:
                    f.write(chunk)
                    written += len(chunk)
                f.write('"}}')
        sys.exit(0)
        """
    )
    make_raw_stub(bin_dir, "gitleaks", script)
    res = run_tool(GITLEAKS, repo)
    assert not res.ok
    assert "refusing to parse" in res.diagnostic.message
    assert f"{MAX_OUTPUT_BYTES // (1024 * 1024)} MB" in res.diagnostic.message


def test_report_just_over_the_limit_is_refused(stub_path):
    """Exact-boundary check: MAX_OUTPUT_BYTES + 1 must trip the guard."""
    bin_dir, repo = stub_path
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
            with open(out, "wb") as f:
                f.write(b"0" * ({MAX_OUTPUT_BYTES} + 1))
        sys.exit(0)
        """
    )
    make_raw_stub(bin_dir, "osv-scanner", script)
    res = run_tool(OSV_SCANNER, repo)
    assert not res.ok
    assert "refusing to parse" in res.diagnostic.message


def test_report_exactly_at_the_limit_is_still_parsed(stub_path):
    """The guard is "over", not "at or over" -- a report of exactly
    MAX_OUTPUT_BYTES must not be refused on size alone (it will still fail
    JSON parsing here since it's padding, but the failure must be the JSON
    decode, not the size guard, proving the boundary is where the code says
    it is)."""
    bin_dir, repo = stub_path
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
            with open(out, "wb") as f:
                f.write(b"0" * {MAX_OUTPUT_BYTES})
        sys.exit(0)
        """
    )
    make_raw_stub(bin_dir, "osv-scanner", script)
    res = run_tool(OSV_SCANNER, repo)
    assert not res.ok
    # Must be the JSON-decode message, not the size-refusal message.
    assert "refusing to parse" not in res.diagnostic.message
    assert "not valid SARIF JSON" in res.diagnostic.message


# --- 5. hostile URIs -----------------------------------------------------------


def _extract_uri(res):
    return res.sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]


def _finding_with_uri(uri: str) -> dict:
    return {
        "ruleId": "x",
        "message": {"text": "x"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
    }


def test_etc_passwd_file_uri_is_left_untouched_not_relativized(stub_path):
    bin_dir, repo = stub_path
    make_stub(
        bin_dir, "osv-scanner", stub_sarif("osv-scanner", [_finding_with_uri("file:///etc/passwd")])
    )
    res = run_tool(OSV_SCANNER, repo)
    uri = _extract_uri(res)
    assert uri == "file:///etc/passwd"
    assert not uri.startswith("../")


def test_relative_dotdot_traversal_uri_is_never_produced(stub_path):
    """A tool-supplied relative URI climbing out of the root with ``../`` is
    the one out-of-root shape that is indistinguishable, to a naive resolver,
    from a legitimate in-repo path: unlike an absolute or file:// URI (which
    is unambiguous), a "../"-prefixed relative URI still *looks* repo-relative.
    It must never be emitted as-is; it is rewritten to an unambiguous absolute
    file:// URI instead, so nothing downstream can mistake it for a path
    inside the scanned root."""
    bin_dir, repo = stub_path
    make_stub(
        bin_dir,
        "osv-scanner",
        stub_sarif("osv-scanner", [_finding_with_uri("../../../etc/passwd")]),
    )
    res = run_tool(OSV_SCANNER, repo)
    uri = _extract_uri(res)
    assert not uri.startswith("../")
    assert uri != "../../../etc/passwd"
    assert uri.startswith("file://")
    assert uri.endswith("/etc/passwd")


def test_file_uri_with_host_is_contained(stub_path):
    """``file://host/share`` -- a UNC-style URI with a network host component.
    urlparse puts "host" in netloc, not path, so after unquote the path is
    "/share"; it must resolve (if at all) only within the scanned root, never
    reach out to an actual host share."""
    bin_dir, repo = stub_path
    make_stub(
        bin_dir,
        "osv-scanner",
        stub_sarif("osv-scanner", [_finding_with_uri("file://host/share")]),
    )
    res = run_tool(OSV_SCANNER, repo)
    uri = _extract_uri(res)
    assert not uri.startswith("../")
    assert "host" not in uri or uri == "file://host/share"


def test_percent_encoded_traversal_is_contained(stub_path):
    """``file:///repo/%2e%2e/secret`` -- percent-encoded ``..`` must not
    escape the scanned root after normalization. Either the URI resolves
    inside the root (if it happens to land there) or is left untouched; it
    must never come out as a path climbing above the root."""
    bin_dir, repo = stub_path
    secret_dir = repo.parent / "secret-outside-repo"
    secret_dir.mkdir()
    (secret_dir / "secret").write_text("nope")
    hostile_uri = f"file://{repo.resolve()}/%2e%2e/secret-outside-repo/secret"
    make_stub(
        bin_dir,
        "osv-scanner",
        stub_sarif("osv-scanner", [_finding_with_uri(hostile_uri)]),
    )
    res = run_tool(OSV_SCANNER, repo)
    uri = _extract_uri(res)
    assert not uri.startswith("../")
    assert not uri.startswith("/")


def test_no_normalized_uri_ever_escapes_the_root(stub_path):
    """Sweep of hostile URI shapes in one document: after normalization, no
    result URI may look repo-relative while actually climbing above the
    scanned root. Absolute paths and file:// URIs pointing outside the root
    are allowed to survive unchanged (that ambiguity does not exist for
    them -- see test_uris_outside_the_repo_are_left_alone in test_ladder.py,
    an already-established product contract); only a bare relative "../"
    escape is required to be neutralized, since it is the one shape a naive
    downstream resolver could mistake for an in-repo path."""
    bin_dir, repo = stub_path
    hostile = [
        "file:///etc/passwd",
        "../../../etc/passwd",
        "file://host/share",
        "file:///repo/%2e%2e/secret",
        "file://" + str((repo / "..").resolve()) + "/outside",
        "/etc/shadow",
        "..%2f..%2f..%2fetc%2fpasswd",
    ]
    findings = [_finding_with_uri(uri) for uri in hostile]
    make_stub(bin_dir, "osv-scanner", stub_sarif("osv-scanner", findings))
    res = run_tool(OSV_SCANNER, repo)
    assert res.ok
    for result in res.sarif["runs"][0]["results"]:
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert not uri.startswith("../"), uri


# --- 6. unexpected exit codes ---------------------------------------------


def test_unexpected_exit_code_is_a_diagnostic_not_a_crash(stub_path):
    bin_dir, repo = stub_path
    make_stub(bin_dir, "gitleaks", stub_sarif("gitleaks", []), exit_code=2)
    res = run_tool(GITLEAKS, repo)
    assert not res.ok
    assert "exited 2" in res.diagnostic.message


def test_signal_killed_exit_code_is_a_diagnostic_not_a_crash(stub_path):
    """137 = 128 + SIGKILL: the OOM-killer or a sandbox killing the scanner
    mid-run. Must degrade gracefully, same as any other unexpected code."""
    bin_dir, repo = stub_path
    make_stub(bin_dir, "osv-scanner", stub_sarif("osv-scanner", []), exit_code=137)
    res = run_tool(OSV_SCANNER, repo)
    assert not res.ok
    assert "exited 137" in res.diagnostic.message


def test_exit_code_diagnostic_caps_stderr_length(stub_path):
    """A hostile or buggy scanner could spew megabytes to stderr; the
    diagnostic message must stay bounded (the source truncates to 200 chars)
    so a giant stderr blob never becomes a giant diagnostic string."""
    bin_dir, repo = stub_path
    script = textwrap.dedent(
        """\
        #!/usr/bin/env python3
        import sys
        sys.stderr.write("X" * 1_000_000)
        sys.exit(2)
        """
    )
    make_raw_stub(bin_dir, "gitleaks", script)
    res = run_tool(GITLEAKS, repo)
    assert not res.ok
    assert len(res.diagnostic.message) < 1000


# --- 7. no report file, exit 0 -----------------------------------------------


def test_exit_zero_with_no_report_file_is_a_diagnostic(stub_path):
    bin_dir, repo = stub_path
    script = textwrap.dedent(
        """\
        #!/usr/bin/env python3
        import sys
        sys.exit(0)
        """
    )
    make_raw_stub(bin_dir, "gitleaks", script)
    res = run_tool(GITLEAKS, repo)
    assert not res.ok
    assert "wrote no report" in res.diagnostic.message


# --- 8. non-SARIF severity levels --------------------------------------------


def test_bogus_string_level_does_not_raise_and_counts_sanely():
    """``_contained_parse`` accepts any dict-shaped result -- ``level`` content
    validation happens in ``ExternalRun.__init__``'s severity accounting, not
    the structural parse. A level of "critical" (not a real SARIF level) must
    not raise and must land in some bucket, not silently vanish."""
    doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "x", "rules": []}},
                "results": [{"ruleId": "a", "level": "critical", "message": {"text": "x"}}],
            }
        ],
    }
    run = ExternalRun(GITLEAKS, sarif=doc)
    assert run.finding_count == 1
    assert sum(run.severity_counts.values()) == 1


def test_numeric_level_does_not_raise():
    doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "x", "rules": []}},
                "results": [{"ruleId": "a", "level": 42, "message": {"text": "x"}}],
            }
        ],
    }
    run = ExternalRun(GITLEAKS, sarif=doc)
    assert run.finding_count == 1


def test_none_level_falls_back_to_sarif_default_warning():
    doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "x", "rules": []}},
                "results": [{"ruleId": "a", "level": None, "message": {"text": "x"}}],
            }
        ],
    }
    run = ExternalRun(GITLEAKS, sarif=doc)
    assert run.finding_count == 1
    assert run.severity_counts["warning"] == 1


def test_unrecognized_level_via_stub_end_to_end(stub_path):
    """Same shape, exercised through the real subprocess + parse path rather
    than constructing ExternalRun directly."""
    bin_dir, repo = stub_path
    results = [
        {"ruleId": "a", "level": "critical", "message": {"text": "x"}},
        {"ruleId": "b", "level": "informational", "message": {"text": "x"}},
    ]
    make_stub(bin_dir, "osv-scanner", stub_sarif("osv-scanner", results), exit_code=1)
    res = run_tool(OSV_SCANNER, repo)
    assert res.ok
    assert res.finding_count == 2
    # Neither bogus level matches a real SARIF level, so both fall into the
    # dict.get(level, "warning") default bucket.
    assert res.severity_counts["warning"] == 2


# --- 9. CLI end-to-end with a hostile stub on PATH ---------------------------


def test_cli_sarif_output_is_valid_json_with_hostile_stub_on_path(stub_path, repo_root):
    """The stub emits garbage; --format sarif must still print parseable JSON
    to stdout with TriDelPhi's own run intact as runs[0], and any diagnostic
    text must land on stderr, never interleaved into stdout."""
    bin_dir, repo = stub_path
    make_stub(bin_dir, "gitleaks", "{{{ not json at all")
    env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    result = run_cli(
        [str(repo), "--level", "1", "--format", "sarif"], cwd=repo_root, env=env
    )
    document = json.loads(result.stdout)  # raises if stdout is not clean JSON
    assert document["runs"][0]["tool"]["driver"]["name"] == "tridelphi"
    assert "not valid SARIF JSON" in result.stderr


def test_cli_sarif_output_survives_malformed_sarif_internals(stub_path, repo_root):
    bin_dir, repo = stub_path
    doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "gitleaks"}}, "results": "x"}]}
    make_stub(bin_dir, "gitleaks", json.dumps(doc))
    env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    result = run_cli(
        [str(repo), "--level", "1", "--format", "sarif"], cwd=repo_root, env=env
    )
    document = json.loads(result.stdout)
    assert document["runs"][0]["tool"]["driver"]["name"] == "tridelphi"
    assert len(document["runs"]) == 1  # the malformed gitleaks run never merges in


def test_cli_sarif_output_survives_hostile_uris_end_to_end(stub_path, repo_root):
    bin_dir, repo = stub_path
    make_stub(
        bin_dir,
        "osv-scanner",
        stub_sarif("osv-scanner", [_finding_with_uri("../../../etc/passwd")]),
        exit_code=1,
    )
    env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    result = run_cli(
        [str(repo), "--level", "2", "--format", "sarif"], cwd=repo_root, env=env
    )
    document = json.loads(result.stdout)
    names = [r["tool"]["driver"]["name"] for r in document["runs"]]
    assert names[0] == "tridelphi"
    assert "osv-scanner" in names
    for run in document["runs"]:
        for result_entry in run.get("results", []):
            for loc in result_entry.get("locations", []):
                uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                assert not uri.startswith("../"), uri


def test_cli_exit_code_137_stub_does_not_break_the_scan(stub_path, repo_root):
    bin_dir, repo = stub_path
    make_stub(bin_dir, "gitleaks", stub_sarif("gitleaks", []), exit_code=137)
    env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    result = run_cli([str(repo), "--level", "1", "--no-color"], cwd=repo_root, env=env)
    assert result.returncode == 0
    assert "exited 137" in result.stderr


# --- direct _contained_parse coverage (fast, no subprocess) ------------------


def test_contained_parse_never_raises_on_arbitrary_json_shapes():
    """Broad sweep directly against the parser: nothing here should raise,
    every case must come back as an ExternalRun with a diagnostic."""
    hostile_payloads = [
        "not json",
        "[]",
        "[1, 2, 3]",
        '{"runs": null}',
        '{"runs": {}}',
        '{"runs": [null]}',
        '{"runs": [[]]}',
        '{"runs": [{"results": null}]}',
        '{"runs": [{"results": [null]}]}',
        '{"runs": [{"results": [1, 2]}]}',
        '{"runs": [{"tool": null, "results": []}]}',
        '{"runs": [{"tool": {}, "results": []}]}',
        '{"runs": [{"tool": {"driver": []}, "results": []}]}',
        "",
        "   ",
        "﻿{}",  # BOM-prefixed empty object
    ]
    for payload in hostile_payloads:
        outcome = _contained_parse(GITLEAKS, payload)
        assert isinstance(outcome, ExternalRun), payload
        assert not outcome.ok, payload
        assert outcome.diagnostic is not None, payload
