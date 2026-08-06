"""zizmor orchestration: graceful when absent, correct SARIF merge when present."""

from __future__ import annotations

import json

import pytest
from conftest import run_cli

from tridelphi.orchestrate import merge_runs, run_zizmor, summarize_external_run, zizmor_path

MALICIOUS = "tests/fixtures/malicious/comment-and-control"


def test_missing_zizmor_is_a_diagnostic_not_a_crash(repo_root):
    """A user without zizmor still gets the findings that justify the tool."""
    result = run_cli([MALICIOUS, "--with-zizmor", "--no-color"], cwd=repo_root)
    # tridelphi's own critical is unaffected, so exit is still 1.
    assert result.returncode == 1
    if zizmor_path() is None:
        assert "zizmor is not on PATH" in result.stderr
        assert "CRITICAL" in result.stdout


def test_run_zizmor_absent_returns_diagnostic(tmp_path):
    if zizmor_path() is not None:
        pytest.skip("zizmor is installed; the absent-path branch cannot be exercised")
    res = run_zizmor(tmp_path)
    assert not res.ok
    assert res.diagnostic is not None
    assert "zizmor" in res.diagnostic.message


def test_merge_runs_appends_external_as_second_run():
    primary = {
        "$schema": "x",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "tridelphi"}}, "results": [{"ruleId": "a"}]}],
    }
    external = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "zizmor"}}, "results": [{"ruleId": "template-injection"}]}],
    }
    merged = merge_runs(primary, external)
    names = [r["tool"]["driver"]["name"] for r in merged["runs"]]
    assert names == ["tridelphi", "zizmor"]
    # primary must not be reordered or mutated
    assert primary["runs"][0]["tool"]["driver"]["name"] == "tridelphi"
    assert len(primary["runs"]) == 1


def test_merge_preserves_each_tools_results():
    primary = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "tridelphi"}}, "results": [1, 2]}]}
    external = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "zizmor"}}, "results": [3]}]}
    merged = merge_runs(primary, external)
    assert merged["runs"][0]["results"] == [1, 2]
    assert merged["runs"][1]["results"] == [3]


def test_summary_line_is_stable():
    from tridelphi.orchestrate import ZizmorResult

    assert "skipped" in summarize_external_run(ZizmorResult(diagnostic=object()))  # type: ignore[arg-type]
    assert "3 findings" in summarize_external_run(ZizmorResult(sarif={"runs": []}, finding_count=3))
    assert "1 finding " in summarize_external_run(ZizmorResult(sarif={"runs": []}, finding_count=1))


def test_zizmor_merges_into_sarif_when_present(repo_root):
    """When zizmor is installed, its run appears alongside tridelphi's."""
    if zizmor_path() is None:
        pytest.skip("zizmor not installed in this environment")
    result = run_cli([MALICIOUS, "--with-zizmor", "--format", "sarif"], cwd=repo_root)
    document = json.loads(result.stdout)
    names = [r["tool"]["driver"]["name"] for r in document["runs"]]
    assert "tridelphi" in names and "zizmor" in names
