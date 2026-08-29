"""The L1-L3 ladder: rung selection, graceful absence, merge, credits, gating.

Two kinds of tests here:

* Stub-based — fake `gitleaks`/`osv-scanner` executables on PATH that emit
  canned SARIF, so the runner's plumbing is testable on any machine.
* Live — marked with skipif, exercised when the real binaries are installed
  (the CI ladder job installs them).
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import textwrap

import pytest
from conftest import run_cli

from tridelphi.ladder import (
    GITLEAKS,
    LADDER,
    OSV_SCANNER,
    ZIZMOR,
    credits_text,
    run_ladder,
    run_tool,
    summarize_run,
)

MALICIOUS = "tests/fixtures/malicious/comment-and-control"


# --- helpers -----------------------------------------------------------------


def make_stub(bin_dir, name: str, sarif: dict | str, exit_code: int = 0) -> None:
    """Install a fake scanner that writes ``sarif`` wherever it is told to.

    Understands both report-flag conventions used by the real tools
    (``--report-path`` for gitleaks, ``--output`` for osv-scanner).
    """
    payload = sarif if isinstance(sarif, str) else json.dumps(sarif)
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
        sys.exit({exit_code})
        """
    )
    path = bin_dir / name
    path.write_text(script)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def stub_sarif(tool: str, results: list[dict]) -> dict:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": tool, "rules": []}}, "results": results}],
    }


@pytest.fixture
def stub_path(tmp_path, monkeypatch):
    """A bin dir prepended to PATH, plus a scannable repo dir."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ok.yml").write_text(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n"
    )
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return bin_dir, repo


# --- registry ----------------------------------------------------------------


def test_ladder_is_ordered_by_rung():
    assert [spec.level for spec in LADDER] == sorted(spec.level for spec in LADDER)


def test_every_tool_is_credited():
    text = credits_text()
    for spec in LADDER:
        assert spec.name in text
        assert spec.license in text
        assert spec.homepage in text


def test_level_selects_cumulative_rungs(stub_path):
    bin_dir, repo = stub_path
    make_stub(bin_dir, "gitleaks", stub_sarif("gitleaks", []))
    names1 = [r.spec.name for r in run_ladder(repo, level=1)]
    names3 = [r.spec.name for r in run_ladder(repo, level=3)]
    assert names1 == ["gitleaks"]
    assert names3 == ["gitleaks", "osv-scanner", "zizmor"]


# --- graceful absence and offline --------------------------------------------


def test_missing_binary_is_a_diagnostic_with_install_hint(stub_path, monkeypatch):
    _bin_dir, repo = stub_path
    if shutil.which("gitleaks"):
        monkeypatch.setenv("PATH", "/nonexistent")
    res = run_tool(GITLEAKS, repo)
    assert not res.ok
    assert "not on PATH" in res.diagnostic.message
    assert GITLEAKS.install_hint in res.diagnostic.message


def test_offline_skips_network_tools(stub_path):
    _bin_dir, repo = stub_path
    res = run_tool(OSV_SCANNER, repo, offline=True)
    assert not res.ok
    assert "--offline" in res.diagnostic.message


def test_offline_does_not_skip_offline_tools(stub_path):
    bin_dir, repo = stub_path
    make_stub(bin_dir, "gitleaks", stub_sarif("gitleaks", []))
    res = run_tool(GITLEAKS, repo, offline=True)
    assert res.ok


# --- severity accounting and overrides ---------------------------------------


def test_gitleaks_results_escalate_to_error(stub_path):
    """A committed credential is never just a warning. gitleaks omits `level`
    (SARIF-default warning); the runner must force it to error."""
    bin_dir, repo = stub_path
    finding = {"ruleId": "github-pat", "message": {"text": "secret"}, "locations": []}
    make_stub(bin_dir, "gitleaks", stub_sarif("gitleaks", [finding]), exit_code=1)
    res = run_tool(GITLEAKS, repo)
    assert res.ok
    assert res.sarif["runs"][0]["results"][0]["level"] == "error"
    assert res.severity_counts["critical"] == 1


def test_severity_counts_follow_sarif_levels(stub_path):
    bin_dir, repo = stub_path
    results = [
        {"ruleId": "a", "level": "error", "message": {"text": "x"}},
        {"ruleId": "b", "level": "warning", "message": {"text": "x"}},
        {"ruleId": "c", "message": {"text": "x"}},  # absent -> SARIF default warning
    ]
    make_stub(bin_dir, "osv-scanner", stub_sarif("osv-scanner", results), exit_code=1)
    res = run_tool(OSV_SCANNER, repo)
    assert res.severity_counts == {"critical": 1, "warning": 2, "note": 0}
    assert res.finding_count == 3


def test_in_source_suppressed_results_do_not_count_but_stay_in_sarif(stub_path):
    """A wrapped tool (semgrep's `# nosemgrep`) reports an audited finding with a
    non-empty `suppressions` array rather than dropping it. That is the author's
    reviewed acceptance: it must not gate or show as an open item, but it stays in
    the merged document so the Security tab renders it as a dismissed alert."""
    bin_dir, repo = stub_path
    results = [
        {"ruleId": "live", "level": "error", "message": {"text": "x"}},
        {"ruleId": "audited", "level": "error", "message": {"text": "x"},
         "suppressions": [{"kind": "inSource"}]},
    ]
    make_stub(bin_dir, "osv-scanner", stub_sarif("osv-scanner", results), exit_code=1)
    res = run_tool(OSV_SCANNER, repo)
    assert res.severity_counts == {"critical": 1, "warning": 0, "note": 0}
    assert res.finding_count == 1
    # the suppressed result is preserved in the document, just not counted
    kept = res.sarif["runs"][0]["results"]
    assert any(r.get("ruleId") == "audited" for r in kept)


# --- URI normalization -------------------------------------------------------


def test_absolute_file_uris_become_repo_relative(stub_path):
    bin_dir, repo = stub_path
    lock = repo / "package-lock.json"
    lock.write_text("{}")
    finding = {
        "ruleId": "CVE-0000-0000",
        "level": "warning",
        "message": {"text": "x"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": lock.resolve().as_uri(), "uriBaseId": "ROOT"}
                }
            }
        ],
    }
    make_stub(bin_dir, "osv-scanner", stub_sarif("osv-scanner", [finding]), exit_code=1)
    res = run_tool(OSV_SCANNER, repo)
    artifact = res.sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]
    assert artifact["uri"] == "package-lock.json"
    assert "uriBaseId" not in artifact


def test_uris_outside_the_repo_are_left_alone(stub_path):
    bin_dir, repo = stub_path
    finding = {
        "ruleId": "x",
        "message": {"text": "x"},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": "file:///etc/passwd"}}}
        ],
    }
    make_stub(bin_dir, "osv-scanner", stub_sarif("osv-scanner", [finding]), exit_code=1)
    res = run_tool(OSV_SCANNER, repo)
    uri = res.sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert uri == "file:///etc/passwd"


# --- CLI integration ---------------------------------------------------------


def test_credits_flag(repo_root):
    result = run_cli(["--credits"], cwd=repo_root)
    assert result.returncode == 0
    for spec in LADDER:
        assert spec.name in result.stdout


def test_level_gates_on_external_critical(stub_path, repo_root):
    """A gitleaks finding must fail the build at the default --fail-on."""
    bin_dir, repo = stub_path
    finding = {"ruleId": "github-pat", "message": {"text": "secret"}, "locations": []}
    make_stub(bin_dir, "gitleaks", stub_sarif("gitleaks", [finding]), exit_code=1)
    env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    result = run_cli([str(repo), "--level", "1", "--no-color"], cwd=repo_root, env=env)
    assert result.returncode == 1
    assert "gitleaks: 1 finding" in result.stdout


def test_level_clean_run_exits_zero(stub_path, repo_root):
    bin_dir, repo = stub_path
    make_stub(bin_dir, "gitleaks", stub_sarif("gitleaks", []))
    env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    result = run_cli([str(repo), "--level", "1", "--no-color"], cwd=repo_root, env=env)
    assert result.returncode == 0


def test_level_merges_every_tool_as_its_own_run(stub_path, repo_root):
    bin_dir, repo = stub_path
    make_stub(bin_dir, "gitleaks", stub_sarif("gitleaks", []))
    make_stub(bin_dir, "osv-scanner", stub_sarif("osv-scanner", []))
    env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    result = run_cli([str(repo), "--level", "2", "--format", "sarif"], cwd=repo_root, env=env)
    document = json.loads(result.stdout)
    names = [r["tool"]["driver"]["name"] for r in document["runs"]]
    assert names[0] == "tridelphi"
    assert "gitleaks" in names and "osv-scanner" in names


def test_missing_tools_never_break_the_scan(repo_root, monkeypatch, tmp_path):
    """--level 3 with nothing installed: diagnostics, core findings intact."""
    env = dict(os.environ, PATH="/nonexistent")
    result = run_cli(
        [MALICIOUS, "--level", "3", "--no-color"],
        cwd=repo_root,
        env=env,
    )
    # our own critical still gates
    assert result.returncode == 1
    assert "CRITICAL" in result.stdout
    assert "skipped" in result.stderr


# --- live (real binaries) ----------------------------------------------------


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks not installed")
def test_live_gitleaks_finds_a_planted_secret(tmp_path):
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    # Inert, synthetic token shaped like a GitHub PAT. Not a real credential.
    (tmp_path / "leaky.py").write_text('token = "ghp_x7Qm9Kp2Rt4Vw8Yz3Bn6Df1Hj5Lk0Sg2Xc4V"\n')
    res = run_tool(GITLEAKS, tmp_path)
    assert res.ok
    assert res.severity_counts["critical"] >= 1
    uris = {
        loc["physicalLocation"]["artifactLocation"]["uri"]
        for run in res.sarif["runs"]
        for result in run.get("results", [])
        for loc in result.get("locations", [])
    }
    assert "leaky.py" in uris


@pytest.mark.skipif(shutil.which("zizmor") is None, reason="zizmor not installed")
def test_live_zizmor_uris_are_repo_relative(repo_root):
    res = run_tool(ZIZMOR, repo_root / MALICIOUS)
    assert res.ok
    for run in res.sarif["runs"]:
        for result in run.get("results", []):
            for loc in result.get("locations", []):
                uri = loc["physicalLocation"]["artifactLocation"]["uri"]
                assert uri.startswith(".github/workflows/"), uri


def test_summary_lines():
    assert "2 findings" in summarize_run(_fake_ok())
    assert "skipped" in summarize_run(_fake_skip())


def _fake_ok():
    from tridelphi.ladder import ExternalRun

    return ExternalRun(
        GITLEAKS,
        sarif={"runs": [{"results": [{"level": "error"}, {"level": "error"}]}]},
    )


def _fake_skip():
    from tridelphi.ladder import ExternalRun
    from tridelphi.model import Diagnostic

    return ExternalRun(GITLEAKS, diagnostic=Diagnostic("gitleaks", "gone", "warning"))
