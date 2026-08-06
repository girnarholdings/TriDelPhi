"""Exit codes, output routing, and the flags people actually type."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import run_cli

MALICIOUS = "tests/fixtures/malicious/comment-and-control"
CLEAN = "tests/fixtures/clean/vanilla-ci"
TWO_CAP = "tests/fixtures/two_cap/up-no-egress"


def test_critical_exits_1(repo_root):
    assert run_cli([MALICIOUS], cwd=repo_root).returncode == 1


def test_clean_exits_0(repo_root):
    assert run_cli([CLEAN], cwd=repo_root).returncode == 0


def test_warnings_do_not_fail_by_default(repo_root):
    """The obvious implementation is `if findings: return 1`, which ignores
    --fail-on and turns every repo red on day one."""
    result = run_cli([TWO_CAP], cwd=repo_root)
    assert result.returncode == 0, result.stdout


def test_fail_on_warning_catches_them(repo_root):
    assert run_cli([TWO_CAP, "--fail-on", "warning"], cwd=repo_root).returncode == 1


def test_fail_on_none_never_fails(repo_root):
    assert run_cli([MALICIOUS, "--fail-on", "none"], cwd=repo_root).returncode == 0


def test_missing_path_exits_2(repo_root):
    result = run_cli(["tests/fixtures/does-not-exist"], cwd=repo_root)
    assert result.returncode == 2
    assert "does not exist" in result.stderr


def test_no_workflows_exits_0(repo_root, tmp_path):
    """Fresh repos and monorepo subdirectories are legitimate; only a bad path
    is an error."""
    result = run_cli([str(tmp_path)], cwd=repo_root)
    assert result.returncode == 0
    assert "nothing to scan" in result.stderr


def test_require_workflows_makes_it_an_assertion(repo_root, tmp_path):
    assert run_cli([str(tmp_path), "--require-workflows"], cwd=repo_root).returncode == 2


def test_sarif_goes_to_stdout_clean(repo_root):
    """Diagnostics must not corrupt `--format sarif > out.sarif`."""
    result = run_cli([MALICIOUS, "--format", "sarif"], cwd=repo_root)
    document = json.loads(result.stdout)
    assert document["version"] == "2.1.0"


def test_text_and_sarif_file_combine(repo_root, tmp_path):
    """CI needs both: text in the job log, SARIF for upload. Forcing either/or
    makes the log useless, which is where findings are actually read."""
    out = tmp_path / "out.sarif"
    result = run_cli(
        [MALICIOUS, "--format", "text", "--sarif-file", str(out)], cwd=repo_root
    )
    assert result.returncode == 1
    assert "CRITICAL" in result.stdout
    assert json.loads(out.read_text())["version"] == "2.1.0"


def test_malformed_yaml_is_a_finding_not_a_crash(repo_root, tmp_path):
    """Exit 2 on the whole run kills the scan; silent skip is a bypass, because
    anyone able to choke the parser would become invisible."""
    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "broken.yml").write_text("on: push\njobs:\n  a:\n   - [unclosed\n")
    (workflows / "fine.yml").write_text(
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"
    )
    result = run_cli(
        [str(tmp_path), "--fail-on", "warning", "--min-severity", "warning"], cwd=repo_root
    )
    assert result.returncode == 1
    assert "parse-error" in result.stdout


def test_strict_parse_escalates_to_2(repo_root, tmp_path):
    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "broken.yml").write_text("jobs:\n  a:\n   - [unclosed\n")
    assert run_cli([str(tmp_path), "--strict-parse"], cwd=repo_root).returncode == 2


def test_explain_renders_rule_help(repo_root):
    result = run_cli(["--explain", "agent-config-ingress"], cwd=repo_root)
    assert result.returncode == 0
    assert "restores" in result.stdout


def test_explain_unknown_rule_exits_2(repo_root):
    assert run_cli(["--explain", "nope"], cwd=repo_root).returncode == 2


def test_core_subcommand_and_bare_path_agree(repo_root):
    bare = run_cli([CLEAN, "--quiet"], cwd=repo_root)
    core = run_cli(["core", CLEAN, "--quiet"], cwd=repo_root)
    assert bare.returncode == core.returncode == 0
    assert bare.stdout == core.stdout


def test_version_and_help(repo_root):
    assert run_cli(["--version"], cwd=repo_root).returncode == 0
    assert run_cli(["--help"], cwd=repo_root).returncode == 0


def test_self_check_validates_schema(repo_root):
    result = run_cli([MALICIOUS, "--format", "sarif", "--self-check"], cwd=repo_root)
    assert result.returncode == 1
    assert json.loads(result.stdout)
