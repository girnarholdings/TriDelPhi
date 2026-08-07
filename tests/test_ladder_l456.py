"""L4-L6: scorecard adapter, semgrep rung, and the attest/gate processes.

Stub-based tests run everywhere; live tests (real scorecard/semgrep) skip when
the binary is absent, matching the pattern in test_ladder.py.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import textwrap

import pytest
from conftest import run_cli

from tridelphi.gate_cmd import EVIDENCE_PREDICATE_TYPE, run_attest, run_gate
from tridelphi.ladder import (
    LADDER,
    MAX_LEVEL,
    SCORECARD,
    SEMGREP,
    _scorecard_to_sarif,
    run_ladder,
    run_tool,
)


def _repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ok.yml").write_text(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n"
    )
    return repo


def _stub(bin_dir, name, *, stdout="", report=None, exit_code=0):
    body = f"sys.stdout.write({stdout!r})\n"
    if report is not None:
        body += textwrap.dedent(
            f"""\
            for flag in ("--report-path", "--output"):
                if flag in sys.argv:
                    open(sys.argv[sys.argv.index(flag) + 1], "w").write({report!r})
            """
        )
    script = "#!/usr/bin/env python3\nimport sys\n" + body + f"sys.exit({exit_code})\n"
    path = bin_dir / name
    path.write_text(script)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


# --- registry ---------------------------------------------------------------


def test_ladder_now_has_five_rungs():
    assert [s.level for s in LADDER] == [1, 2, 3, 4, 5]
    assert MAX_LEVEL == 6
    assert SCORECARD.level == 4 and SEMGREP.level == 5


def test_level_6_runs_every_wrapped_rung(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    repo = _repo(tmp_path)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    for name in ("gitleaks", "osv-scanner", "scorecard", "semgrep"):
        _stub(bin_dir, name, report='{"version":"2.1.0","runs":[]}', stdout='{"checks":[]}')
    names = [r.spec.name for r in run_ladder(repo, level=6)]
    assert names == ["gitleaks", "osv-scanner", "zizmor", "scorecard", "semgrep"]


# --- scorecard adapter ------------------------------------------------------


def test_scorecard_json_becomes_sarif_by_score():
    raw = json.dumps(
        {
            "scorecard": {"version": "v5.5.0"},
            "checks": [
                {"name": "Security-Policy", "score": 0, "reason": "none found"},
                {"name": "Pinned-Dependencies", "score": 6, "reason": "partial"},
                {"name": "Token-Permissions", "score": 10, "reason": "least privilege"},
                {"name": "Packaging", "score": -1, "reason": "n/a"},
            ],
        }
    )
    result = _scorecard_to_sarif(SCORECARD, raw)
    run = result["runs"][0]
    assert run["tool"]["driver"]["semanticVersion"] == "5.5.0"
    by_rule = {r["ruleId"]: r["level"] for r in run["results"]}
    # 0-3 -> warning, 4-7 -> note, 8+ and -1 -> dropped
    assert by_rule == {
        "scorecard/Security-Policy": "warning",
        "scorecard/Pinned-Dependencies": "note",
    }


def test_scorecard_results_are_deterministic():
    raw = json.dumps(
        {
            "checks": [
                {"name": "B-check", "score": 1, "reason": "x"},
                {"name": "A-check", "score": 2, "reason": "y"},
            ]
        }
    )
    a = _scorecard_to_sarif(SCORECARD, raw)
    b = _scorecard_to_sarif(SCORECARD, raw)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    ids = [r["ruleId"] for r in a["runs"][0]["results"]]
    assert ids == sorted(ids)  # name-sorted


def test_scorecard_garbage_is_contained():
    from tridelphi.ladder import ExternalRun

    for bad in ("not json", "[]", '{"no":"checks"}', '{"checks":"x"}'):
        out = _scorecard_to_sarif(SCORECARD, bad)
        assert isinstance(out, ExternalRun) and not out.ok


# --- L6: gate ---------------------------------------------------------------


def _write_sarif(path, results_by_run):
    doc = {
        "version": "2.1.0",
        "runs": [
            {"tool": {"driver": {"name": name}}, "results": results}
            for name, results in results_by_run
        ],
    }
    path.write_text(json.dumps(doc))
    return path


def test_gate_passes_when_below_threshold(tmp_path, capsys):
    sarif = _write_sarif(tmp_path / "s.sarif", [("zizmor", [{"level": "warning"}])])
    assert run_gate(str(sarif), fail_on="critical") == 0


def test_gate_fails_on_critical(tmp_path):
    sarif = _write_sarif(tmp_path / "s.sarif", [("gitleaks", [{"level": "error"}])])
    assert run_gate(str(sarif), fail_on="critical") == 1


def test_gate_counts_across_runs(tmp_path):
    sarif = _write_sarif(
        tmp_path / "s.sarif",
        [("a", [{"level": "warning"}]), ("b", [{"level": "warning"}])],
    )
    assert run_gate(str(sarif), fail_on="warning") == 1
    assert run_gate(str(sarif), fail_on="critical") == 0


def test_gate_rejects_unreadable_sarif(tmp_path):
    assert run_gate(str(tmp_path / "missing.sarif")) == 2
    bad = tmp_path / "bad.sarif"
    bad.write_text("not json")
    assert run_gate(str(bad)) == 2


def test_gate_none_policy_always_passes(tmp_path):
    sarif = _write_sarif(tmp_path / "s.sarif", [("gitleaks", [{"level": "error"}])])
    assert run_gate(str(sarif), fail_on="none") == 0


# --- L6: attest -------------------------------------------------------------


def test_attest_writes_in_toto_statement(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    sarif = _write_sarif(
        tmp_path / "s.sarif",
        [("tridelphi", [{"level": "error"}]), ("zizmor", [{"level": "warning"}])],
    )
    evidence = tmp_path / "ev.json"
    assert run_attest(str(sarif), evidence_path=str(evidence)) == 0
    stmt = json.loads(evidence.read_text())
    assert stmt["_type"] == "https://in-toto.io/Statement/v1"
    assert stmt["predicateType"] == EVIDENCE_PREDICATE_TYPE
    assert stmt["subject"][0]["digest"]["sha256"]
    tools = {r["tool"]: r["severities"] for r in stmt["predicate"]["runs"]}
    assert tools["tridelphi"]["critical"] == 1
    assert tools["zizmor"]["warning"] == 1


def test_attest_is_deterministic_for_same_sarif(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    monkeypatch.setenv("GITHUB_SHA", "deadbeef")
    sarif = _write_sarif(tmp_path / "s.sarif", [("tridelphi", [{"level": "note"}])])
    e1, e2 = tmp_path / "e1.json", tmp_path / "e2.json"
    run_attest(str(sarif), evidence_path=str(e1))
    run_attest(str(sarif), evidence_path=str(e2))
    assert e1.read_text() == e2.read_text()
    stmt = json.loads(e1.read_text())
    assert stmt["predicate"]["source"] == {"repository": "acme/app", "commit": "deadbeef"}


def test_attest_rejects_unreadable_sarif(tmp_path):
    assert run_attest(str(tmp_path / "nope.sarif")) == 2


# --- CLI wiring -------------------------------------------------------------


def test_cli_gate_and_attest_subcommands(tmp_path, repo_root):
    sarif = _write_sarif(tmp_path / "s.sarif", [("gitleaks", [{"level": "error"}])])
    gate = run_cli(["gate", str(sarif)], cwd=repo_root)
    assert gate.returncode == 1 and "FAIL" in gate.stdout

    ev = tmp_path / "ev.json"
    attest = run_cli(["attest", str(sarif), "--evidence-file", str(ev)], cwd=repo_root)
    assert attest.returncode == 0 and ev.is_file()


def test_cli_gate_needs_an_argument(repo_root):
    assert run_cli(["gate"], cwd=repo_root).returncode == 2


def test_level_6_writes_evidence_alongside_scan(tmp_path, repo_root, monkeypatch):
    """--level 6 with a --sarif-file emits the evidence statement inline."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    repo = _repo(tmp_path)
    for name in ("gitleaks", "osv-scanner", "scorecard", "semgrep"):
        _stub(bin_dir, name, report='{"version":"2.1.0","runs":[]}', stdout='{"checks":[]}')
    env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    sarif = tmp_path / "out.sarif"
    ev = tmp_path / "ev.json"
    result = run_cli(
        [str(repo), "--level", "6", "--sarif-file", str(sarif), "--evidence-file", str(ev)],
        cwd=repo_root,
        env=env,
    )
    assert result.returncode == 0
    assert sarif.is_file() and ev.is_file()
    assert json.loads(ev.read_text())["_type"] == "https://in-toto.io/Statement/v1"


# --- live -------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("scorecard") is None, reason="scorecard not installed")
def test_live_scorecard_produces_a_sarif_run(repo_root):
    res = run_tool(SCORECARD, repo_root)
    assert res.ok
    assert res.sarif["runs"][0]["tool"]["driver"]["name"] == "scorecard"


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_live_semgrep_flags_a_planted_issue(tmp_path):
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / "vuln.py").write_text(
        "import subprocess\ndef r(x):\n    subprocess.call('ls ' + x, shell=True)\n"
    )
    res = run_tool(SEMGREP, tmp_path)
    assert res.ok
    assert res.finding_count >= 1
