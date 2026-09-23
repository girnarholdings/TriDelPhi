"""A pull request cannot accept its own findings.

`.tridelphi-baseline.json` waives findings by fingerprint, and a fingerprint is a
plain hash of the workflow, job and rule names. When the gate read the baseline
from the tree under scan, a pull request could add the fingerprint of the
critical it introduces and pass. Both workflows that gate pull requests — the
composite action and `init --from-source` — now take the baseline from the base
commit. These run the real step bodies: the script under Node against a mock
GitHub client, and the scan step's bash against a stub `tridelphi`.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import run_cli
from ruamel.yaml import YAML

from tridelphi.init_cmd import BASE_BASELINE_SCRIPT, WORKFLOW
from tridelphi.sarif import fingerprint

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
BASH = shutil.which("bash")


def _steps(document: dict) -> list[dict]:
    if "runs" in document:
        return document["runs"]["steps"]
    return document["jobs"]["scan"]["steps"]


def _step(document: dict, step_id: str) -> dict:
    return next(step for step in _steps(document) if step.get("id") == step_id)


ACTION = YAML(typ="safe").load((ROOT / "action.yml").read_text(encoding="utf-8"))
FROM_SOURCE = YAML(typ="safe").load(WORKFLOW)
SURFACES = {"action.yml": ACTION, "init --from-source": FROM_SOURCE}


@pytest.mark.parametrize("surface", SURFACES)
def test_every_gating_workflow_carries_the_same_step(surface):
    step = _step(SURFACES[surface], "baseline")
    assert "github-script" in step["uses"]
    assert step["with"]["script"] == BASE_BASELINE_SCRIPT
    names = [s.get("id") for s in _steps(SURFACES[surface])]
    assert names.index("baseline") < names.index("scan"), "the baseline must exist before the scan"


# --- the script -------------------------------------------------------------

HARNESS = r"""
const [body, scenario] = JSON.parse(process.argv[1]);
const outputs = {}, notices = [], warnings = [], calls = [];
const fail = (status) => Object.assign(new Error('http ' + status), { status });
const github = { rest: {
  pulls: { get: async (args) => {
    calls.push(['pulls.get', args.pull_number]);
    if (scenario.pullsFail) throw fail(403);
    return { data: { base: { sha: 'dispatchbase' } } };
  } },
  repos: { getContent: async (args) => {
    calls.push(['getContent', args.path, args.ref, args.mediaType.format]);
    if (scenario.contentStatus) throw fail(scenario.contentStatus);
    return { data: scenario.baseFile };
  } },
} };
const context = { repo: { owner: 'o', repo: 'r' }, payload: scenario.payload };
const core = {
  setOutput: (k, v) => { outputs[k] = v; },
  notice: (m) => notices.push(m),
  warning: (m) => warnings.push(m),
};
const AsyncFunction = (async () => {}).constructor;
new AsyncFunction('github', 'context', 'core', 'require', body)(github, context, core, require)
  .then(() => console.log(JSON.stringify({ outputs, notices, warnings, calls })))
  .catch((e) => console.log(JSON.stringify({ thrown: e.message })));
"""

PR_EVENT = {"pull_request": {"number": 7, "base": {"sha": "basesha"}}}
BASE_FILE = '{"version": 1, "fingerprints": [{"fp": "accepted-on-main"}]}\n'


def _run_script(tmp_path: Path, scenario: dict, *, tree_file: str | None = None,
                scan_path: str = ".", pr_number: str = "") -> tuple[dict, Path]:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    if tree_file is not None:
        (workspace / ".tridelphi-baseline.json").write_text(tree_file, encoding="utf-8")
    out = tmp_path / "base-baseline.json"
    env = {**os.environ, "SCAN_PATH": scan_path, "PR_NUMBER": pr_number, "BASE_BASELINE": str(out)}
    proc = subprocess.run(
        [NODE, "-e", HARNESS, json.dumps([BASE_BASELINE_SCRIPT, scenario])],
        capture_output=True, text=True, timeout=30, cwd=workspace, env=env,
    )
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert "thrown" not in result, result
    return result, out


node_only = pytest.mark.skipif(NODE is None, reason="node is not installed")


@node_only
def test_pull_request_gets_the_base_commits_baseline(tmp_path):
    waiver = '{"version": 1, "fingerprints": [{"fp": "my-own-critical"}]}\n'
    result, out = _run_script(
        tmp_path, {"payload": PR_EVENT, "baseFile": BASE_FILE}, tree_file=waiver,
    )
    assert result["outputs"] == {"mode": "base"}
    assert out.read_text() == BASE_FILE, "the pull request's copy must not be used"
    assert ["getContent", ".tridelphi-baseline.json", "basesha", "raw"] in result["calls"]
    assert result["notices"] and "changes .tridelphi-baseline.json" in result["notices"][0]


@node_only
def test_an_unchanged_baseline_raises_no_notice(tmp_path):
    result, _ = _run_script(
        tmp_path, {"payload": PR_EVENT, "baseFile": BASE_FILE}, tree_file=BASE_FILE,
    )
    assert result["outputs"] == {"mode": "base"} and not result["notices"]


@node_only
def test_no_baseline_on_the_base_branch_means_none_even_if_the_pr_adds_one(tmp_path):
    result, out = _run_script(
        tmp_path, {"payload": PR_EVENT, "contentStatus": 404}, tree_file=BASE_FILE,
    )
    assert result["outputs"] == {"mode": "none"} and not out.exists()
    assert result["notices"], "adding a baseline in the pull request is worth saying"


@node_only
@pytest.mark.parametrize("status", [403, 500])
def test_an_unreadable_base_fails_toward_counting_everything(tmp_path, status):
    result, out = _run_script(tmp_path, {"payload": PR_EVENT, "contentStatus": status})
    assert result["outputs"] == {"mode": "none"} and not out.exists()
    assert result["warnings"]


@node_only
def test_a_push_keeps_the_trees_baseline(tmp_path):
    result, _ = _run_script(tmp_path, {"payload": {}}, tree_file=BASE_FILE)
    assert result["outputs"] == {"mode": "tree"} and not result["calls"]


@node_only
def test_a_dispatched_pull_request_resolves_its_base(tmp_path):
    result, out = _run_script(
        tmp_path, {"payload": {}, "baseFile": BASE_FILE}, pr_number="12",
    )
    assert ["pulls.get", 12] in result["calls"]
    assert ["getContent", ".tridelphi-baseline.json", "dispatchbase", "raw"] in result["calls"]
    assert result["outputs"] == {"mode": "base"} and out.read_text() == BASE_FILE


@node_only
def test_a_dispatched_pull_request_that_cannot_be_read_counts_everything(tmp_path):
    result, _ = _run_script(tmp_path, {"payload": {}, "pullsFail": True}, pr_number="12")
    assert result["outputs"] == {"mode": "none"} and result["warnings"]


@node_only
@pytest.mark.parametrize("scan_path,expected", [
    ("sub/", "sub/.tridelphi-baseline.json"),
    ("./sub/../app", "app/.tridelphi-baseline.json"),
])
def test_the_baseline_path_follows_the_scan_path(tmp_path, scan_path, expected):
    result, _ = _run_script(
        tmp_path, {"payload": PR_EVENT, "baseFile": BASE_FILE}, scan_path=scan_path,
    )
    assert ["getContent", expected, "basesha", "raw"] in result["calls"]


@node_only
@pytest.mark.parametrize("scan_path", ["..", "../other", "/etc"])
def test_a_scan_path_outside_the_repository_gets_no_baseline(tmp_path, scan_path):
    result, _ = _run_script(tmp_path, {"payload": PR_EVENT}, scan_path=scan_path)
    assert result["outputs"] == {"mode": "none"} and not result["calls"]


# --- the scan step's wiring ---------------------------------------------------

STUB = """#!/bin/sh
printf '%s\\n' "$@" > "$ARGS_FILE"
"""


@pytest.mark.skipif(BASH is None, reason="bash is not installed")
@pytest.mark.parametrize("surface", SURFACES)
@pytest.mark.parametrize("mode,expected", [
    ("base", ["--baseline", "BASEFILE"]),
    ("tree", []),
    ("none", ["--no-baseline"]),
    ("", ["--no-baseline"]),  # the step did not finish: accept nothing
])
def test_scan_step_passes_the_chosen_baseline(tmp_path, surface, mode, expected):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "tridelphi"
    stub.write_text(STUB)
    stub.chmod(0o755)
    runner_temp = tmp_path / "runner"
    runner_temp.mkdir()
    args_file = tmp_path / "args"
    base_file = str(runner_temp / "tridelphi-base-baseline.json")
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "ARGS_FILE": str(args_file),
        "RUNNER_TEMP": str(runner_temp),
        "GITHUB_OUTPUT": str(tmp_path / "output"),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
        "BASELINE_MODE": mode,
        "BASE_BASELINE": base_file,
        "SCAN_PATH": ".",
        "LEVEL": "0",
        "FAIL_ON": "critical",
        "SARIF_FILE": str(tmp_path / "out.sarif"),
        "EVIDENCE_FILE": str(tmp_path / "evidence.json"),
        "TRUST_LOCK": ".tridelphi/trust.lock",
    }
    script = _step(SURFACES[surface], "scan")["run"]
    subprocess.run([BASH, "-c", script], cwd=tmp_path, env=env, capture_output=True,
                   text=True, timeout=60)
    args = args_file.read_text().splitlines()
    baseline_args = [a for a in args if a in ("--baseline", "--no-baseline", base_file)]
    assert baseline_args == [base_file if a == "BASEFILE" else a for a in expected]


# --- what the fix prevents, end to end ----------------------------------------

_CRITICAL = (
    "on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
    "    permissions:\n      contents: write\n    steps:\n"
    '      - run: echo "${{ github.event.comment.body }}" && curl https://x.example\n'
)


def test_the_trees_baseline_can_waive_the_pull_requests_own_critical(repo_root, tmp_path):
    """The attack, and why the gate must not read the tree's copy."""
    from tridelphi.api import analyze

    repo = tmp_path / "pr"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "new.yml").write_text(_CRITICAL)
    prints = [fingerprint(f) for f in analyze(repo).findings if f.severity == "critical"]
    assert prints
    (repo / ".tridelphi-baseline.json").write_text(
        json.dumps({"version": 1, "fingerprints": [{"fp": fp} for fp in prints]})
    )
    assert run_cli([str(repo)], cwd=repo_root).returncode == 0, "the self-waiver works on the tree"

    base = tmp_path / "base-baseline.json"
    base.write_text(json.dumps({"version": 1, "fingerprints": []}))
    assert run_cli([str(repo), "--baseline", str(base)], cwd=repo_root).returncode == 1
    assert run_cli([str(repo), "--no-baseline"], cwd=repo_root).returncode == 1
