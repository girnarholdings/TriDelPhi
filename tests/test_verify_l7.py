"""L7 · trust — `tridelphi verify`, the trust-lock pawl and provenance rung.

The pawl is fully offline and deterministic, so most tests need no network and
no external tools. Provenance verification (gh) is exercised only for its
graceful-absence path.
"""

from __future__ import annotations

import json

from conftest import run_cli

from tridelphi.verify_cmd import (
    ActionRef,
    enumerate_uses,
    run_verify,
    verify_to_sarif,
)


def _wf(repo, name, body):
    d = repo / ".github" / "workflows"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(body)


def _basic_repo(tmp_path):
    repo = tmp_path / "repo"
    _wf(
        repo,
        "ci.yml",
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4\n"
        "      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5\n"
        "      - uses: ./local-action\n"
        "      - uses: docker://alpine:3.19\n",
    )
    return repo


# --- enumeration ------------------------------------------------------------


def test_enumerate_finds_third_party_actions_only(tmp_path):
    repo = _basic_repo(tmp_path)
    refs = enumerate_uses(repo)
    slugs = [r.slug for r in refs]
    assert slugs == ["actions/checkout", "actions/setup-python"]  # sorted, no local/docker
    assert all(r.pinned_sha for r in refs)  # both SHA-pinned


def test_enumerate_captures_line_numbers_and_subpaths(tmp_path):
    repo = tmp_path / "repo"
    _wf(
        repo,
        "r.yml",
        "on: push\njobs:\n  a:\n    steps:\n"
        "      - uses: github/codeql-action/upload-sarif@abcabcabcabcabcabcabcabcabcabcabcabcabca\n",
    )
    refs = enumerate_uses(repo)
    assert len(refs) == 1
    assert refs[0].slug == "github/codeql-action/upload-sarif"
    assert refs[0].subpath == "/upload-sarif"
    assert refs[0].line == 5


def test_enumerate_ignores_commented_uses(tmp_path):
    repo = tmp_path / "repo"
    _wf(repo, "r.yml", "on: push\n# - uses: evil/action@v1\njobs: {}\n")
    assert enumerate_uses(repo) == []


def test_unpinned_ref_is_recorded_but_has_no_sha(tmp_path):
    repo = tmp_path / "repo"
    _wf(repo, "r.yml", "on: push\njobs:\n  a:\n    steps:\n      - uses: foo/bar@main\n")
    refs = enumerate_uses(repo)
    assert refs[0].pinned_sha is None
    assert refs[0].ref == "main"


# --- trust-lock lifecycle ---------------------------------------------------


def test_write_then_verify_is_clean(tmp_path):
    repo = _basic_repo(tmp_path)
    lock = tmp_path / "trust.lock"
    code, _ = run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)
    assert code == 0 and lock.is_file()
    code, doc = run_verify(repo, trust_lock=str(lock), offline=True)
    assert code == 0
    assert doc["runs"][0]["results"] == []  # everything locked, nothing to say


def test_unlocked_actions_are_notes_not_errors(tmp_path):
    repo = _basic_repo(tmp_path)
    lock = tmp_path / "trust.lock"  # never written
    code, doc = run_verify(repo, trust_lock=str(lock), offline=True, fail_on="critical")
    assert code == 0  # notes never gate at the default
    levels = {r["level"] for r in doc["runs"][0]["results"]}
    assert levels == {"note"}
    rules = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert rules == {"tridelphi-verify/unlocked-action"}


def test_sha_change_under_same_ref_is_a_regression(tmp_path):
    repo = _basic_repo(tmp_path)
    lock = tmp_path / "trust.lock"
    run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)
    # Repoint checkout to a different SHA — a tag mutation / forced pin bump.
    _wf(
        repo,
        "ci.yml",
        "on: push\njobs:\n  a:\n    steps:\n"
        "      - uses: actions/checkout@0000000000000000000000000000000000000000 # v4\n"
        "      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5\n",
    )
    code, doc = run_verify(repo, trust_lock=str(lock), offline=True, fail_on="critical")
    assert code == 1  # error gates
    regressions = [
        r for r in doc["runs"][0]["results"]
        if r["ruleId"] == "tridelphi-verify/trust-lock-regression"
    ]
    assert len(regressions) == 1
    assert regressions[0]["level"] == "error"


def test_owner_transfer_is_flagged(tmp_path):
    repo = _basic_repo(tmp_path)
    lock = tmp_path / "trust.lock"
    run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)
    # Tamper the lock to simulate: what we locked was owned by someone else.
    data = json.loads(lock.read_text())
    data["actions"]["actions/checkout"]["owner"] = "attacker"
    lock.write_text(json.dumps(data))
    code, doc = run_verify(repo, trust_lock=str(lock), offline=True)
    assert code == 1
    owner_changed = [
        r for r in doc["runs"][0]["results"]
        if r["ruleId"] == "tridelphi-verify/signer-owner-changed"
    ]
    assert owner_changed and owner_changed[0]["level"] == "error"


def test_fail_on_none_never_gates(tmp_path):
    repo = _basic_repo(tmp_path)
    lock = tmp_path / "trust.lock"
    run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)
    _wf(
        repo, "ci.yml",
        "on: push\njobs:\n  a:\n    steps:\n"
        "      - uses: actions/checkout@0000000000000000000000000000000000000000\n",
    )
    code, _ = run_verify(repo, trust_lock=str(lock), offline=True, fail_on="none")
    assert code == 0


# --- determinism and output -------------------------------------------------


def test_verify_sarif_is_deterministic(tmp_path):
    repo = _basic_repo(tmp_path)
    lock = tmp_path / "trust.lock"  # no lock -> notes
    _, d1 = run_verify(repo, trust_lock=str(lock), offline=True, tool_version="1.2.3")
    _, d2 = run_verify(repo, trust_lock=str(lock), offline=True, tool_version="1.2.3")
    assert json.dumps(d1, sort_keys=True) == json.dumps(d2, sort_keys=True)


def test_verify_sarif_passes_the_shape_gate(tmp_path):
    from tridelphi.orchestrate import sarif_shape_error

    ref = ActionRef("acme", "act", "", "main", "ci.yml", 5)
    from tridelphi.verify_cmd import VerifyFinding

    doc = verify_to_sarif(
        [VerifyFinding("error", "trust-lock-regression", ref, "x")], tool_version="0"
    )
    assert sarif_shape_error(doc) is None
    assert doc["runs"][0]["tool"]["driver"]["name"] == "tridelphi-verify"


def test_corrupt_lock_is_treated_as_empty(tmp_path):
    repo = _basic_repo(tmp_path)
    lock = tmp_path / "trust.lock"
    lock.write_text("not json{{{")
    code, doc = run_verify(repo, trust_lock=str(lock), offline=True)
    # A corrupt lock cannot silently pass everything: it reads as no lock, so
    # every action becomes an unlocked note, and the run still succeeds.
    assert code == 0
    assert all(r["level"] == "note" for r in doc["runs"][0]["results"])


# --- CLI --------------------------------------------------------------------


def test_cli_verify_subcommand(tmp_path, repo_root):
    repo = _basic_repo(tmp_path)
    lock = tmp_path / "trust.lock"
    write = run_cli(
        ["verify", str(repo), "--write-trust-lock", "--trust-lock", str(lock)],
        cwd=repo_root,
    )
    assert write.returncode == 0 and lock.is_file()
    ok = run_cli(["verify", str(repo), "--trust-lock", str(lock), "--offline"], cwd=repo_root)
    assert ok.returncode == 0


def test_cli_verify_sarif_stdout_is_clean(tmp_path, repo_root):
    """--format sarif must put valid JSON on stdout, summary on stderr."""
    repo = _basic_repo(tmp_path)
    lock = tmp_path / "trust.lock"  # no lock -> notes, but valid document
    result = run_cli(
        ["verify", str(repo), "--trust-lock", str(lock), "--offline", "--format", "sarif"],
        cwd=repo_root,
    )
    doc = json.loads(result.stdout)  # parses = clean
    assert doc["runs"][0]["tool"]["driver"]["name"] == "tridelphi-verify"


def test_level_7_folds_trust_into_the_merged_sarif(tmp_path, repo_root):
    repo = _basic_repo(tmp_path)
    sarif = tmp_path / "out.sarif"
    result = run_cli(
        [str(repo), "--level", "7", "--offline", "--sarif-file", str(sarif)],
        cwd=repo_root,
    )
    # No lock yet -> trust notes, which do not gate; exit governed by core.
    doc = json.loads(sarif.read_text())
    names = [r["tool"]["driver"]["name"] for r in doc["runs"]]
    assert "tridelphi" in names and "tridelphi-verify" in names
    assert result.returncode in (0, 1)
