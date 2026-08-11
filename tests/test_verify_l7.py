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


# --- --relock: the on-ramp back to green after an intentional bump ----------


def _bump_checkout(repo):
    """Repoint checkout to a new SHA, as a dependency bot would."""
    _wf(
        repo,
        "ci.yml",
        "on: push\njobs:\n  a:\n    steps:\n"
        "      - uses: actions/checkout@0000000000000000000000000000000000000000 # v5\n"
        "      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5\n",
    )


def test_relock_records_an_intentional_bump_and_clears_the_gate(tmp_path):
    """The whole point: a wanted update must have a way back to green."""
    repo = _basic_repo(tmp_path)
    lock = tmp_path / "trust.lock"
    run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)
    _bump_checkout(repo)
    assert run_verify(repo, trust_lock=str(lock), offline=True)[0] == 1  # gated

    code, doc = run_verify(repo, trust_lock=str(lock), relock=True, offline=True)
    assert code == 0 and doc is None
    # ...and the pawl is armed again on the NEW identity, not disabled.
    assert run_verify(repo, trust_lock=str(lock), offline=True)[0] == 0
    assert json.loads(lock.read_text())["actions"]["actions/checkout"]["sha"] == "0" * 40


def test_relock_refuses_when_an_action_changed_hands(tmp_path):
    """A takeover looks exactly like a routine bump. One click must not bless it."""
    repo = _basic_repo(tmp_path)
    lock = tmp_path / "trust.lock"
    run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)
    data = json.loads(lock.read_text())
    data["actions"]["actions/checkout"]["owner"] = "attacker"
    lock.write_text(json.dumps(data))
    before = lock.read_text()

    code, _ = run_verify(repo, trust_lock=str(lock), relock=True, offline=True)
    assert code == 1, "an owner change must refuse"
    assert lock.read_text() == before, "a refused re-lock must write nothing at all"
    # Still gating afterwards — the refusal did not quietly clear the finding.
    assert run_verify(repo, trust_lock=str(lock), offline=True)[0] == 1


def test_relock_refuses_wholesale_not_per_entry(tmp_path):
    """With a takeover live, the *other* moved pins must not be blessed either."""
    repo = _basic_repo(tmp_path)
    lock = tmp_path / "trust.lock"
    run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)
    data = json.loads(lock.read_text())
    data["actions"]["actions/setup-python"]["owner"] = "attacker"
    lock.write_text(json.dumps(data))
    _bump_checkout(repo)  # a legitimate bump alongside the scary one

    code, _ = run_verify(repo, trust_lock=str(lock), relock=True, offline=True)
    assert code == 1
    still = json.loads(lock.read_text())["actions"]["actions/checkout"]["sha"]
    assert still != "0" * 40, "the innocent bump must not ride along on a refusal"


def test_relock_is_a_no_op_when_nothing_moved(tmp_path):
    repo = _basic_repo(tmp_path)
    lock = tmp_path / "trust.lock"
    run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)
    before = lock.read_text()
    code, _ = run_verify(repo, trust_lock=str(lock), relock=True, offline=True)
    assert code == 0 and lock.read_text() == before


def test_cli_exposes_relock(tmp_path, repo_root):
    repo = _basic_repo(tmp_path)
    lock = tmp_path / "trust.lock"
    run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)
    _bump_checkout(repo)
    result = run_cli(
        ["verify", str(repo), "--trust-lock", str(lock), "--relock", "--offline"],
        cwd=repo_root,
    )
    assert result.returncode == 0
    assert "re-locked" in result.stdout


# --- action definitions are consumed too, so they must be locked too ---------


def _action_yml(repo, body):
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "action.yml").write_text(body, encoding="utf-8")


def test_action_definitions_are_enumerated_not_just_workflows(tmp_path):
    """A repo that *publishes* a composite action ships its dependencies to
    every consumer. Scanning only .github/workflows left those dependencies
    outside the pawl — swappable without tripping anything."""
    repo = tmp_path / "repo"
    _action_yml(
        repo,
        "name: Demo\nruns:\n  using: composite\n  steps:\n"
        "    - uses: actions/setup-python@" + "a" * 40 + " # v5\n"
        "    - uses: github/codeql-action/upload-sarif@" + "b" * 40 + " # v3\n",
    )
    refs = enumerate_uses(repo)
    assert {r.slug for r in refs} == {
        "actions/setup-python",
        "github/codeql-action/upload-sarif",
    }
    assert all(r.workflow == "action.yml" for r in refs)


def test_a_takeover_inside_action_yml_is_caught(tmp_path):
    """The whole point of closing the gap: an owner change in a published
    action's own dependency must gate, exactly as it does in a workflow."""
    repo = tmp_path / "repo"
    _action_yml(
        repo,
        "name: Demo\nruns:\n  using: composite\n  steps:\n"
        "    - uses: actions/setup-python@" + "a" * 40 + " # v5\n",
    )
    lock = tmp_path / "trust.lock"
    run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)
    assert run_verify(repo, trust_lock=str(lock), offline=True)[0] == 0

    data = json.loads(lock.read_text())
    data["actions"]["actions/setup-python"]["owner"] = "attacker"
    lock.write_text(json.dumps(data))

    code, doc = run_verify(repo, trust_lock=str(lock), offline=True)
    assert code == 1, "a takeover in action.yml must gate"
    rules = [r["ruleId"] for r in doc["runs"][0]["results"]]
    assert "tridelphi-verify/signer-owner-changed" in rules


def test_composite_actions_under_dot_github_are_scanned(tmp_path):
    repo = tmp_path / "repo"
    d = repo / ".github" / "actions" / "helper"
    d.mkdir(parents=True)
    (d / "action.yml").write_text(
        "name: Helper\nruns:\n  using: composite\n  steps:\n"
        "    - uses: actions/checkout@" + "c" * 40 + " # v4\n",
        encoding="utf-8",
    )
    refs = enumerate_uses(repo)
    assert [r.slug for r in refs] == ["actions/checkout"]
    assert refs[0].workflow == ".github/actions/helper/action.yml"


def test_a_repo_with_no_workflows_but_an_action_is_still_covered(tmp_path):
    """The old early-return bailed out when .github/workflows was missing,
    which silently skipped a pure action repository entirely."""
    repo = tmp_path / "repo"
    _action_yml(
        repo,
        "name: Demo\nruns:\n  using: composite\n  steps:\n"
        "    - uses: actions/checkout@" + "d" * 40 + " # v4\n",
    )
    assert not (repo / ".github" / "workflows").exists()
    assert [r.slug for r in enumerate_uses(repo)] == ["actions/checkout"]
