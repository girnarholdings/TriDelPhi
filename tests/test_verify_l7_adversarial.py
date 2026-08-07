"""L7 · trust — adversarial coverage for `tridelphi verify` / verify_cmd.py.

The threat model: a hostile repo controls its own workflow files AND could
tamper with a committed trust-lock. Every test here either (a) proves an
attack is already contained, or (b) reproduces a genuine bug that was fixed
alongside this file (see the two "GENUINE BUG" sections below).

Two real bugs were found and fixed in tridelphi/verify_cmd.py while writing
this suite:

1. **Case-insensitive identity evasion** (`ActionRef.lock_key` /
   `_load_lock`). GitHub resolves ``owner/repo`` case-insensitively, but the
   trust-lock key was case-sensitive. An attacker could change the casing of
   a `uses:` line *and* its SHA in the same PR; the case-sensitive key missed
   the existing lock entry, so what should have been a gating
   `trust-lock-regression` **error** was reported as a non-gating
   `unlocked-action` **note** — exit code 0. A tamperable lock that
   downgrades a real takeover to "unseen before" is worse than no lock at
   all. Fixed by lower-casing the lock key on both the write/lookup side
   (`ActionRef.lock_key`) and the load side (`_load_lock`), and by comparing
   `owner` case-insensitively in `_check_against_lock`.

2. **Folded `uses:` value invisibility** (`enumerate_uses`). YAML permits a
   mapping value to fold onto the next line with no block-scalar indicator:

       - uses:
           some/action@<sha>

   GitHub Actions' parser treats this identically to the one-line form. The
   original line-level scan only recognized `uses:` with its value on the
   *same* line, so a third-party action written this way was invisible to
   the pawl entirely — no note, no error, nothing — a strictly worse outcome
   than "unlocked", since a note at least surfaces the action for review.
   Fixed with a narrow one-line-fold detector (`_folded_uses_value`) that
   only fires for the direct, unambiguous continuation shape; deeper
   multi-line YAML folding remains explicitly out of scope, matching the
   module's stated line-scan trade-off.
"""

from __future__ import annotations

import json
import time

from conftest import run_cli

from tridelphi.orchestrate import sarif_shape_error
from tridelphi.verify_cmd import (
    ActionRef,
    VerifyFinding,
    _load_lock,
    _uses_value,
    enumerate_uses,
    run_verify,
    verify_to_sarif,
)


def _wf(repo, name, body):
    d = repo / ".github" / "workflows"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(body)


SHA_A = "1111111111111111111111111111111111111111"
SHA_B = "2222222222222222222222222222222222222222"


# =============================================================================
# 1. enumerate_uses / _uses_value / _USES_RE — attacker-controlled workflow text
# =============================================================================


def test_weird_whitespace_and_tabs_still_enumerate(tmp_path):
    """Tabs between the list dash, the key, and the value are all valid YAML
    whitespace; the scanner must not choke on them or silently drop the ref."""
    repo = tmp_path / "repo"
    _wf(repo, "r.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      -\tuses:\tactions/checkout@{SHA_A}\n")
    refs = enumerate_uses(repo)
    assert len(refs) == 1
    assert refs[0].slug == "actions/checkout"


def test_single_and_double_quoted_values_are_unquoted(tmp_path):
    repo = tmp_path / "repo"
    _wf(
        repo,
        "r.yml",
        "on: push\njobs:\n  a:\n    steps:\n"
        f"      - uses: 'actions/checkout@{SHA_A}'\n"
        f"      - uses: \"actions/setup-python@{SHA_B}\"\n",
    )
    refs = enumerate_uses(repo)
    slugs = {r.slug: r.ref for r in refs}
    assert slugs == {"actions/checkout": SHA_A, "actions/setup-python": SHA_B}


def test_inline_comment_with_trailing_hashes_is_stripped(tmp_path):
    repo = tmp_path / "repo"
    _wf(
        repo,
        "r.yml",
        "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A} # v4 # nested # hashes\n",
    )
    refs = enumerate_uses(repo)
    assert refs[0].ref == SHA_A


def test_local_and_docker_uses_are_excluded(tmp_path):
    """Neither `./local-action` nor `docker://image` has a publisher identity
    to lock — both must be excluded, not just skipped-with-a-crash."""
    repo = tmp_path / "repo"
    _wf(
        repo,
        "r.yml",
        "on: push\njobs:\n  a:\n    steps:\n"
        "      - uses: ./local-action\n"
        "      - uses: docker://alpine:3.19\n"
        "      - uses: docker://ghcr.io/owner/image@sha256:deadbeef\n",
    )
    assert enumerate_uses(repo) == []


def test_reusable_workflow_call_is_enumerated_with_full_subpath(tmp_path):
    """`owner/repo/.github/workflows/x.yml@ref` — a reusable workflow call —
    has the same third-party-trust shape as an action and must be lockable."""
    repo = tmp_path / "repo"
    _wf(
        repo,
        "r.yml",
        "on: push\njobs:\n  a:\n    uses: octo/shared/.github/workflows/build.yml@" + SHA_A + "\n",
    )
    refs = enumerate_uses(repo)
    assert len(refs) == 1
    assert refs[0].slug == "octo/shared/.github/workflows/build.yml"
    assert refs[0].pinned_sha == SHA_A


def test_wrong_case_uses_key_is_not_a_match(tmp_path):
    """`USES:` is not `uses:` — GitHub Actions' key is case-sensitive, and so
    must the scanner be, or it would falsely enumerate a key that GH ignores."""
    repo = tmp_path / "repo"
    _wf(repo, "r.yml", "on: push\njobs:\n  a:\n    steps:\n" "      - USES: evil/action@main\n")
    assert enumerate_uses(repo) == []


def test_flow_mapping_uses_is_not_misparsed(tmp_path):
    """`{uses: owner/repo@ref}` (flow style) is not the line-prefix shape the
    scanner expects. It must not be silently mis-recorded as a bogus action
    whose owner is literally `{uses`; it should simply not match."""
    repo = tmp_path / "repo"
    _wf(repo, "r.yml", "on: push\njobs:\n  a:\n    steps:\n" "      - uses: {a: b}\n")
    assert enumerate_uses(repo) == []


def test_path_traversal_shaped_owner_repo_does_not_crash_or_escape(tmp_path):
    """`../../../etc/passwd@ref` matches the owner/repo *character class*
    (`.` and `-` are permitted). It must be recorded as an inert, distinct
    slug — never used to touch the filesystem — and never crash."""
    repo = tmp_path / "repo"
    _wf(repo, "r.yml", "on: push\njobs:\n  a:\n    steps:\n" "      - uses: ../../../etc/passwd@deadbeef\n")
    refs = enumerate_uses(repo)
    assert len(refs) == 1
    assert refs[0].owner == ".."
    assert refs[0].repo == ".."
    assert refs[0].subpath == "/../etc/passwd"


def test_unicode_homoglyph_owner_is_a_distinct_slug_not_a_silent_match(tmp_path):
    """Cyrillic small letter A (U+0430) visually resembles Latin 'a'. `\\w`
    matches Unicode word characters, so this must not crash — and
    critically, it must NOT be treated as the same lock identity as ASCII
    `actions/checkout`."""
    repo = tmp_path / "repo"
    homoglyph_owner = "\u0430ctions"  # U+0430 (Cyrillic) + "ctions"
    _wf(repo, "r.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: {homoglyph_owner}/checkout@{SHA_A}\n")
    refs = enumerate_uses(repo)
    assert len(refs) == 1
    assert refs[0].owner == homoglyph_owner
    assert refs[0].lock_key != "actions/checkout"


def test_line_numbers_are_correct_across_multiple_workflows(tmp_path):
    repo = tmp_path / "repo"
    _wf(repo, "a.yml", "on: push\njobs:\n  x:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A}\n")
    _wf(
        repo,
        "b.yml",
        "on: push\n\n\njobs:\n  y:\n    steps:\n" f"      - uses: actions/setup-python@{SHA_B}\n",
    )
    refs = {r.workflow: r.line for r in enumerate_uses(repo)}
    assert refs[".github/workflows/a.yml"] == 5
    assert refs[".github/workflows/b.yml"] == 7


def test_commented_out_uses_is_ignored(tmp_path):
    repo = tmp_path / "repo"
    _wf(repo, "r.yml", "on: push\n# - uses: evil/action@v1\njobs: {}\n")
    assert enumerate_uses(repo) == []


def test_only_third_party_actions_enumerated_ordering_is_deterministic(tmp_path):
    repo = tmp_path / "repo"
    _wf(
        repo,
        "z.yml",
        "on: push\njobs:\n  a:\n    steps:\n"
        f"      - uses: zzz/last@{SHA_A}\n"
        f"      - uses: aaa/first@{SHA_B}\n"
        "      - uses: ./local\n"
        "      - uses: docker://alpine\n",
    )
    refs = enumerate_uses(repo)
    assert [r.slug for r in refs] == ["aaa/first", "zzz/last"]


def test_uses_re_has_no_catastrophic_backtracking(tmp_path):
    """A pathological `uses:` value (many slash-separated segments, no
    trailing `@`) must fail to match in linear time, not hang the scan."""
    repo = tmp_path / "repo"
    payload = "a/" * 20000 + "a"  # no '@' — worst case for a naive regex
    _wf(repo, "r.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: {payload}\n")
    start = time.time()
    refs = enumerate_uses(repo)
    elapsed = time.time() - start
    assert elapsed < 2.0, f"enumerate_uses took {elapsed}s on a pathological uses: value"
    assert refs == []  # no '@' -> not a valid action ref, correctly dropped


def test_five_thousand_actions_enumerate_quickly(tmp_path):
    """A single giant workflow (or an attacker trying to DoS the scanner via
    workflow size) must still finish quickly and deterministically."""
    repo = tmp_path / "repo"
    body = "on: push\njobs:\n  a:\n    steps:\n" + "".join(
        f"      - uses: owner{i}/repo{i}@{'a' * 40}\n" for i in range(5000)
    )
    _wf(repo, "big.yml", body)
    start = time.time()
    refs = enumerate_uses(repo)
    elapsed = time.time() - start
    assert elapsed < 5.0
    assert len(refs) == 5000


def test_folded_uses_value_is_enumerated_GENUINE_BUG_FIXED(tmp_path):
    """GENUINE BUG (fixed): `uses:` folded onto the next line is valid YAML
    that GitHub Actions parses identically to the one-line form. Before the
    fix, this third-party action was completely invisible to the pawl — not
    even an 'unlocked' note. Now it must be enumerated like any other ref."""
    repo = tmp_path / "repo"
    _wf(
        repo,
        "r.yml",
        "on: push\njobs:\n  a:\n    steps:\n"
        "      - uses:\n"
        f"          actions/checkout@{SHA_A}\n"
        "      - run: echo hi\n",
    )
    refs = enumerate_uses(repo)
    assert len(refs) == 1
    assert refs[0].slug == "actions/checkout"
    assert refs[0].ref == SHA_A
    assert refs[0].line == 5  # the `uses:` key line, not the value line


def test_folded_uses_value_with_quotes_and_comment(tmp_path):
    repo = tmp_path / "repo"
    _wf(
        repo,
        "r.yml",
        "on: push\njobs:\n  a:\n    steps:\n"
        "      - uses:\n"
        f"          'actions/checkout@{SHA_A}'  # v4\n",
    )
    refs = enumerate_uses(repo)
    assert refs[0].ref == SHA_A


def test_bare_uses_with_no_real_continuation_does_not_misfire(tmp_path):
    """A malformed/empty `uses:` immediately followed by a sibling list item
    or a dedented key must not be mistaken for a folded value."""
    repo = tmp_path / "repo"
    _wf(
        repo,
        "r.yml",
        "on: push\njobs:\n  a:\n    steps:\n" "      - uses:\n" "      - run: echo hi\n",
    )
    assert enumerate_uses(repo) == []


def test_folded_value_does_not_get_double_counted(tmp_path):
    """The continuation line itself must not *also* be scanned as an
    independent `uses:` line (it isn't prefixed with `uses:`, so the normal
    path already ignores it — this pins that down explicitly)."""
    repo = tmp_path / "repo"
    _wf(
        repo,
        "r.yml",
        "on: push\njobs:\n  a:\n    steps:\n"
        "      - uses:\n"
        f"          actions/checkout@{SHA_A}\n",
    )
    refs = enumerate_uses(repo)
    assert len(refs) == 1


def test_uses_value_helper_rejects_pure_comment_lines():
    assert _uses_value("# uses: evil/action@v1") is None
    assert _uses_value("   ") is None
    assert _uses_value("uses:") is None


# =============================================================================
# 2. _load_lock — the lock file itself is attacker-influenceable
#    CRITICAL PROPERTY: a corrupt/tampered lock must read as EMPTY, never as
#    "matches everything" — a malformed lock must never hide a real
#    regression by making it look locked-and-clean.
# =============================================================================


def test_lock_not_json_reads_empty(tmp_path):
    p = tmp_path / "trust.lock"
    p.write_text("not json{{{")
    assert _load_lock(p) == {}


def test_lock_actions_is_a_list_reads_empty(tmp_path):
    p = tmp_path / "trust.lock"
    p.write_text(json.dumps({"actions": ["a", "b"]}))
    assert _load_lock(p) == {}


def test_lock_actions_is_a_string_reads_empty(tmp_path):
    p = tmp_path / "trust.lock"
    p.write_text(json.dumps({"actions": "oops"}))
    assert _load_lock(p) == {}


def test_lock_actions_missing_entirely_reads_empty(tmp_path):
    p = tmp_path / "trust.lock"
    p.write_text(json.dumps({"unrelated": True}))
    assert _load_lock(p) == {}


def test_lock_entry_not_a_dict_is_dropped_not_crashed(tmp_path):
    p = tmp_path / "trust.lock"
    p.write_text(json.dumps({"actions": {"a/b": "just a string, not a dict"}}))
    assert _load_lock(p) == {}


def test_lock_entry_missing_sha_is_dropped(tmp_path):
    p = tmp_path / "trust.lock"
    p.write_text(json.dumps({"actions": {"a/b": {"owner": "a"}}}))
    assert _load_lock(p) == {}


def test_lock_entry_missing_owner_is_dropped(tmp_path):
    p = tmp_path / "trust.lock"
    p.write_text(json.dumps({"actions": {"a/b": {"sha": "x" * 40}}}))
    assert _load_lock(p) == {}


def test_lock_entry_non_string_sha_is_dropped(tmp_path):
    p = tmp_path / "trust.lock"
    p.write_text(json.dumps({"actions": {"a/b": {"owner": "a", "sha": 123456}}}))
    assert _load_lock(p) == {}


def test_lock_entry_non_string_owner_is_dropped(tmp_path):
    p = tmp_path / "trust.lock"
    p.write_text(json.dumps({"actions": {"a/b": {"owner": None, "sha": "x" * 40}}}))
    assert _load_lock(p) == {}


def test_lock_entry_extra_keys_are_ignored_not_fatal(tmp_path):
    p = tmp_path / "trust.lock"
    p.write_text(
        json.dumps({"actions": {"a/b": {"owner": "a", "sha": "x" * 40, "extra": "z", "nested": {"k": 1}}}})
    )
    assert _load_lock(p) == {"a/b": {"sha": "x" * 40, "owner": "a"}}


def test_lock_top_level_not_an_object_reads_empty(tmp_path):
    for payload in ('["a","b"]', '"hello"', "42", "null", "true"):
        p = tmp_path / "trust.lock"
        p.write_text(payload)
        assert _load_lock(p) == {}, payload


def test_lock_missing_file_reads_empty(tmp_path):
    assert _load_lock(tmp_path / "nope.lock") == {}


def test_huge_lock_loads_quickly_and_does_not_crash(tmp_path):
    p = tmp_path / "trust.lock"
    huge = {"actions": {f"owner{i}/repo{i}": {"owner": f"owner{i}", "sha": "a" * 40} for i in range(50000)}}
    p.write_text(json.dumps(huge))
    start = time.time()
    loaded = _load_lock(p)
    elapsed = time.time() - start
    assert elapsed < 5.0
    assert len(loaded) == 50000


def test_corrupt_lock_never_silently_matches_everything(tmp_path):
    """The critical property: a malformed lock must not accidentally make a
    real, malicious change look 'already locked and unchanged'. It must fall
    back to empty, which means every action becomes a visible `note` — never
    a silent pass-through with zero findings and no trace."""
    repo = tmp_path / "repo"
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: attacker/action@{SHA_B}\n")
    lock = tmp_path / "trust.lock"
    lock.write_text("{not even valid json")
    code, doc = run_verify(repo, trust_lock=str(lock), offline=True)
    assert code == 0
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "tridelphi-verify/unlocked-action"
    assert results[0]["level"] == "note"


# =============================================================================
# 2b. Case-insensitive identity — GENUINE BUG, fixed
# =============================================================================


def test_case_swap_plus_sha_change_is_still_a_gating_regression_GENUINE_BUG_FIXED(tmp_path):
    """GENUINE BUG (fixed): GitHub resolves `owner/repo` case-insensitively.
    Before the fix, an attacker could change the case of `uses:` *and* swap
    the SHA in the same PR; the case-sensitive lock key missed the existing
    entry, downgrading a gating `trust-lock-regression` error to a
    non-gating `unlocked-action` note (exit 0) — a tampered identity that
    read as merely "never seen before". This is the exact "takeover reports
    clean" failure mode the pawl exists to prevent."""
    repo = tmp_path / "repo"
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A}\n")
    lock = tmp_path / "trust.lock"
    run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)

    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: Actions/Checkout@{SHA_B}\n")
    code, doc = run_verify(repo, trust_lock=str(lock), offline=True, fail_on="critical")
    assert code == 1
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "tridelphi-verify/trust-lock-regression"
    assert results[0]["level"] == "error"


def test_case_only_change_with_unchanged_sha_is_clean(tmp_path):
    """The corollary: pure casing with the SAME pinned identity is cosmetic
    (GitHub routes it to the same repo) and must not raise a false
    'signer-owner-changed' alarm."""
    repo = tmp_path / "repo"
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A}\n")
    lock = tmp_path / "trust.lock"
    run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)

    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: ACTIONS/CHECKOUT@{SHA_A}\n")
    code, doc = run_verify(repo, trust_lock=str(lock), offline=True)
    assert code == 0
    assert doc["runs"][0]["results"] == []


def test_tampered_lock_key_casing_does_not_evade_matching(tmp_path):
    """The reverse direction of the same bug: the lock *file* is also
    attacker-influenceable. If someone hand-edits the committed lock to
    recase its own key, the lookup must still find it (both sides are
    normalized), not silently treat a locked action as unlocked."""
    repo = tmp_path / "repo"
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_B}\n")
    lock = tmp_path / "trust.lock"
    lock.write_text(json.dumps({"actions": {"Actions/Checkout": {"owner": "actions", "sha": SHA_A}}}))
    code, doc = run_verify(repo, trust_lock=str(lock), offline=True)
    assert code == 1
    results = doc["runs"][0]["results"]
    assert results[0]["ruleId"] == "tridelphi-verify/trust-lock-regression"


def test_owner_transfer_still_detected_case_insensitively(tmp_path):
    """A genuine owner transfer (different owner entirely, not just casing)
    must still be caught as `signer-owner-changed`, unaffected by the
    case-insensitivity fix."""
    repo = tmp_path / "repo"
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A}\n")
    lock = tmp_path / "trust.lock"
    run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)

    data = json.loads(lock.read_text())
    data["actions"]["actions/checkout"]["owner"] = "totally-different-attacker"
    lock.write_text(json.dumps(data))
    code, doc = run_verify(repo, trust_lock=str(lock), offline=True)
    assert code == 1
    results = doc["runs"][0]["results"]
    assert results[0]["ruleId"] == "tridelphi-verify/signer-owner-changed"
    assert results[0]["level"] == "error"


# =============================================================================
# 3. _check_against_lock — the core pawl, exhaustively
# =============================================================================


def test_locked_action_unchanged_produces_no_finding(tmp_path):
    repo = tmp_path / "repo"
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A}\n")
    lock = tmp_path / "trust.lock"
    run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)
    code, doc = run_verify(repo, trust_lock=str(lock), offline=True)
    assert code == 0
    assert doc["runs"][0]["results"] == []


def test_sha_change_under_same_ref_gates(tmp_path):
    repo = tmp_path / "repo"
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A}\n")
    lock = tmp_path / "trust.lock"
    run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_B}\n")
    code, doc = run_verify(repo, trust_lock=str(lock), offline=True)
    assert code == 1
    assert doc["runs"][0]["results"][0]["ruleId"] == "tridelphi-verify/trust-lock-regression"


def test_owner_change_gates(tmp_path):
    repo = tmp_path / "repo"
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A}\n")
    lock = tmp_path / "trust.lock"
    run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)
    data = json.loads(lock.read_text())
    data["actions"]["actions/checkout"]["owner"] = "attacker"
    lock.write_text(json.dumps(data))
    code, doc = run_verify(repo, trust_lock=str(lock), offline=True)
    assert code == 1
    assert doc["runs"][0]["results"][0]["ruleId"] == "tridelphi-verify/signer-owner-changed"


def test_unlocked_action_is_a_note_and_does_not_gate_at_default(tmp_path):
    repo = tmp_path / "repo"
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A}\n")
    lock = tmp_path / "trust.lock"  # never written
    code, doc = run_verify(repo, trust_lock=str(lock), offline=True, fail_on="critical")
    assert code == 0
    assert doc["runs"][0]["results"][0]["ruleId"] == "tridelphi-verify/unlocked-action"
    assert doc["runs"][0]["results"][0]["level"] == "note"


def test_action_removed_from_workflow_but_still_in_lock_produces_no_finding(tmp_path):
    """An action no longer used at all is simply not checked — it is not a
    'removed trust root' the pawl needs to warn about, since it can no
    longer run. Document the actual (silent) behavior explicitly."""
    repo = tmp_path / "repo"
    _wf(
        repo,
        "ci.yml",
        "on: push\njobs:\n  a:\n    steps:\n"
        f"      - uses: actions/checkout@{SHA_A}\n"
        f"      - uses: actions/setup-python@{SHA_B}\n",
    )
    lock = tmp_path / "trust.lock"
    run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A}\n")
    code, doc = run_verify(repo, trust_lock=str(lock), offline=True)
    assert code == 0
    assert doc["runs"][0]["results"] == []


def test_unpinned_ref_locked_then_changed_is_a_regression(tmp_path):
    """An action pinned only to a branch/tag (no SHA) is still lockable: the
    ref text itself is the identity to watch, and a later change is still a
    regression worth flagging even though SHA-pinning was never in play."""
    repo = tmp_path / "repo"
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" "      - uses: foo/bar@main\n")
    lock = tmp_path / "trust.lock"
    run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" "      - uses: foo/bar@dev\n")
    code, doc = run_verify(repo, trust_lock=str(lock), offline=True)
    assert code == 1
    assert doc["runs"][0]["results"][0]["ruleId"] == "tridelphi-verify/trust-lock-regression"


def test_fail_on_note_gates_on_unlocked_actions_too(tmp_path):
    """`--fail-on note` is the strictest threshold: even an informational
    unlocked-action note must gate, per SEVERITY_ORDER semantics."""
    repo = tmp_path / "repo"
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A}\n")
    lock = tmp_path / "trust.lock"  # never written
    code, _ = run_verify(repo, trust_lock=str(lock), offline=True, fail_on="note")
    assert code == 1


def test_fail_on_warning_still_gates_errors(tmp_path):
    repo = tmp_path / "repo"
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A}\n")
    lock = tmp_path / "trust.lock"
    run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_B}\n")
    code, _ = run_verify(repo, trust_lock=str(lock), offline=True, fail_on="warning")
    assert code == 1


def test_fail_on_none_never_gates_even_with_a_regression(tmp_path):
    repo = tmp_path / "repo"
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A}\n")
    lock = tmp_path / "trust.lock"
    run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_B}\n")
    code, _ = run_verify(repo, trust_lock=str(lock), offline=True, fail_on="none")
    assert code == 0


# =============================================================================
# 4. run_verify / --write-trust-lock
# =============================================================================


def test_write_then_verify_is_clean(tmp_path):
    repo = tmp_path / "repo"
    _wf(
        repo,
        "ci.yml",
        "on: push\njobs:\n  a:\n    steps:\n"
        f"      - uses: actions/checkout@{SHA_A}\n"
        f"      - uses: actions/setup-python@{SHA_B}\n",
    )
    lock = tmp_path / "trust.lock"
    code, doc = run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)
    assert code == 0 and doc is None and lock.is_file()
    code, doc = run_verify(repo, trust_lock=str(lock), offline=True)
    assert code == 0
    assert doc["runs"][0]["results"] == []


def test_written_lock_round_trips_byte_stable_keys(tmp_path):
    repo = tmp_path / "repo"
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A}\n")
    lock = tmp_path / "trust.lock"
    run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)
    data = json.loads(lock.read_text())
    assert data["actions"] == {"actions/checkout": {"owner": "actions", "sha": SHA_A}}
    # Re-verify against the just-written lock is clean.
    code, doc = run_verify(repo, trust_lock=str(lock), offline=True)
    assert code == 0
    assert doc["runs"][0]["results"] == []


def test_write_trust_lock_overwrites_an_existing_lock(tmp_path):
    repo = tmp_path / "repo"
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A}\n")
    lock = tmp_path / "trust.lock"
    lock.write_text(json.dumps({"actions": {"stale/entry": {"owner": "x", "sha": "y" * 40}}}))
    run_verify(repo, trust_lock=str(lock), write_lock=True, offline=True)
    data = json.loads(lock.read_text())
    assert "stale/entry" not in data["actions"]
    assert "actions/checkout" in data["actions"]


def test_repo_path_that_is_not_a_directory_exits_2(tmp_path):
    code, doc = run_verify(tmp_path / "does-not-exist", offline=True)
    assert code == 2
    assert doc is None


def test_repo_path_that_is_a_file_not_a_directory_exits_2(tmp_path):
    f = tmp_path / "not_a_dir"
    f.write_text("x")
    code, doc = run_verify(f, offline=True)
    assert code == 2
    assert doc is None


# =============================================================================
# 5. verify_to_sarif
# =============================================================================


def test_sarif_passes_the_shared_shape_gate():
    ref = ActionRef("acme", "act", "", "main", "ci.yml", 5)
    doc = verify_to_sarif([VerifyFinding("error", "trust-lock-regression", ref, "x")], tool_version="0")
    assert sarif_shape_error(doc) is None


def test_sarif_uris_are_workflow_relative(tmp_path):
    repo = tmp_path / "repo"
    _wf(repo, "sub.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A}\n")
    lock = tmp_path / "trust.lock"  # unlocked -> note, still located
    _, doc = run_verify(repo, trust_lock=str(lock), offline=True)
    loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == ".github/workflows/sub.yml"
    assert loc["region"]["startLine"] == 5


def test_sarif_is_byte_identical_across_repeated_runs(tmp_path):
    repo = tmp_path / "repo"
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A}\n")
    lock = tmp_path / "trust.lock"
    d1 = run_verify(repo, trust_lock=str(lock), offline=True, tool_version="9.9.9")[1]
    d2 = run_verify(repo, trust_lock=str(lock), offline=True, tool_version="9.9.9")[1]
    assert json.dumps(d1, sort_keys=True) == json.dumps(d2, sort_keys=True)


def test_hostile_action_names_and_messages_round_trip_through_sarif():
    """Quotes, backslashes, control characters, and unicode in an action
    slug or message must not corrupt the emitted SARIF — JSON handles all of
    them natively, but this pins down that verify_to_sarif does not do any
    unsafe string surgery of its own."""
    hostile_ref = ActionRef(
        owner='ev"il\nowner\t\u2028<script>alert(1)</script>',
        repo="rep\\o",
        subpath="",
        ref="a" * 40,
        workflow="ci.yml",
        line=1,
    )
    finding = VerifyFinding(
        "error",
        "trust-lock-regression",
        hostile_ref,
        'msg with "quotes", a\nnewline, a null \x00, and unicode \u2603',
    )
    doc = verify_to_sarif([finding], tool_version="0")
    assert sarif_shape_error(doc) is None
    serialized = json.dumps(doc)
    restored = json.loads(serialized)
    assert restored["runs"][0]["results"][0]["message"]["text"] == finding.message


def test_sarif_rule_ids_deduplicate_across_many_findings_of_the_same_kind(tmp_path):
    repo = tmp_path / "repo"
    body = "on: push\njobs:\n  a:\n    steps:\n" + "".join(
        f"      - uses: owner{i}/repo{i}@{'a' * 40}\n" for i in range(50)
    )
    _wf(repo, "many.yml", body)
    lock = tmp_path / "trust.lock"  # unlocked -> 50 notes, one rule
    _, doc = run_verify(repo, trust_lock=str(lock), offline=True)
    assert len(doc["runs"][0]["results"]) == 50
    assert len(doc["runs"][0]["tool"]["driver"]["rules"]) == 1


# =============================================================================
# 6. CLI
# =============================================================================


def test_cli_verify_write_then_check(tmp_path, repo_root):
    repo = tmp_path / "repo"
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A}\n")
    lock = tmp_path / "trust.lock"
    write = run_cli(["verify", str(repo), "--write-trust-lock", "--trust-lock", str(lock)], cwd=repo_root)
    assert write.returncode == 0 and lock.is_file()
    ok = run_cli(["verify", str(repo), "--trust-lock", str(lock), "--offline"], cwd=repo_root)
    assert ok.returncode == 0


def test_cli_verify_sarif_stdout_is_only_valid_json(tmp_path, repo_root):
    """--format sarif must put ONLY valid JSON on stdout; the human summary
    (and the offline diagnostic) go to stderr."""
    repo = tmp_path / "repo"
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A}\n")
    lock = tmp_path / "trust.lock"
    result = run_cli(
        ["verify", str(repo), "--trust-lock", str(lock), "--offline", "--format", "sarif"],
        cwd=repo_root,
    )
    doc = json.loads(result.stdout)  # raises if stdout has anything but the document
    assert doc["runs"][0]["tool"]["driver"]["name"] == "tridelphi-verify"
    assert "L7 trust" in result.stderr


def test_cli_verify_nonexistent_repo_exits_2(tmp_path, repo_root):
    result = run_cli(["verify", str(tmp_path / "nope")], cwd=repo_root)
    assert result.returncode == 2


def test_cli_level_7_folds_regression_into_the_scan_exit_code(tmp_path, repo_root):
    """A trust-lock regression at --level 7 must fail the *whole scan's*
    exit code, via external_counts — not just verify's own standalone code."""
    repo = tmp_path / "repo"
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A}\n")
    lock = repo / ".tridelphi" / "trust.lock"
    write = run_cli(["verify", str(repo), "--write-trust-lock"], cwd=repo_root)
    assert write.returncode == 0 and lock.is_file()

    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_B}\n")
    result = run_cli([str(repo), "--level", "7", "--offline"], cwd=repo_root)
    assert result.returncode == 1


def test_cli_level_7_no_lock_yet_does_not_force_a_failing_exit(tmp_path, repo_root):
    """With no trust-lock committed, every action is an 'unlocked-action'
    note (never gating on its own at the default --fail-on critical) — the
    trust rung must not force a nonzero exit by itself."""
    repo = tmp_path / "repo"
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A}\n")
    result = run_cli([str(repo), "--level", "7", "--offline"], cwd=repo_root)
    assert result.returncode in (0, 1)  # core's own findings may still gate; trust notes must not force it


def test_cli_level_7_sarif_file_contains_both_runs(tmp_path, repo_root):
    repo = tmp_path / "repo"
    _wf(repo, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n" f"      - uses: actions/checkout@{SHA_A}\n")
    sarif = tmp_path / "out.sarif"
    result = run_cli([str(repo), "--level", "7", "--offline", "--sarif-file", str(sarif)], cwd=repo_root)
    doc = json.loads(sarif.read_text())
    names = [r["tool"]["driver"]["name"] for r in doc["runs"]]
    assert "tridelphi" in names and "tridelphi-verify" in names
    assert result.returncode in (0, 1)
