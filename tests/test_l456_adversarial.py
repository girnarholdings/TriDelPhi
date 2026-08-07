"""Red-team L4-L6: the scorecard adapter, the gate/attest processes, and the
CLI dispatch that wires them up.

Three new attack surfaces this cycle:

* ``ladder._scorecard_to_sarif`` converts scorecard's local-mode JSON (plain
  JSON on stdout, not SARIF) into a SARIF run. scorecard reads repo files, so
  its output is attacker-influenceable the same way gitleaks/osv-scanner's is
  in test_ladder_adversarial.py -- but here the *shape* of the untrusted input
  is JSON-that-isn't-SARIF-yet, and the adapter itself must not trust a single
  field of it.
* ``gate_cmd.run_gate``/``run_attest`` both take an untrusted SARIF *path* as
  their whole argument -- the file could be attacker-influenced ladder output,
  a hostile hand-crafted document, or garbage. Both are separate processes
  from the scan (that is the L6 design), so they re-validate from scratch.
* CLI dispatch: ``gate``/``attest`` as the literal first positional argument
  collide with the same string used as a scan path.

Every attack below must either be contained (diagnostic / non-zero-but-defined
exit code, never a crash or hang) or, for the scorecard adapter, produce a
structurally valid SARIF document that ``sarif_shape_error`` accepts.
"""

from __future__ import annotations

import hashlib
import io
import json

import pytest
from conftest import run_cli

from tridelphi.gate_cmd import EVIDENCE_PREDICATE_TYPE, run_attest, run_gate
from tridelphi.ladder import SCORECARD, ExternalRun, _scorecard_to_sarif
from tridelphi.orchestrate import MAX_OUTPUT_BYTES, sarif_shape_error

# =============================================================================
# 1. _scorecard_to_sarif
# =============================================================================


def _checks_doc(checks, *, version=None):
    doc = {"checks": checks}
    if version is not None:
        doc["scorecard"] = {"version": version}
    return json.dumps(doc)


def _convert(raw):
    out = _scorecard_to_sarif(SCORECARD, raw)
    assert not isinstance(out, ExternalRun), (
        "expected a document, got a skip diagnostic: "
        f"{out.diagnostic.message if isinstance(out, ExternalRun) else out}"
    )
    assert sarif_shape_error(out) is None, "converter fed the shape gate a malformed document"
    return out


def _results_by_rule(doc):
    return {r["ruleId"]: r for r in doc["runs"][0]["results"]}


# --- severity boundary: prove 0, 3, 4, 7, 8, -1 exactly ----------------------


@pytest.mark.parametrize(
    ("score", "expected_level"),
    [
        (0, "warning"),
        (3, "warning"),
        (4, "note"),
        (7, "note"),
        (8, None),  # 8+ dropped entirely
        (-1, None),  # not-applicable, dropped
    ],
)
def test_scorecard_score_boundary_is_exact(score, expected_level):
    raw = _checks_doc([{"name": "Check", "score": score, "reason": "r"}])
    doc = _convert(raw)
    results = _results_by_rule(doc)
    if expected_level is None:
        assert results == {}
    else:
        assert results["scorecard/Check"]["level"] == expected_level


@pytest.mark.parametrize("score", [-2, -10, -999])
def test_scorecard_any_negative_other_than_minus_one_is_also_dropped(score):
    raw = _checks_doc([{"name": "Check", "score": score, "reason": "r"}])
    doc = _convert(raw)
    assert _results_by_rule(doc) == {}


def test_scorecard_huge_positive_score_is_dropped_not_crashed():
    raw = _checks_doc([{"name": "Check", "score": 10**12, "reason": "r"}])
    doc = _convert(raw)
    assert _results_by_rule(doc) == {}


# --- score type confusion ----------------------------------------------------


@pytest.mark.parametrize(
    "score_literal",
    ["5.5", "null", '"5"', '"warning"', "[]", "{}"],
)
def test_scorecard_non_int_score_types_are_skipped_not_crashed(score_literal):
    """float / string / null / list / dict scores must be excluded from the
    document (not coerced, not crashed on) -- only a real ``int`` is trusted."""
    raw = f'{{"checks": [{{"name": "Check", "score": {score_literal}, "reason": "r"}}]}}'
    doc = _convert(raw)
    assert _results_by_rule(doc) == {}


def test_scorecard_missing_score_field_is_skipped():
    raw = _checks_doc([{"name": "Check", "reason": "r"}])
    doc = _convert(raw)
    assert _results_by_rule(doc) == {}


def test_scorecard_bool_score_is_excluded_not_coerced():
    """``isinstance(True, int)`` is True in Python, so a JSON boolean score
    would slip the int gate and read as 0/1. The converter excludes bool
    explicitly: a hostile ``"score": true`` produces no finding at all rather
    than a spurious warning."""
    for literal in ("true", "false"):
        raw = f'{{"checks": [{{"name": "Check", "score": {literal}, "reason": "r"}}]}}'
        doc = _convert(raw)
        assert doc["runs"][0]["results"] == []


# --- checks list containing garbage entries ----------------------------------


def test_scorecard_non_dict_check_entries_are_filtered_out():
    raw = json.dumps(
        {
            "checks": [
                1,
                "a string",
                None,
                [],
                True,
                {"name": "Real-Check", "score": 2, "reason": "kept"},
            ]
        }
    )
    doc = _convert(raw)
    results = _results_by_rule(doc)
    assert list(results.keys()) == ["scorecard/Real-Check"]


def test_scorecard_checks_as_a_dict_not_a_list_is_rejected():
    """``checks`` must be a list; a dict (truthy, and iterable-of-keys if code
    were careless) must be caught explicitly, same posture as
    ``sarif_shape_error``'s own ``runs``-as-dict test."""
    raw = json.dumps({"checks": {"Foo": {"score": 1}}})
    out = _scorecard_to_sarif(SCORECARD, raw)
    assert isinstance(out, ExternalRun) and not out.ok
    assert "no checks list" in out.diagnostic.message


def test_scorecard_checks_as_a_string_is_rejected():
    out = _scorecard_to_sarif(SCORECARD, json.dumps({"checks": "not-a-list"}))
    assert isinstance(out, ExternalRun) and not out.ok


def test_scorecard_top_level_not_a_dict_is_rejected():
    for payload in ("[]", "42", "null", '"scorecard"'):
        out = _scorecard_to_sarif(SCORECARD, payload)
        assert isinstance(out, ExternalRun) and not out.ok, payload


def test_scorecard_non_json_is_rejected():
    out = _scorecard_to_sarif(SCORECARD, "\x00not json {{{ garbage")
    assert isinstance(out, ExternalRun) and not out.ok
    assert "not valid JSON" in out.diagnostic.message


# --- name field: injection characters, absurd length, duplicates ------------


def test_scorecard_name_with_sarif_injection_characters_stays_contained():
    """A name containing quote/backslash/newline/control characters must not
    corrupt the surrounding document -- it is built as Python dict values and
    only serialized to JSON text downstream (never string-concatenated), so
    this is a containment *proof*, not a fix; verify the round trip explicitly
    rather than assuming it."""
    hostile_name = 'Weird"Name\\with\nnewlines\tand\x00nulls'
    raw = _checks_doc([{"name": hostile_name, "score": 1, "reason": "r"}])
    doc = _convert(raw)
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["name"] == hostile_name.replace("-", "")
    # Round-trip through real JSON serialization: no corruption, no injected
    # sibling keys, no truncation.
    reparsed = json.loads(json.dumps(doc))
    assert reparsed == doc


def test_scorecard_name_with_unicode_and_rtl_override_is_contained():
    hostile_name = "Check\u202e\u0000\U0001f600"  # RTL override + NUL + emoji
    raw = _checks_doc([{"name": hostile_name, "score": 1, "reason": "r"}])
    doc = _convert(raw)
    reparsed = json.loads(json.dumps(doc))
    assert reparsed == doc


def test_scorecard_absurdly_long_name_does_not_crash():
    hostile_name = "X" * 200_000
    raw = _checks_doc([{"name": hostile_name, "score": 1, "reason": "r"}])
    doc = _convert(raw)
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert len(rule["id"]) > 200_000
    assert json.loads(json.dumps(doc)) == doc


def test_scorecard_unicode_control_chars_in_reason_are_contained():
    hostile_reason = "bad\x00\x1b[31mnull-and-ansi\u202e\U0001f600"
    raw = _checks_doc([{"name": "Check", "score": 1, "reason": hostile_reason}])
    doc = _convert(raw)
    message = doc["runs"][0]["results"][0]["message"]["text"]
    assert hostile_reason in message
    assert json.loads(json.dumps(doc)) == doc


def test_scorecard_duplicate_name_emits_one_rule_but_keeps_each_result():
    """Two checks with the same ``name`` (attacker-crafted scorecard-json, or
    a future scorecard bug) must not muddy the tool metadata with duplicate
    rule entries. The rule is emitted once; each check still becomes its own
    result referencing that shared ruleId."""
    raw = _checks_doc(
        [
            {"name": "Dup-Check", "score": 1, "reason": "first"},
            {"name": "Dup-Check", "score": 2, "reason": "second"},
        ]
    )
    doc = _convert(raw)
    ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
    assert ids.count("scorecard/Dup-Check") == 1
    result_ids = [r["ruleId"] for r in doc["runs"][0]["results"]]
    assert result_ids.count("scorecard/Dup-Check") == 2


# --- scorecard.version ---------------------------------------------------


def test_scorecard_missing_version_defaults_to_unknown():
    raw = _checks_doc([{"name": "Check", "score": 1, "reason": "r"}])  # no "scorecard" key
    doc = _convert(raw)
    assert doc["runs"][0]["tool"]["driver"]["semanticVersion"] == "unknown"


@pytest.mark.parametrize("bad_meta", ['"not-a-dict"', "[]", "null", "42"])
def test_scorecard_malformed_meta_block_defaults_to_unknown(bad_meta):
    raw = f'{{"scorecard": {bad_meta}, "checks": [{{"name": "Check", "score": 1, "reason": "r"}}]}}'
    doc = _convert(raw)
    assert doc["runs"][0]["tool"]["driver"]["semanticVersion"] == "unknown"


@pytest.mark.parametrize("bad_version", ["null", "5", "5.5", "[]", "{}"])
def test_scorecard_non_string_version_defaults_to_unknown(bad_version):
    raw = (
        f'{{"scorecard": {{"version": {bad_version}}}, '
        f'"checks": [{{"name": "Check", "score": 1, "reason": "r"}}]}}'
    )
    doc = _convert(raw)
    assert doc["runs"][0]["tool"]["driver"]["semanticVersion"] == "unknown"


def test_scorecard_deterministic_ordering_survives_hostile_names():
    """Sort key is ``str(c.get("name", ""))`` -- verify hostile/odd names sort
    stably and the whole document is byte-identical across repeated
    conversions, matching the determinism claim in test_ladder_l456.py but
    against attacker-shaped names instead of clean ones."""
    checks = [
        {"name": "\u202ereversed", "score": 1, "reason": "a"},
        {"name": "", "score": 2, "reason": "b"},
        {"name": "ZZZ", "score": 1, "reason": "c"},
        {"name": "aaa", "score": 2, "reason": "d"},
    ]
    raw = json.dumps({"checks": checks})
    a = _convert(raw)
    b = _convert(raw)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# =============================================================================
# 2. gate_cmd.run_gate / run_attest
# =============================================================================


def _write(path, obj):
    text = obj if isinstance(obj, str) else json.dumps(obj)
    path.write_text(text)
    return path


def _gate(path, fail_on="critical"):
    out, err = io.StringIO(), io.StringIO()
    code = run_gate(str(path), fail_on=fail_on, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def _sarif(runs):
    """``runs`` is a list of (tool_name, [results]) pairs."""
    return {
        "version": "2.1.0",
        "runs": [
            {"tool": {"driver": {"name": name}}, "results": results} for name, results in runs
        ],
    }


def _levels(*levels):
    return [{"level": lvl} for lvl in levels]


# --- malformed shapes: gate rejects the whole document, never crashes -------


@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        "[]",
        "42",
        "null",
        '{"version": "2.1.0"}',
        '{"version": "2.1.0", "runs": "not-a-list"}',
        '{"version": "2.1.0", "runs": {"results": []}}',
        '{"version": "2.1.0", "runs": ["not-a-dict"]}',
        '{"version": "2.1.0", "runs": [{"tool": {"driver": {}}, "results": "x"}]}',
        '{"version": "2.1.0", "runs": [{"tool": {"driver": {}}, "results": ["x"]}]}',
        '{"version": "2.1.0", "runs": [{"results": []}]}',
        '{"version": "2.1.0", "runs": [{"tool": "x", "results": []}]}',
        '{"version": "2.1.0", "runs": [{"tool": {"driver": "x"}, "results": []}]}',
        (
            '{"version": "2.1.0", "runs": ['
            '{"tool": {"driver": {}}, "results": []}, "not-a-dict"]}'
        ),
    ],
)
def test_gate_rejects_every_malformed_sarif_shape(tmp_path, payload):
    path = _write(tmp_path / "s.sarif", payload)
    code, out, err = _gate(path)
    assert code == 2
    assert out == ""
    assert err != ""


@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        "[]",
        '{"version": "2.1.0", "runs": [{"tool": {"driver": {}}, "results": "x"}]}',
    ],
)
def test_attest_rejects_every_malformed_sarif_shape_too(tmp_path, payload):
    path = _write(tmp_path / "s.sarif", payload)
    out, err = io.StringIO(), io.StringIO()
    ev = tmp_path / "ev.json"
    code = run_attest(str(path), evidence_path=str(ev), out=out, err=err)
    assert code == 2
    assert not ev.exists()


def test_gate_second_run_malformed_rejects_whole_document(tmp_path):
    """A hostile SARIF could front-load one clean run to look valid and hide
    the poison later in ``runs`` -- gate must reject the whole file, not
    gate on a partial read."""
    payload = (
        '{"version": "2.1.0", "runs": ['
        '{"tool": {"driver": {"name": "clean"}}, "results": []}, '
        '"not-a-dict"]}'
    )
    path = _write(tmp_path / "s.sarif", payload)
    assert _gate(path)[0] == 2


def test_gate_empty_runs_list_passes_at_every_fail_on(tmp_path):
    path = _write(tmp_path / "s.sarif", _sarif([]))
    for fail_on in ("critical", "warning", "note", "none"):
        assert _gate(path, fail_on=fail_on)[0] == 0


# --- oversized input ---------------------------------------------------------


def test_gate_rejects_file_over_the_size_cap(tmp_path):
    path = tmp_path / "big.sarif"
    path.write_bytes(b"0" * (MAX_OUTPUT_BYTES + 1))
    code, _out, err = _gate(path)
    assert code == 2
    assert "exceeds the size limit" in err


def test_gate_file_exactly_at_the_size_cap_reaches_json_parse(tmp_path):
    """Boundary is "over", not "at or over" -- a file of exactly
    MAX_OUTPUT_BYTES must not be refused on size alone (padding content still
    fails JSON parsing, but the failure must be the parse error, not the size
    guard, proving where the boundary actually sits)."""
    path = tmp_path / "big.sarif"
    path.write_bytes(b"0" * MAX_OUTPUT_BYTES)
    code, _out, err = _gate(path)
    assert code == 2
    assert "exceeds the size limit" not in err
    assert "not valid JSON" in err


def test_attest_rejects_file_over_the_size_cap(tmp_path):
    path = tmp_path / "big.sarif"
    path.write_bytes(b"0" * (MAX_OUTPUT_BYTES + 1))
    out, err = io.StringIO(), io.StringIO()
    ev = tmp_path / "ev.json"
    code = run_attest(str(path), evidence_path=str(ev), out=out, err=err)
    assert code == 2
    assert not ev.exists()


def test_gate_rejects_a_directory_as_the_sarif_path(tmp_path):
    code, _out, err = _gate(tmp_path)
    assert code == 2
    assert "is not a file" in err


def test_gate_rejects_a_missing_path(tmp_path):
    assert _gate(tmp_path / "does-not-exist.sarif")[0] == 2


# --- non-SARIF-level ``level`` values never crash the gate -------------------


@pytest.mark.parametrize(
    "level_literal",
    ["null", "123", "3.5", '["nested"]', "{}", '"informational"', "true"],
)
def test_gate_non_standard_level_counts_as_warning_default(tmp_path, level_literal):
    """Anything that is not one of the four real SARIF level strings --
    including a non-string type -- must fall back to the SARIF default,
    "warning", and never raise. Mirrors the same contract already proven for
    the ladder's own ``ExternalRun`` severity accounting, but here at the
    gate boundary where the SARIF arrives as an independent file, not
    produced by ``run_tool`` in-process."""
    payload = (
        '{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}, '
        f'"results": [{{"ruleId": "a", "level": {level_literal}}}]}}]}}'
    )
    path = _write(tmp_path / "s.sarif", payload)
    code, out, _err = _gate(path, fail_on="warning")
    assert code == 1  # counted as a warning, which meets fail-on warning
    assert "1 warning" in out
    code_critical_only, _, _ = _gate(path, fail_on="critical")
    assert code_critical_only == 0  # not miscounted as critical


# --- exit code matrix: 0 pass / 1 fail / 2 unreadable, across fail-on --------


@pytest.mark.parametrize(
    ("severities", "fail_on", "expected_exit"),
    [
        # Single critical: blocks at every threshold except "none".
        (["error"], "critical", 1),
        (["error"], "warning", 1),
        (["error"], "note", 1),
        (["error"], "none", 0),
        # Single warning: blocks at warning/note, not at critical.
        (["warning"], "critical", 0),
        (["warning"], "warning", 1),
        (["warning"], "note", 1),
        (["warning"], "none", 0),
        # Single note: blocks only at note.
        (["note"], "critical", 0),
        (["note"], "warning", 0),
        (["note"], "note", 1),
        (["note"], "none", 0),
        # SARIF's own "none" level maps to the "note" severity bucket, not
        # "no findings" -- prove it is not silently dropped.
        (["none"], "critical", 0),
        (["none"], "note", 1),
        # Clean run: always passes regardless of fail-on.
        ([], "critical", 0),
        ([], "none", 0),
    ],
)
def test_gate_exit_code_matrix(tmp_path, severities, fail_on, expected_exit):
    path = _write(tmp_path / "s.sarif", _sarif([("tool", _levels(*severities))]))
    code, _out, _err = _gate(path, fail_on=fail_on)
    assert code == expected_exit


def test_gate_fail_on_none_passes_even_with_many_criticals(tmp_path):
    many_criticals = _levels(*(["error"] * 500))
    path = _write(tmp_path / "s.sarif", _sarif([("gitleaks", many_criticals)]))
    code, out, _err = _gate(path, fail_on="none")
    assert code == 0
    assert "pass" in out


# --- summation across multiple runs ------------------------------------------


def test_gate_sums_severities_across_many_runs(tmp_path):
    doc = _sarif(
        [
            ("tridelphi", _levels("error")),
            ("gitleaks", _levels("error", "error")),
            ("zizmor", _levels("warning", "warning", "warning")),
            ("scorecard", _levels("note", "note", "note", "note")),
        ]
    )
    path = _write(tmp_path / "s.sarif", doc)

    code, out, _ = _gate(path, fail_on="critical")
    assert code == 1
    assert "3 findings" in out  # 1 + 2 criticals across two runs

    code, out, _ = _gate(path, fail_on="warning")
    assert code == 1
    assert "6 findings" in out  # 3 criticals + 3 warnings

    code, out, _ = _gate(path, fail_on="note")
    assert code == 1
    assert "10 findings" in out  # everything

    code, out, _ = _gate(path, fail_on="none")
    assert code == 0


def test_gate_per_tool_lines_report_each_runs_own_counts(tmp_path):
    doc = _sarif([("toolA", _levels("error")), ("toolB", _levels("warning", "note"))])
    path = _write(tmp_path / "s.sarif", doc)
    _, out, _ = _gate(path, fail_on="note")
    assert "toolA: 1 critical" in out
    assert "toolB: 1 warning, 1 note" in out


# --- attest: digest correctness and determinism ------------------------------


def test_attest_subject_digest_matches_file_bytes_exactly(tmp_path):
    sarif = _write(tmp_path / "s.sarif", _sarif([("tridelphi", _levels("error"))]))
    ev = tmp_path / "ev.json"
    assert run_attest(str(sarif), evidence_path=str(ev)) == 0
    stmt = json.loads(ev.read_text())
    expected = hashlib.sha256(sarif.read_bytes()).hexdigest()
    assert stmt["subject"][0]["digest"]["sha256"] == expected
    assert stmt["subject"][0]["name"] == sarif.name


def test_attest_digest_changes_when_a_single_byte_changes(tmp_path):
    """Sanity check on the digest binding itself: a one-byte edit to the SARIF
    (e.g. an attacker altering a finding after the scan but before attest)
    must change the subject digest -- proving the attestation is actually
    over the file's real bytes, not a re-derived or cached value."""
    sarif = _write(tmp_path / "s.sarif", _sarif([("tridelphi", _levels("error"))]))
    ev1 = tmp_path / "ev1.json"
    run_attest(str(sarif), evidence_path=str(ev1))
    digest1 = json.loads(ev1.read_text())["subject"][0]["digest"]["sha256"]

    sarif.write_text(sarif.read_text() + " ")  # single whitespace byte appended
    ev2 = tmp_path / "ev2.json"
    run_attest(str(sarif), evidence_path=str(ev2))
    digest2 = json.loads(ev2.read_text())["subject"][0]["digest"]["sha256"]

    assert digest1 != digest2


def test_attest_is_deterministic_across_unrelated_env_noise(tmp_path, monkeypatch):
    """Only GITHUB_REPOSITORY/GITHUB_SHA are meant to influence the statement.
    Vary everything else that could plausibly leak (temp dirs, locale, a
    second GitHub Actions run of the *same* commit with a different run id)
    and confirm byte-for-byte identical output."""
    sarif = _write(tmp_path / "s.sarif", _sarif([("tridelphi", _levels("error", "warning"))]))
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    monkeypatch.setenv("GITHUB_SHA", "deadbeef")

    monkeypatch.setenv("GITHUB_RUN_ID", "111111")
    monkeypatch.setenv("RUNNER_TEMP", "/tmp/run-one")
    monkeypatch.setenv("TZ", "UTC")
    e1 = tmp_path / "e1.json"
    run_attest(str(sarif), evidence_path=str(e1))

    monkeypatch.setenv("GITHUB_RUN_ID", "999999999")  # different run of same commit
    monkeypatch.setenv("RUNNER_TEMP", "/tmp/completely/different/path")
    monkeypatch.setenv("TZ", "America/Los_Angeles")
    e2 = tmp_path / "e2.json"
    run_attest(str(sarif), evidence_path=str(e2))

    assert e1.read_text() == e2.read_text()


def test_attest_predicate_leaks_no_unrelated_env_vars(tmp_path, monkeypatch):
    """Only ``repository``/``commit`` are documented as populated from the
    environment. Prove nothing else -- run id, actor, a secret-shaped env var
    -- leaks into the evidence file."""
    sarif = _write(tmp_path / "s.sarif", _sarif([("tridelphi", _levels("error"))]))
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    monkeypatch.setenv("GITHUB_SHA", "deadbeef")
    monkeypatch.setenv("GITHUB_RUN_ID", "should-not-appear-12345")
    monkeypatch.setenv("GITHUB_ACTOR", "should-not-appear-actor")
    monkeypatch.setenv("SUPER_SECRET_TOKEN", "should-not-appear-secret-xyz")
    ev = tmp_path / "ev.json"
    run_attest(str(sarif), evidence_path=str(ev))
    raw = ev.read_text()
    assert "should-not-appear" not in raw


def test_attest_predicate_type_and_scanner_block_are_present(tmp_path):
    sarif = _write(tmp_path / "s.sarif", _sarif([("tridelphi", [])]))
    ev = tmp_path / "ev.json"
    run_attest(str(sarif), evidence_path=str(ev))
    stmt = json.loads(ev.read_text())
    assert stmt["predicateType"] == EVIDENCE_PREDICATE_TYPE
    assert stmt["predicate"]["scanner"]["name"] == "tridelphi"
    assert "no-timestamp" not in stmt["predicate"] and "timestamp" not in stmt["predicate"]


# =============================================================================
# 3. CLI dispatch
# =============================================================================


def test_cli_gate_with_no_arg_exits_2_with_a_message(repo_root):
    result = run_cli(["gate"], cwd=repo_root)
    assert result.returncode == 2
    assert "needs a SARIF file" in result.stderr
    assert result.stdout == ""


def test_cli_attest_with_no_arg_exits_2_with_a_message(repo_root):
    result = run_cli(["attest"], cwd=repo_root)
    assert result.returncode == 2
    assert "needs a SARIF file" in result.stderr
    assert result.stdout == ""


def test_cli_gate_target_that_is_a_directory_exits_2(tmp_path, repo_root):
    result = run_cli(["gate", str(tmp_path)], cwd=repo_root)
    assert result.returncode == 2
    assert "is not a file" in result.stderr


def test_cli_attest_target_that_is_a_directory_exits_2(tmp_path, repo_root):
    result = run_cli(["attest", str(tmp_path)], cwd=repo_root)
    assert result.returncode == 2
    assert "is not a file" in result.stderr


def test_cli_path_literally_named_gate_is_the_subcommand_not_a_scan(tmp_path):
    """A repo whose scan target is a directory literally named "gate" hits the
    subcommand branch, not a scan, when invoked as the bare first positional
    argument -- this is the CLI's documented ambiguity (gate/attest are
    reserved first-argument words), not a crash: it degrades to the same
    "needs a SARIF file" exit 2 as any other bare ``gate`` invocation, and the
    directory is reachable by prefixing the path (``./gate``)."""
    gate_dir = tmp_path / "gate"
    (gate_dir / ".github" / "workflows").mkdir(parents=True)
    (gate_dir / ".github" / "workflows" / "ok.yml").write_text(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n"
    )

    literal = run_cli(["gate"], cwd=tmp_path)
    assert literal.returncode == 2
    assert "needs a SARIF file" in literal.stderr

    prefixed = run_cli(["./gate"], cwd=tmp_path)
    assert prefixed.returncode == 0
    assert "1 workflow" in prefixed.stdout


def test_cli_path_literally_named_attest_is_the_subcommand_not_a_scan(tmp_path):
    attest_dir = tmp_path / "attest"
    (attest_dir / ".github" / "workflows").mkdir(parents=True)
    (attest_dir / ".github" / "workflows" / "ok.yml").write_text(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n"
    )

    literal = run_cli(["attest"], cwd=tmp_path)
    assert literal.returncode == 2
    assert "needs a SARIF file" in literal.stderr

    prefixed = run_cli(["./attest"], cwd=tmp_path)
    assert prefixed.returncode == 0
    assert "1 workflow" in prefixed.stdout


def test_cli_level_6_without_sarif_file_skips_attest_gracefully(tmp_path, repo_root):
    """--level 6 needs a SARIF file on disk to attest over (the attest half
    reads a file path, not the in-memory document). Without --sarif-file it
    must degrade to a diagnostic, never crash, and the scan's own exit code
    must still be governed by --fail-on, not by the skipped attest step."""
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ok.yml").write_text(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n"
    )
    result = run_cli([str(tmp_path), "--level", "6", "--offline"], cwd=repo_root)
    assert "attestation needs --sarif-file; skipped" in result.stderr
    assert result.returncode in (0, 1)  # governed by findings, not by the skip


def test_cli_level_6_evidence_file_matches_direct_run_attest(tmp_path, repo_root):
    """--level 6 with --sarif-file must write byte-identical evidence to
    calling run_attest directly over the same SARIF (same env)."""
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ok.yml").write_text(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n"
    )
    sarif_path = tmp_path / "out.sarif"
    ev_path = tmp_path / "ev.json"
    result = run_cli(
        [str(tmp_path), "--level", "6", "--offline", "--sarif-file", str(sarif_path),
         "--evidence-file", str(ev_path)],
        cwd=repo_root,
    )
    assert result.returncode in (0, 1)
    assert sarif_path.is_file() and ev_path.is_file()

    ev_direct = tmp_path / "ev_direct.json"
    run_attest(str(sarif_path), evidence_path=str(ev_direct))
    assert ev_path.read_text() == ev_direct.read_text()
