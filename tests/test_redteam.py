"""The red-team corpus as a standing regression gate.

`scripts/redteam.py` is the interactive brute-forcer; this pins its two
invariants into CI so a future change that opens an evasion path, or that starts
crying wolf on a benign near-miss, turns the build red.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from redteam_corpus import attack_cases, control_cases

from tridelphi.api import analyze


def _gating(findings):
    return [f for f in findings if f.severity in ("critical", "warning")]


def _analyze_case(case):
    with tempfile.TemporaryDirectory() as tmp:
        return analyze(case.materialize(Path(tmp)))


@pytest.mark.parametrize("case", attack_cases(), ids=lambda c: c.name)
def test_every_attack_shape_is_caught(case):
    """A miss here is the encoding an attacker would reach for to evade us."""
    result = _analyze_case(case)
    gating = _gating(result.findings)
    rules = {f.rule_id for f in gating}
    assert gating, f"{case.name}: attack shape produced no gating finding"
    assert any(case.expect_rule in r for r in rules), (
        f"{case.name}: expected a rule containing {case.expect_rule!r}, got {sorted(rules)}"
    )


@pytest.mark.parametrize("case", control_cases(), ids=lambda c: c.name)
def test_every_control_stays_clean(case):
    """A false positive on a benign near-miss is how a tool gets uninstalled."""
    result = _analyze_case(case)
    offenders = _gating(result.findings)
    assert not offenders, (
        f"{case.name}: benign near-miss was flagged: "
        + "; ".join(f"{f.severity} {f.rule_id}" for f in offenders)
    )


def test_corpus_has_real_breadth():
    """Guard against the corpus silently shrinking to a token set."""
    assert len(attack_cases()) >= 50, "the sweep must cover many payload encodings"
    assert len(control_cases()) >= 5


def test_restored_config_is_never_named_as_ingress():
    """The restore-semantics moat, asserted directly.

    An agent over an untrusted checkout is critical because it reviews the diff —
    but the finding must NOT claim CLAUDE.md is attacker-controlled, since the
    action restores it from base. Naming it would be a false-cause: the right
    file to name is the untrusted worktree, not the restored config.
    """
    case = next(
        c for c in attack_cases() if "restored-CLAUDE.md" in c.name
    )
    result = _analyze_case(case)
    critical = next(f for f in result.findings if f.severity == "critical")
    u_reasons = " ".join(h.reason for h in critical.hits if h.capability == "U")
    assert "pull request code" in u_reasons, "must flag the untrusted worktree"
    assert "CLAUDE.md" not in u_reasons, (
        "claude-code-action restores CLAUDE.md from base; naming it as ingress "
        "is a false-cause finding"
    )


def test_object_filter_and_bracket_encodings_are_covered():
    """The evasion encodings most likely to slip a naive matcher must be in the
    corpus, not just the plain dotted paths."""
    from redteam_corpus import UNTRUSTED_PAYLOADS

    joined = " ".join(UNTRUSTED_PAYLOADS)
    assert "github.event.*.body" in joined, "object-filter syntax"
    assert "commits.0.message" in joined, "array indexing"
