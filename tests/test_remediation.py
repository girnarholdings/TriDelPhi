"""The cheapest fix is a first-class deliverable, so it gets a linter.

A free-text field with no obligations produces "consider reducing permissions to
the minimum required" — true, unactionable, and indistinguishable from every
tool the user has already muted. These tests encode what separates a usable fix
from a templated one: a concrete location, a verbatim source token, and a
statement of what breaks.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tridelphi.api import analyze

BANNED = (
    "the minimum required",
    "consider ",
    "as appropriate",
    "best practice",
    "secrets.*",
    "review this",
)

FIXTURES = sorted(
    p
    for bucket in ("malicious", "two_cap")
    for p in (Path("tests/fixtures") / bucket).iterdir()
    if p.is_dir()
)


def _remediations():
    for repo in FIXTURES:
        for finding in analyze(repo).findings:
            if finding.remediation is not None:
                yield repo.name, finding


def test_every_gating_finding_offers_a_fix():
    missing = [
        f"{repo.name}::{f.context.job_id} ({f.rule_id})"
        for repo in FIXTURES
        for f in analyze(repo).findings
        if f.severity in ("critical", "warning") and f.remediation is None
    ]
    assert not missing, f"no remediation for: {missing}"


def test_fix_text_is_specific():
    for name, finding in _remediations():
        text = finding.remediation.rendered
        lowered = text.lower()
        for phrase in BANNED:
            assert phrase not in lowered, f"{name}: generic phrase {phrase!r} in fix"
        assert re.search(r"[\w./-]+\.ya?ml:\d+", text), (
            f"{name}: fix names no file:line — {text[:120]}"
        )
        assert "`" in text, f"{name}: fix quotes no concrete token"
        assert len(text) > 120, f"{name}: fix is too short to be actionable"


def test_fix_states_what_breaks():
    for name, finding in _remediations():
        assert finding.remediation.breaks.strip(), f"{name}: 'breaks' is empty"


def test_fix_names_a_real_capability():
    for name, finding in _remediations():
        strip = finding.remediation.strip
        assert strip in ("U", "P", "E")
        assert strip in set(finding.capabilities()), (
            f"{name}: proposes stripping {strip}, which the finding does not hold"
        )


def test_expression_injection_prefers_env_indirection():
    """The one-line fix that breaks nothing should win over narrowing a trigger
    or removing a credential."""
    result = analyze("tests/fixtures/malicious/issue-to-write-token")
    finding = next(f for f in result.findings if f.severity == "critical")
    assert finding.remediation.strip == "U"
    assert finding.remediation.kind == "env-indirect"
    assert "env:" in finding.remediation.rendered


def test_agent_prompt_fix_explains_semantic_injection():
    """Telling someone to escape a prompt is wrong advice; the fix must say so."""
    result = analyze("tests/fixtures/malicious/comment-and-control")
    finding = next(f for f in result.findings if f.severity == "critical")
    assert "author_association" in finding.remediation.rendered
    assert "semantic" in finding.remediation.rendered.lower()


def test_self_hosted_fix_does_not_suggest_permissions():
    """No `permissions:` change helps when the runner itself is the exposure."""
    result = analyze("tests/fixtures/malicious/self-hosted-runner-takeover")
    finding = next(f for f in result.findings if f.severity == "critical")
    assert finding.remediation.kind == "narrow-runner"
    assert "ephemeral" in finding.remediation.rendered
