"""The acceptance bar. If this file is red, v1 is not done.

The original bar was circular — fixtures authored from our threat model,
asserted against detectors built from the same threat model, which proves only
that our matcher matches our fixture. Two additions make it falsifiable:
``test_false_positive_budget`` (over-firing on ordinary code) and
``test_dogfood`` (our own repository, including the README's CI snippet).
"""

from __future__ import annotations

import pytest
from conftest import gating

from tridelphi.api import analyze

EXPECTED_CRITICAL = {
    "comment-and-control": "tridelphi/agent-prompt-injection",
    "issue-to-write-token": "tridelphi/expression-injection-privileged",
    "agent-config-poisoning": "tridelphi/agent-config-ingress",
    "cross-job-laundering": "tridelphi/cross-job-untrusted-flow",
    "self-hosted-runner-takeover": "tridelphi/untrusted-checkout-privileged-egress",
}

EXPECTED_STRIP = {
    "up-no-egress": "U",
    "ue-no-privilege": "U",
    # A removed guardrail is reported as privilege to strip: narrow who may
    # invoke the agent and which tools it gets.
    "agent-overbroad-tools": "P",
}


def test_malicious_is_critical(malicious_repo):
    result = analyze(malicious_repo)
    criticals = [f for f in result.findings if f.severity == "critical"]
    assert criticals, f"{malicious_repo.name}: expected a critical finding, got none"

    expected = EXPECTED_CRITICAL[malicious_repo.name]
    assert expected in {f.rule_id for f in criticals}, (
        f"{malicious_repo.name}: expected {expected}, got "
        f"{sorted({f.rule_id for f in criticals})}"
    )


def test_malicious_message_names_all_three(malicious_repo):
    result = analyze(malicious_repo)
    for finding in (f for f in result.findings if f.severity == "critical"):
        capabilities = set(finding.capabilities())
        assert capabilities == {"U", "P", "E"}, (
            f"{malicious_repo.name}/{finding.context.job_id}: a critical must carry "
            f"evidence for all three capabilities, got {sorted(capabilities)}"
        )


def test_two_cap_is_warning_with_correct_strip(two_cap_repo):
    result = analyze(two_cap_repo)
    warnings = [f for f in result.findings if f.severity == "warning"]
    assert warnings, f"{two_cap_repo.name}: expected a warning"
    assert not [f for f in result.findings if f.severity == "critical"], (
        f"{two_cap_repo.name}: holding exactly two capabilities is Rule of Two "
        "compliant and must never be critical"
    )
    expected = EXPECTED_STRIP[two_cap_repo.name]
    strips = {f.remediation.strip for f in warnings if f.remediation}
    assert expected in strips, f"{two_cap_repo.name}: expected strip {expected}, got {strips}"


def test_clean_produces_nothing_that_gates(clean_repo):
    """False positives here are as fatal as false negatives.

    Notes are permitted — they are off by default and never affect the exit
    code. Anything at warning or above on a hardened repo is a bug.
    """
    result = analyze(clean_repo)
    offenders = gating(result.findings)
    assert not offenders, (
        f"{clean_repo.name}: expected nothing at warning or above, got "
        + "; ".join(f"{f.severity} {f.rule_id} on {f.context.job_id}" for f in offenders)
    )


def test_false_positive_budget(realworld_repo):
    """A numeric noise ceiling on ordinary, unhardened code.

    Self-authored malicious fixtures cannot detect over-firing; only ordinary
    code can. This is the check that catches the failure mode where a scanner
    flags the modal job on GitHub.
    """
    result = analyze(realworld_repo)
    criticals = [f for f in result.findings if f.severity == "critical"]
    assert not criticals, (
        f"{realworld_repo.name}: no critical is justified on this repo, got "
        + "; ".join(f"{f.rule_id} on {f.context.job_id}" for f in criticals)
    )

    flagged = {f.context.job_id for f in gating(result.findings)}
    ratio = len(flagged) / max(result.contexts_scanned, 1)
    assert ratio <= 0.15, (
        f"{realworld_repo.name}: {len(flagged)}/{result.contexts_scanned} jobs flagged "
        f"({ratio:.0%}) exceeds the 15% budget — {sorted(flagged)}"
    )


def test_agent_restore_semantics_are_modelled():
    """The moat, asserted directly.

    Two fixtures differ only in the checkout ref. The exploitable one must name
    the file the action does *not* restore, and must not claim the restored file
    is attacker-controlled. The hardened one must stay silent. A filename-based
    detector fails both halves.
    """
    exploitable = analyze("tests/fixtures/malicious/agent-config-poisoning")
    finding = next(f for f in exploitable.findings if f.severity == "critical")
    reasons = " ".join(h.reason for h in finding.hits if h.capability == "U")

    assert "AGENTS.md" in reasons, "must name the instruction file left at PR head"
    assert "CLAUDE.md" not in reasons, (
        "claude-code-action restores CLAUDE.md from base; claiming it is "
        "attacker-controlled is a false positive on the flagship target"
    )

    hardened = analyze("tests/fixtures/clean/hardened-agent")
    assert not gating(hardened.findings), (
        "the same shape with a base-branch checkout is the recommended pattern "
        "and must not be flagged"
    )


def test_workflow_run_split_is_not_a_trigger_finding():
    """`workflow_run` confers ingress only when upstream state is consumed.

    Listing it as a dangerous trigger while also requiring the recommended split
    pattern to be clean is a contradiction that makes this suite unsatisfiable.
    """
    result = analyze("tests/fixtures/clean/workflow-run-split")
    assert not gating(result.findings)


def test_dogfood(repo_root):
    """Our own repository, including the README's CI snippet, must be clean.

    Under the original spec that snippet — `security-events: write` plus `run:`
    steps on a `pull_request` trigger — was flagged CRITICAL by the tool it
    installs. If we cannot pass our own README, we do not ship.
    """
    result = analyze(repo_root)
    offenders = gating(result.findings)
    assert not offenders, "; ".join(
        f"{f.severity} {f.rule_id} on {f.context.workflow_file}::{f.context.job_id}"
        for f in offenders
    )
