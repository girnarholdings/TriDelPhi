"""Regression tests against the shape of real, disclosed CI/CD attacks.

These are not synthetic red-team shapes — each fixture reproduces the pattern
behind a public incident, so a regression here means TriDelPhi stopped catching
something that actually happened in the wild. Sources are cited in
docs/REAL_WORLD.md.
"""

from __future__ import annotations

from pathlib import Path

from tridelphi.api import analyze
from tridelphi.verify_cmd import run_verify

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "realworld"


def test_pwn_request_target_is_critical():
    """pull_request_target + PR-head checkout + secret-in-env — the pattern
    behind the MITRE CAR / Splunk (Sysdig), spotipy and timescale/pgai
    disclosures. Must be a critical U∩P∩E finding."""
    result = analyze(FIXTURES.parent / "malicious" / "pwn-request-target")
    criticals = [f for f in result.findings if f.severity == "critical"]
    assert criticals, "the pwn-request pattern was not flagged critical"
    finding = criticals[0]
    assert finding.rule_id == "tridelphi/untrusted-checkout-privileged-egress"
    caps = {h.capability for h in finding.hits if h.observed}
    assert caps == {"U", "P", "E"}, f"expected all three capabilities, got {caps}"


def test_tj_actions_supply_chain_takeover_is_caught():
    """CVE-2025-30066: a SHA-pinned action whose pin was moved to the malicious
    commit. The trust-lock records the legitimate identity; verify must flag the
    swap as an error and fail the gate — the change SHA-pinning alone cannot
    catch."""
    fixture = FIXTURES / "supply-chain-tj-actions"
    code, doc = run_verify(
        fixture,
        trust_lock=str(fixture / ".tridelphi" / "trust.lock"),
        offline=True,
        fail_on="critical",
    )
    assert code == 1, "the trust-lock regression did not fail the gate"
    assert doc is not None
    results = doc["runs"][0]["results"]
    regressions = [r for r in results if r["ruleId"] == "tridelphi-verify/trust-lock-regression"]
    assert regressions, "no trust-lock-regression finding was produced"
    r = regressions[0]
    assert r["level"] == "error"
    assert "0e58ed8671d6" in r["message"]["text"]  # the malicious commit


def test_tj_actions_untampered_pin_passes():
    """Control: with the pin matching the lock, verify is clean — the pawl does
    not cry wolf on a correctly pinned action."""
    fixture = FIXTURES / "supply-chain-tj-actions"
    # Point verify at a lock that matches the (malicious-in-fixture) pin: a
    # matching lock must pass, proving the error above is the diff, not noise.
    import json
    import tempfile

    lock = {
        "actions": {
            "actions/checkout": {
                "owner": "actions",
                "sha": "11d5960a326750d5838078e36cf38b85af677262",
            },
            "tj-actions/changed-files": {
                "owner": "tj-actions",
                "sha": "0e58ed8671d6b60d0890c21b07f8835ace038e67",
            },
        }
    }
    with tempfile.NamedTemporaryFile("w", suffix=".lock", delete=False) as fh:
        json.dump(lock, fh)
        lock_path = fh.name
    code, _doc = run_verify(fixture, trust_lock=lock_path, offline=True, fail_on="critical")
    assert code == 0, "a correctly pinned action was wrongly flagged"
