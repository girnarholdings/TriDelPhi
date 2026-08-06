"""SARIF output contract."""

from __future__ import annotations

import json

import pytest
from jsonschema.validators import Draft4Validator, validator_for

from tridelphi import __version__
from tridelphi.api import analyze
from tridelphi.model import RULES
from tridelphi.sarif import dumps, fingerprint, load_schema, to_sarif, validate_sarif


def _all_findings():
    findings = []
    for name in ("malicious/comment-and-control", "two_cap/up-no-egress", "clean/deploy-on-push"):
        findings.extend(analyze(f"tests/fixtures/{name}").findings)
    return findings


def test_schema_is_draft4():
    """A modern validator silently mishandles draft-04 keywords, so the choice
    must be asserted rather than assumed."""
    schema = load_schema()
    assert schema["$schema"].startswith("http://json-schema.org/draft-04/")
    assert validator_for(schema) is Draft4Validator


def test_empty_run_validates():
    document = to_sarif([], tool_version=__version__, validate=True)
    assert document["runs"][0]["results"] == []
    assert document["version"] == "2.1.0"


def test_all_severities_validate():
    findings = _all_findings()
    severities = {f.severity for f in findings}
    assert {"critical", "warning", "note"} <= severities, severities
    validate_sarif(to_sarif(findings, tool_version=__version__))


def test_levels_map_correctly():
    document = to_sarif(_all_findings(), tool_version=__version__)
    by_rule = {r["ruleId"]: r for r in document["runs"][0]["results"]}
    for result in by_rule.values():
        assert result["level"] in ("error", "warning", "note")
        # SARIF has no "critical", so true severity rides in the property bag.
        assert result["properties"]["tridelphiSeverity"] in ("critical", "warning", "note")
        if result["properties"]["tridelphiSeverity"] == "critical":
            assert result["level"] == "error"


def test_every_emitted_rule_is_in_the_driver():
    """Rule IDs are minted in rule.py and rendered in sarif.py. Without a single
    registry those namespaces drift and results reference undeclared rules."""
    document = to_sarif(_all_findings(), tool_version=__version__)
    declared = {r["id"] for r in document["runs"][0]["tool"]["driver"]["rules"]}
    for result in document["runs"][0]["results"]:
        assert result["ruleId"] in declared
        assert (
            document["runs"][0]["tool"]["driver"]["rules"][result["ruleIndex"]]["id"]
            == result["ruleId"]
        )


def test_regions_are_one_indexed():
    """ruamel's .lc is 0-indexed and SARIF declares minimum: 1, so a missed
    conversion is a schema violation rather than an off-by-one cosmetic."""
    document = to_sarif(_all_findings(), tool_version=__version__)
    for result in document["runs"][0]["results"]:
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1
        assert region.get("startColumn", 1) >= 1


def test_fingerprints_ignore_line_numbers():
    """Inserting lines above a job must not invalidate its baseline entry, or
    the ratchet fires spuriously and stops being trusted."""
    import shutil
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "repo"
        shutil.copytree("tests/fixtures/malicious/comment-and-control", target)
        before = [fingerprint(f) for f in analyze(target).findings]

        workflow = target / ".github/workflows/assist.yml"
        workflow.write_text("\n" * 10 + workflow.read_text(), encoding="utf-8")
        after = [fingerprint(f) for f in analyze(target).findings]

    assert before == after


def test_rules_registry_is_complete_and_unique():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))
    for spec in RULES:
        assert spec.id.startswith("tridelphi/")
        assert spec.full_description.strip()
        assert spec.help_uri.startswith("https://")


def test_output_is_valid_json_and_stable():
    findings = _all_findings()
    first = dumps(to_sarif(findings, tool_version=__version__))
    second = dumps(to_sarif(findings, tool_version=__version__))
    assert first == second
    assert json.loads(first)
    assert first.endswith("\n")
