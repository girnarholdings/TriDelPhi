"""ADR threat-taxonomy mapping and the --coverage report.

Adopting a published taxonomy is only worth anything if the mapping stays
honest: every id has to resolve, and a technique nothing can see statically must
not be claimed as covered.
"""

from __future__ import annotations

import io

import pytest
from conftest import run_cli

from tridelphi.coverage import coverage_rows, render_coverage
from tridelphi.model import RULES
from tridelphi.tables import load_tables

VALID_REACH = {"static", "partial", "runtime"}


def test_taxonomy_has_all_seventeen_techniques(tables):
    techniques = tables.section("adr_techniques", "techniques", [])
    assert len(techniques) == 17, "ADR-Bench defines 17 threat techniques"


def test_every_technique_is_well_formed(tables):
    seen = set()
    for entry in tables.section("adr_techniques", "techniques", []):
        assert entry["id"] not in seen, f"duplicate technique id {entry['id']}"
        seen.add(entry["id"])
        assert entry["reach"] in VALID_REACH, entry
        assert str(entry["name"]).strip()
        assert str(entry["note"]).strip(), f"{entry['id']} must justify its reach"


def test_every_rule_technique_id_resolves(tables):
    """A typo in a rule's technique list would silently drop it from coverage."""
    known = {e["id"] for e in tables.section("adr_techniques", "techniques", [])}
    for spec in RULES:
        for technique in spec.adr_techniques:
            assert technique in known, (
                f"{spec.id} references unknown ADR technique {technique!r}"
            )


def test_runtime_only_techniques_are_never_claimed():
    """The honesty constraint. Claiming static coverage of a runtime-only
    technique would send a team away believing they were protected."""
    for row in coverage_rows():
        if row["reach"] == "runtime":
            assert not row["rules"], (
                f"{row['name']} is runtime-only but {row['rules']} claims to detect it"
            )


def test_the_moat_rules_map_to_the_hijacking_techniques():
    rows = {r["id"]: r for r in coverage_rows()}
    assert "tridelphi/agent-config-ingress" in rows["agentic-control-flow-hijacking"]["rules"]
    assert "tridelphi/agent-prompt-injection" in rows["indirect-prompt-injection"]["rules"]


def test_coverage_renders_and_names_its_own_gaps():
    out = io.StringIO()
    assert render_coverage(out) == 0
    text = out.getvalue()
    assert "runtime-only" in text
    # A statically reachable technique with no rule is our backlog, and the
    # report must say so rather than hiding it among the runtime ones.
    assert "gap" in text
    assert "arXiv:2605.17380" in text


def test_coverage_via_cli(repo_root):
    result = run_cli(["--coverage"], cwd=repo_root)
    assert result.returncode == 0
    assert "ADR agent threat techniques" in result.stdout


def test_explain_surfaces_techniques(repo_root):
    result = run_cli(["--explain", "agent-prompt-injection"], cwd=repo_root)
    assert result.returncode == 0
    assert "ADR threat techniques" in result.stdout


def test_sarif_carries_techniques_on_result_and_rule():
    import json

    from tridelphi import __version__
    from tridelphi.api import analyze
    from tridelphi.sarif import to_sarif

    result = analyze("tests/fixtures/malicious/comment-and-control")
    doc = to_sarif(result.findings, tool_version=__version__, validate=True)
    run = doc["runs"][0]
    res = run["results"][0]
    assert res["properties"]["adrTechniques"]
    rule = run["tool"]["driver"]["rules"][res["ruleIndex"]]
    assert rule["properties"]["adrTechniques"] == res["properties"]["adrTechniques"]
    assert json.dumps(doc)  # serialisable


def test_overbroad_tools_is_detected():
    """The rule the taxonomy gap analysis produced."""
    from tridelphi.api import analyze

    result = analyze("tests/fixtures/two_cap/agent-overbroad-tools")
    findings = [f for f in result.findings if f.rule_id == "tridelphi/agent-overbroad-tools"]
    assert findings, "wildcard user allowlist should be flagged"
    finding = findings[0]
    assert finding.severity == "warning", "a removed guardrail is not itself an exploit"
    assert finding.remediation is not None
    assert "author_association" in finding.remediation.rendered


def test_overbroad_tools_quiet_without_an_agent(tmp_path):
    """The marker only matters on an agent step."""
    from tridelphi.api import analyze

    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "w.yml").write_text(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo '--yolo is just a string here'\n",
        encoding="utf-8",
    )
    result = analyze(tmp_path)
    assert not [
        f for f in result.findings if f.rule_id == "tridelphi/agent-overbroad-tools"
    ]
