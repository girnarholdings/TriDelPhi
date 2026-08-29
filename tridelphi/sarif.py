"""Finding[] -> SARIF 2.1.0.

Determinism is a contract, not a nicety: a future merge gate diffs these
documents. Two consequences worth stating because both are easy to get wrong.

Fingerprints exclude line numbers. Including the line means inserting a step
above a job invalidates every fingerprint in the file, the gate reports an
all-new finding set, and the ratchet is untrustworthy within a week.

Validation is off by default. The vendored schema is draft-04 and 110 KB;
validating on every run is a needless cost for an air-gapped CLI, so it is
enabled in tests and behind ``--self-check``.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from importlib import resources
from typing import Any

from .model import RULES, Diagnostic, Finding, rule_by_id
from .severity import SEVERITY_TO_SARIF_LEVEL as _LEVEL

__all__ = [
    "dumps",
    "fingerprint",
    "is_suppressed",
    "load_schema",
    "simple_sarif",
    "to_sarif",
    "validate_sarif",
]

SCHEMA_URI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"


def is_suppressed(result: dict[str, Any]) -> bool:
    """Whether a SARIF result is suppressed (SARIF 2.1.0 §3.27.23).

    A wrapped tool that supports in-source suppression — semgrep's `# nosemgrep`,
    for one — does not drop the finding from its SARIF; it emits the result with a
    non-empty ``suppressions`` array (``kind: inSource``). That is the author's
    reviewed, in-code statement that the finding was audited and accepted, so it
    must not be counted as an open item or gate the build. It stays in the merged
    document (GitHub renders it as a dismissed alert), just not as a live finding.

    Defensive: the field is attacker-adjacent (it rides in a subprocess's output),
    so a malformed ``suppressions`` never raises — only a well-formed, non-empty
    array suppresses, and anything else counts, which fails safe toward showing.
    """
    supp = result.get("suppressions")
    return isinstance(supp, list) and len(supp) > 0 and all(
        isinstance(s, dict) for s in supp
    )


def load_schema() -> dict[str, Any]:
    text = resources.files(f"{__package__}.data").joinpath("sarif-2.1.0.json").read_text("utf-8")
    return json.loads(text)


def validate_sarif(document: dict[str, Any]) -> None:
    """Raise if ``document`` does not validate. Draft-04 selection is explicit —
    a modern validator silently mishandles draft-04 keywords."""
    from jsonschema.validators import validator_for

    schema = load_schema()
    validator_cls = validator_for(schema)
    validator_cls.check_schema(schema)
    validator_cls(schema).validate(document)


def fingerprint(finding: Finding) -> str:
    parts = (
        finding.context.workflow_file,
        finding.context.job_id,
        finding.rule_id,
        ",".join(sorted({h.kind for h in finding.hits})),
    )
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()[:16]


def _region(position) -> dict[str, Any]:
    region: dict[str, Any] = {"startLine": position.line}
    if position.column:
        region["startColumn"] = position.column
    if position.end_line:
        region["endLine"] = position.end_line
    if position.snippet:
        region["snippet"] = {"text": position.snippet}
    return region


def _location(position) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": position.file, "uriBaseId": "%SRCROOT%"},
            "region": _region(position),
        }
    }


def _result(finding: Finding, baseline_state: str | None) -> dict[str, Any]:
    # Raises if the rule is not in the registry. Kept for the side effect: it is
    # what stops rule.py from minting an id that never appears in
    # tool.driver.rules, which would emit SARIF referencing an undeclared rule.
    spec = rule_by_id(finding.rule_id)
    properties: dict[str, Any] = {
        # The ADR technique ids let a consumer roll findings up against a
        # published taxonomy rather than our rule names alone.
        "adrTechniques": list(spec.adr_techniques),
        "tridelphiSeverity": finding.severity,
        "capabilities": list(finding.capabilities()),
        "jobId": finding.context.job_id,
        "triggers": list(finding.context.triggers),
        "permissionsSource": finding.context.permissions_source,
        "hits": [
            {
                "capability": h.capability,
                "kind": h.kind,
                "reason": h.reason,
                "observed": h.observed,
                "tier": h.tier,
                "file": h.position.file,
                "line": h.position.line,
            }
            for h in finding.hits
        ],
    }
    if finding.remediation is not None:
        properties["remediation"] = {
            "strip": finding.remediation.strip,
            "kind": finding.remediation.kind,
            "target": finding.remediation.target,
            "breaks": finding.remediation.breaks,
            "confidence": finding.remediation.confidence,
            "text": finding.remediation.rendered,
        }

    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": _RULE_INDEX[finding.rule_id],
        "level": _LEVEL[finding.severity],
        "message": {"text": finding.message},
        "locations": [_location(finding.primary_position)],
        "partialFingerprints": {"tridelphiContextHash/v1": fingerprint(finding)},
        "properties": properties,
    }

    # SARIF declares relatedLocations with uniqueItems, and several hits
    # legitimately share a position (a step that is both the agent and the
    # egress). Deduplicate on the position, preserving order.
    related = []
    seen_positions = {finding.primary_position.sort_key}
    for hit in finding.hits:
        key = hit.position.sort_key
        if key in seen_positions:
            continue
        seen_positions.add(key)
        related.append(_location(hit.position))
    if related:
        # Showing U here, P there and E somewhere else in one result is the
        # product thesis rendered in the consumer's UI.
        result["relatedLocations"] = related
    if baseline_state:
        result["baselineState"] = baseline_state
    return result


_RULE_INDEX = {spec.id: i for i, spec in enumerate(RULES)}


def _rules_block() -> list[dict[str, Any]]:
    return [
        {
            "id": spec.id,
            "name": spec.name,
            "shortDescription": {"text": spec.short_description},
            "fullDescription": {"text": spec.full_description},
            "helpUri": spec.help_uri,
            "defaultConfiguration": {"level": spec.default_level},
            "properties": {"adrTechniques": list(spec.adr_techniques)},
        }
        for spec in RULES
    ]


def to_sarif(
    findings: Sequence[Finding],
    *,
    tool_version: str,
    diagnostics: Sequence[Diagnostic] = (),
    baseline: set[str] | None = None,
    validate: bool = False,
) -> dict[str, Any]:
    ordered = sorted(findings, key=lambda f: f.sort_key)
    results = []
    for finding in ordered:
        state = None
        if baseline is not None:
            state = "unchanged" if fingerprint(finding) in baseline else "new"
        results.append(_result(finding, state))

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "tridelphi",
                "version": tool_version,
                "informationUri": "https://github.com/girnarholdings/TriDelPhi",
                "rules": _rules_block(),
            }
        },
        "results": results,
        "originalUriBaseIds": {"%SRCROOT%": {"description": {"text": "repository root"}}},
    }

    if diagnostics:
        run["invocations"] = [
            {
                "executionSuccessful": True,
                "toolExecutionNotifications": [
                    {
                        "level": d.severity,
                        "message": {"text": f"{d.path}: {d.message}"},
                    }
                    for d in sorted(diagnostics, key=lambda d: d.sort_key)
                ],
            }
        ]

    document = {"$schema": SCHEMA_URI, "version": "2.1.0", "runs": [run]}
    if validate:
        validate_sarif(document)
    return document


def simple_sarif(findings, *, tool: str, audit_label: str, tool_version: str,
                 help_uri: str) -> dict[str, Any]:
    """One SARIF run for the sibling audits' flat findings.

    ``scan`` and ``expose`` findings carry (rule, severity, where, message)
    rather than the core model's :class:`Finding`, and the two commands had
    grown identical forty-line builders. Any object with those four attributes
    renders here; output is deterministic (sorted by where/rule/message) like
    everything else that feeds the gate.
    """
    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    results: list[dict[str, Any]] = []
    for f in sorted(findings, key=lambda x: (x.where, x.rule, x.message)):
        rule_id = f"{tool}/{f.rule}"
        if rule_id not in seen:
            seen.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": f.rule.replace("-", ""),
                "shortDescription": {"text": f"{audit_label}: {f.rule}"},
                "helpUri": help_uri,
            })
        path, _sep, line = f.where.partition(":")
        region = {"startLine": int(line)} if line.isdigit() else {"startLine": 1}
        results.append({
            "ruleId": rule_id,
            "level": _LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": path or "README.md"},
                "region": region,
            }}],
        })
    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": tool,
                "version": tool_version,
                "informationUri": help_uri,
                "rules": rules,
            }},
            "results": results,
        }],
    }


def dumps(document: dict[str, Any]) -> str:
    """Byte-stable serialisation. ``ensure_ascii`` keeps output identical across
    locales; the trailing newline is explicit so the file layer cannot vary."""
    return json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
