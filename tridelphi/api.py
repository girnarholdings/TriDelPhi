"""The public Python API.

``analyze()`` exists so the test suite is not forced to do SARIF archaeology
through a subprocess. Assertions run against typed ``Finding`` objects; the
subprocess path is exercised only where it proves something unique — the exit
code contract and stdout being parseable JSON.

The function never raises for a per-file problem. A malformed workflow becomes a
``Diagnostic`` and the scan continues, because one bad file must not take down a
repo with twelve workflows, and silently skipping it would be a bypass.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Sequence

from .model import AnalysisResult, Diagnostic, Finding, Position
from .parse import parse_repo
from .rule import evaluate_all
from .tables import Tables, load_tables

__all__ = ["analyze", "analyze_to_sarif", "AnalysisError"]

# `# tridelphi: ignore <rule-id> — <reason>`. The reason is mandatory: an
# exception a reviewer cannot evaluate is not an exception, it is a hole.
_SUPPRESS = re.compile(
    r"#\s*tridelphi:\s*ignore\s+(?P<rule>[\w/-]+)\s*[—–-]{1,2}\s*(?P<reason>\S.*)$"
)


class AnalysisError(Exception):
    """Raised only for conditions that make the whole run impossible."""


def _suppressions(root: Path, workflow_files: Sequence[str]) -> dict[str, list[tuple[int, str]]]:
    """Read suppression comments directly from source lines.

    ruamel's comment API attaches comments to unpredictable neighbouring nodes;
    a line scan is both simpler and more faithful to what a reviewer sees.
    """
    found: dict[str, list[tuple[int, str]]] = {}
    for rel in workflow_files:
        path = root / rel
        try:
            text = path.read_text("utf-8", errors="replace")
        except OSError:
            continue
        entries: list[tuple[int, str]] = []
        for index, line in enumerate(text.splitlines(), start=1):
            match = _SUPPRESS.search(line)
            if match:
                entries.append((index, match.group("rule")))
        if entries:
            found[rel] = entries
    return found


def _is_suppressed(finding: Finding, suppressions: dict[str, list[tuple[int, str]]]) -> bool:
    entries = suppressions.get(finding.context.workflow_file)
    if not entries:
        return False
    job_line = finding.context.position.line
    for line, rule in entries:
        if rule not in (finding.rule_id, finding.rule_id.split("/")[-1]):
            continue
        # A suppression applies to the job whose key it sits on, or the line above.
        if abs(line - job_line) <= 1:
            return True
    return False


def analyze(
    repo_root: str | os.PathLike[str],
    *,
    tables: Tables | None = None,
    assume_default_permissions: str = "write",
) -> AnalysisResult:
    root = Path(repo_root)
    if not root.exists():
        raise AnalysisError(f"path does not exist: {root}")
    if not root.is_dir():
        raise AnalysisError(f"not a directory: {root}")

    tables = tables or load_tables()
    outcome = parse_repo(root, tables, assume_default_permissions=assume_default_permissions)
    findings = evaluate_all(outcome.contexts, tables)

    workflow_files = sorted({c.workflow_file for c in outcome.contexts})
    suppressions = _suppressions(root, workflow_files)
    kept = [f for f in findings if not _is_suppressed(f, suppressions)]
    suppressed = len(findings) - len(kept)

    # A file we could not read is reported, never silently dropped: anyone able
    # to choke the parser would otherwise become invisible to the scan.
    diagnostics = list(outcome.diagnostics)
    for diagnostic in outcome.diagnostics:
        kept.append(_parse_error_finding(diagnostic, outcome, tables))

    return AnalysisResult(
        findings=tuple(sorted(kept, key=lambda f: f.sort_key)),
        diagnostics=tuple(diagnostics),
        contexts_scanned=len(outcome.contexts),
        files_scanned=outcome.files_scanned,
        suppressed=suppressed,
    )


def _parse_error_finding(diagnostic: Diagnostic, outcome, tables: Tables) -> Finding:
    from .model import ExecutionContext, RepoInventory

    position = diagnostic.position or Position(file=diagnostic.path, line=1)
    context = ExecutionContext(
        workflow_file=diagnostic.path,
        job_id="<file>",
        position=position,
        triggers=(),
        fork_reachable=False,
        effective_permissions={},
        permissions_source="unparsed",
        repo=outcome.inventory,
        body=_EMPTY_NODE(diagnostic.path),
    )
    return Finding(
        rule_id="tridelphi/parse-error",
        severity="warning",
        context=context,
        hits=(),
        primary_position=position,
        message=(
            f"`{diagnostic.path}` could not be analysed: {diagnostic.message}. "
            "It is reported rather than skipped, because a file the scanner cannot "
            "read is a blind spot."
        ),
        remediation=None,
    )


def _EMPTY_NODE(path: str):
    from .yamlnode import YamlNode

    return YamlNode.root({}, path, "")


def analyze_to_sarif(
    repo_root: str | os.PathLike[str],
    *,
    tool_version: str,
    validate: bool = False,
    assume_default_permissions: str = "write",
) -> dict:
    from .sarif import to_sarif

    result = analyze(repo_root, assume_default_permissions=assume_default_permissions)
    return to_sarif(
        result.findings,
        tool_version=tool_version,
        diagnostics=result.diagnostics,
        validate=validate,
    )
