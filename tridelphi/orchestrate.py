"""Optional orchestration of external scanners, starting with zizmor.

TriDelPhi's own analysis is the capability-graph join — the finding no per-rule
linter produces. It is deliberately *not* a re-implementation of the commodity
layer: unpinned actions, mutable tags, template injection at the line level.
zizmor already does that layer well, so when the user asks for it we run zizmor
and merge its findings alongside ours rather than duplicating them.

Two properties are load-bearing:

* **Off by default.** `tridelphi core .` stays pure and offline — no subprocess,
  no network, air-gap safe. zizmor only runs when explicitly requested with
  ``--with-zizmor``, and this module is the only place a subprocess is spawned.
* **Graceful when absent.** zizmor is a separate binary the user may not have
  installed. A missing binary is a diagnostic, never a crash — you still get the
  TriDelPhi findings, which are the ones that justify the tool.

The merge is SARIF-correct: zizmor's results become a second ``run`` in the same
document. GitHub code scanning renders multiple runs natively, and keeping them
as distinct runs preserves each tool's rule metadata and provenance.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .model import Diagnostic
from .subprocessutil import run_bounded

__all__ = [
    "MAX_OUTPUT_BYTES",
    "ZizmorResult",
    "merge_runs",
    "run_zizmor",
    "sarif_shape_error",
    "summarize_external_run",
    "zizmor_path",
]

# Refuse to parse external tool output larger than this. The wrapped tools scan
# attacker-influenced content; a report this size is an attack or a bug, and
# either way it does not belong in memory or in the merged document.
MAX_OUTPUT_BYTES = 25 * 1024 * 1024
MAX_SARIF_RUNS = 64
MAX_SARIF_RESULTS_PER_RUN = 50_000
MAX_SARIF_RULES_PER_RUN = 50_000
MAX_SARIF_LOCATIONS_PER_RESULT = 32
MAX_SARIF_NODES = 2_000_000
MAX_SARIF_STRING_CHARS = 1_000_000


def _text_error(value: Any, label: str, *, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str):
        return f"output had a non-text {label}"
    if required and not value.strip():
        return f"output had an empty {label}"
    if len(value) > MAX_SARIF_STRING_CHARS:
        return f"output had an overlong {label}"
    return None


def _global_budget_error(document: Any) -> str | None:
    """Bound hostile JSON even in SARIF extension properties we do not use."""

    stack = [document]
    seen = 0
    while stack:
        value = stack.pop()
        seen += 1
        if seen > MAX_SARIF_NODES:
            return "output exceeded the SARIF object budget"
        if isinstance(value, str):
            if len(value) > MAX_SARIF_STRING_CHARS:
                return "output contained an overlong string"
        elif isinstance(value, dict):
            stack.extend(value.keys())
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)
    return None


def sarif_shape_error(document: Any) -> str | None:
    """Structural check for an external tool's SARIF document.

    Returns a human-readable defect description, or None if the document is
    shaped well enough to merge and post-process safely. This is the shared
    containment gate for *every* wrapped scanner — the tools scan
    attacker-influenced repositories, so their output is untrusted and nothing
    downstream (severity counting, URI rewriting, merging) may assume shapes
    this function has not checked.
    """
    if not isinstance(document, dict) or not isinstance(document.get("runs"), list):
        return "output was not a SARIF document"
    budget_error = _global_budget_error(document)
    if budget_error is not None:
        return budget_error
    runs = document["runs"]
    if len(runs) > MAX_SARIF_RUNS:
        return f"output had more than {MAX_SARIF_RUNS} runs"
    for run in runs:
        if not isinstance(run, dict):
            return "output had a malformed run"
        results = run.get("results", [])
        if not isinstance(results, list) or any(not isinstance(r, dict) for r in results):
            return "output had malformed results"
        if len(results) > MAX_SARIF_RESULTS_PER_RUN:
            return f"output had more than {MAX_SARIF_RESULTS_PER_RUN} results in one run"
        driver = run.get("tool", {})
        if not isinstance(driver, dict) or not isinstance(driver.get("driver"), dict):
            return "output had no tool.driver"
        driver = driver["driver"]
        error = _text_error(driver.get("name"), "tool.driver.name", required=True)
        if error is not None:
            return error
        for field in ("version", "semanticVersion", "informationUri"):
            error = _text_error(driver.get(field), f"tool.driver.{field}")
            if error is not None:
                return error
        rules = driver.get("rules", [])
        if not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules):
            return "output had malformed tool rules"
        if len(rules) > MAX_SARIF_RULES_PER_RUN:
            return f"output had more than {MAX_SARIF_RULES_PER_RUN} tool rules"
        for rule in rules:
            error = _text_error(rule.get("id"), "rule id")
            if error is not None:
                return error
        for result in results:
            error = _text_error(result.get("ruleId"), "result ruleId")
            if error is not None:
                return error
            level = result.get("level")
            if level is not None and not isinstance(level, str):
                return "output had a non-text result level"
            message = result.get("message")
            if message is not None:
                if not isinstance(message, dict):
                    return "output had a malformed result message"
                for field in ("text", "markdown", "id"):
                    error = _text_error(message.get(field), f"result message {field}")
                    if error is not None:
                        return error
            locations = result.get("locations", [])
            if not isinstance(locations, list) or any(
                not isinstance(loc, dict) for loc in locations
            ):
                return "output had malformed result locations"
            if len(locations) > MAX_SARIF_LOCATIONS_PER_RESULT:
                return f"output had more than {MAX_SARIF_LOCATIONS_PER_RESULT} result locations"
            for location in locations:
                physical = location.get("physicalLocation")
                if physical is not None and not isinstance(physical, dict):
                    return "output had a malformed physicalLocation"
                if not isinstance(physical, dict):
                    continue
                artifact = physical.get("artifactLocation")
                if artifact is not None and not isinstance(artifact, dict):
                    return "output had a malformed artifactLocation"
                if isinstance(artifact, dict):
                    error = _text_error(artifact.get("uri"), "artifact URI")
                    if error is not None:
                        return error
                    error = _text_error(artifact.get("uriBaseId"), "artifact uriBaseId")
                    if error is not None:
                        return error
                region = physical.get("region")
                if region is not None and not isinstance(region, dict):
                    return "output had a malformed region"
                if isinstance(region, dict):
                    for field in ("startLine", "startColumn", "endLine", "endColumn"):
                        coordinate = region.get(field)
                        if coordinate is not None and (
                            not isinstance(coordinate, int)
                            or isinstance(coordinate, bool)
                            or coordinate < 1
                        ):
                            return f"output had an invalid region {field}"
    return None


class ZizmorResult:
    """The outcome of asking zizmor to scan. Exactly one of ``sarif`` or
    ``diagnostic`` is set."""

    __slots__ = ("diagnostic", "finding_count", "sarif")

    def __init__(
        self,
        sarif: dict[str, Any] | None = None,
        diagnostic: Diagnostic | None = None,
        finding_count: int = 0,
    ) -> None:
        self.sarif = sarif
        self.diagnostic = diagnostic
        self.finding_count = finding_count

    @property
    def ok(self) -> bool:
        return self.sarif is not None


def zizmor_path() -> str | None:
    """Absolute path to the zizmor binary, or None if it is not installed."""
    return shutil.which("zizmor")


def run_zizmor(repo_root: str | Path, *, offline: bool = True, timeout: int = 120) -> ZizmorResult:
    """Run zizmor over ``repo_root`` and return its SARIF.

    ``offline`` passes ``--offline`` so no GitHub API calls are made even when a
    token is present, preserving TriDelPhi's air-gap-safe default. A caller that
    wants zizmor's online audits can pass ``offline=False`` explicitly.
    """
    binary = zizmor_path()
    if binary is None:
        return ZizmorResult(
            diagnostic=Diagnostic(
                path="zizmor",
                message=(
                    "--with-zizmor was requested but zizmor is not on PATH. Install it "
                    "with `pipx install zizmor` or `cargo install zizmor`, or drop the "
                    "flag. TriDelPhi's own findings are unaffected."
                ),
                severity="warning",
            )
        )

    workflows = Path(repo_root) / ".github" / "workflows"
    if not workflows.is_dir():
        return ZizmorResult(sarif=_empty_run(), finding_count=0)

    # Scan `.github/workflows` (relative, cwd=repo_root) — the same surface
    # TriDelPhi core scans, because that is the only place GitHub executes
    # workflows from. Scanning "." would also sweep vendored/example workflows
    # deeper in the tree (test fixtures, monorepo templates) that never run.
    # URI caveat, observed live: zizmor keys URIs to the enclosing *git* root
    # when one exists, and to the scan target otherwise; the ladder layer
    # normalizes both shapes to repo-relative paths.
    cmd = [binary, "--format", "sarif"]
    if offline:
        cmd.append("--offline")
    cmd.append(".github/workflows")

    try:
        completed = run_bounded(
            cmd,
            timeout=timeout,
            cwd=str(repo_root),
            max_stdout_bytes=MAX_OUTPUT_BYTES,
            max_stderr_bytes=1024 * 1024,
        )
    except FileNotFoundError:  # pragma: no cover - race with zizmor_path()
        return ZizmorResult(
            diagnostic=Diagnostic("zizmor", "zizmor vanished between lookup and run", "warning")
        )
    except subprocess.TimeoutExpired:
        return ZizmorResult(
            diagnostic=Diagnostic(
                "zizmor", f"zizmor did not finish within {timeout}s; skipped", "warning"
            )
        )

    # zizmor exits non-zero when it finds problems, which is success for our
    # purposes. A parse failure of its stdout is the real error signal.
    stdout = completed.stdout.strip()
    if completed.stdout_truncated:
        return ZizmorResult(
            diagnostic=Diagnostic(
                "zizmor",
                f"zizmor produced over {MAX_OUTPUT_BYTES // (1024 * 1024)} MB of output; "
                "refusing to parse it",
                "warning",
            )
        )
    if not stdout:
        # No findings, or zizmor wrote to stderr. Treat empty as clean unless it
        # clearly errored.
        if completed.returncode not in (0, 13, 14):  # zizmor: 13/14 = findings present
            return ZizmorResult(
                diagnostic=Diagnostic(
                    "zizmor",
                    f"zizmor exited {completed.returncode}: {completed.stderr.strip()[:200]}",
                    "warning",
                )
            )
        return ZizmorResult(sarif=_empty_run(), finding_count=0)

    try:
        document = json.loads(stdout)
    except (ValueError, RecursionError):
        return ZizmorResult(
            diagnostic=Diagnostic(
                "zizmor", "zizmor output was not valid SARIF JSON", "warning"
            )
        )

    defect = sarif_shape_error(document)
    if defect is not None:
        return ZizmorResult(
            diagnostic=Diagnostic("zizmor", f"zizmor {defect}; skipped", "warning")
        )

    count = sum(len(run.get("results", [])) for run in document.get("runs", []))
    return ZizmorResult(sarif=document, finding_count=count)


def _empty_run() -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "zizmor", "rules": []}}, "results": []}],
    }


# GitHub code scanning rejects the WHOLE uploaded file if any single result
# lacks a location ("locationFromSarifResult: expected at least one location").
# Repo-level findings — scorecard posture is the standing example — have no
# file to point at, so they get the conventional repo-level anchor. README.md
# is where a repository describes itself, and the path does not have to exist
# for ingestion to succeed; what must exist is the location object.
_REPO_LEVEL_LOCATION = {
    "physicalLocation": {
        "artifactLocation": {"uri": "README.md"},
        "region": {"startLine": 1},
    }
}


def _ensure_result_locations(run: dict[str, Any]) -> dict[str, Any]:
    """Give every result at least one location, without touching valid ones.

    This is a containment net at the merge boundary: whichever wrapped tool
    (current or future) emits a locationless result, the merged upload must
    never be the thing that breaks — one bad result would take the entire
    code-scanning upload down with it.
    """
    results = run.get("results")
    if not isinstance(results, list):
        return run
    patched: list[Any] = []
    changed = False
    for result in results:
        if isinstance(result, dict):
            locs = result.get("locations")
            if not (isinstance(locs, list) and locs):
                result = {**result, "locations": [_REPO_LEVEL_LOCATION]}
                changed = True
        patched.append(result)
    if not changed:
        return run
    return {**run, "results": patched}


def merge_runs(primary: dict[str, Any], external: dict[str, Any]) -> dict[str, Any]:
    """Append ``external``'s runs to ``primary``'s ``runs`` array.

    Kept as separate runs on purpose: each tool keeps its own driver metadata,
    rule set, and result provenance, which is exactly what SARIF's multi-run
    model is for. The result is deterministic — no reordering of ``primary``.
    Every appended result is guaranteed a location (see
    :func:`_ensure_result_locations`) so the merged document stays uploadable
    to GitHub code scanning.
    """
    merged = dict(primary)
    merged_runs = list(primary.get("runs", []))
    for run in external.get("runs", []):
        merged_runs.append(_ensure_result_locations(run) if isinstance(run, dict) else run)
    merged["runs"] = merged_runs
    return merged


def summarize_external_run(result: ZizmorResult) -> str:
    """One human line for the text renderer."""
    if not result.ok:
        return "zizmor: skipped"
    n = result.finding_count
    return f"zizmor: {n} finding{'s' if n != 1 else ''} (merged into SARIF output)"
