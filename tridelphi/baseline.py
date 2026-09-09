"""Finding baseline — the ratchet.

Without this, run 2 shows the same findings as run 1 and the honest answer to
"does anyone run this twice" is no. The user's options become fix everything
today, set ``continue-on-error``, or delete the workflow; the second is worst,
because it also swallows exit code 2 and makes a crashed scanner look clean.

Fingerprints deliberately exclude line numbers, so unrelated edits above a job
do not invalidate the baseline.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from .fsutil import atomic_write_text
from .model import Finding
from .sarif import fingerprint

__all__ = [
    "DEFAULT_BASELINE",
    "annotate_external_baseline",
    "external_fingerprint",
    "load_baseline",
    "partition",
    "write_baseline",
]

DEFAULT_BASELINE = ".tridelphi-baseline.json"
_VERSION = 1
_MAX_BASELINE_BYTES = 5 * 1024 * 1024
_MAX_BASELINE_ENTRIES = 200_000


def load_baseline(path: Path) -> set[str]:
    if path.is_symlink() or not path.is_file():
        return set()
    try:
        with path.open("rb") as handle:
            raw = handle.read(_MAX_BASELINE_BYTES + 1)
        if len(raw) > _MAX_BASELINE_BYTES:
            return set()
        doc = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, RecursionError):
        return set()
    if not isinstance(doc, dict) or doc.get("version") != _VERSION:
        return set()
    entries = doc.get("fingerprints") or []
    if not isinstance(entries, list) or len(entries) > _MAX_BASELINE_ENTRIES:
        return set()
    return {
        value
        for entry in entries
        if isinstance(entry, dict)
        and isinstance((value := entry.get("fp")), str)
        and 1 <= len(value) <= 200
    }


def external_fingerprint(result: dict[str, Any]) -> str | None:
    partial = result.get("partialFingerprints")
    if not isinstance(partial, dict):
        return None
    value = partial.get("tridelphiExternal/v1")
    return f"external:{value}" if isinstance(value, str) and value else None


def _external_entries(documents: Iterable[dict[str, Any]]):
    for document in documents:
        runs = document.get("runs", []) if isinstance(document, dict) else []
        for run in runs if isinstance(runs, list) else []:
            if not isinstance(run, dict):
                continue
            driver = run.get("tool", {}).get("driver", {}) if isinstance(run.get("tool"), dict) else {}
            tool = driver.get("name", "external") if isinstance(driver, dict) else "external"
            results = run.get("results", [])
            for result in results if isinstance(results, list) else []:
                if isinstance(result, dict):
                    yield str(tool), result


def write_baseline(
    path: Path,
    findings: Sequence[Finding],
    tool_version: str,
    external_documents: Iterable[dict[str, Any]] = (),
) -> int:
    entries = [
        {
            "fp": fingerprint(f),
            "rule": f.rule_id,
            "note": f"{f.context.workflow_file} :: {f.context.job_id}",
        }
        for f in sorted(findings, key=lambda f: f.sort_key)
    ]
    for tool, result in _external_entries(external_documents):
        # A committed credential must be rotated, never waived into a baseline.
        if tool in {"gitleaks", "tridelphi-verify"}:
            continue
        fp = external_fingerprint(result)
        if fp is None:
            continue
        entries.append(
            {
                "fp": fp,
                "rule": str(result.get("ruleId", "external")),
                "note": f"{tool} external finding",
            }
        )
    entries = list({entry["fp"]: entry for entry in entries}.values())
    entries.sort(key=lambda entry: (entry["fp"], entry["rule"], entry["note"]))
    document = {
        "version": _VERSION,
        "generated_by": f"tridelphi {tool_version}",
        "fingerprints": entries,
    }
    atomic_write_text(path, json.dumps(document, indent=2, sort_keys=True) + "\n")
    return len(entries)


def annotate_external_baseline(
    documents: Iterable[dict[str, Any]], baseline: set[str]
) -> tuple[list[str], set[str]]:
    """Mark external SARIF new/unchanged and return live new severities + seen ids.

    gitleaks is deliberately never suppressible by the baseline: a discovered
    credential remains gating until it is removed and rotated.
    """

    from .sarif import is_suppressed
    from .severity import SARIF_LEVEL_TO_SEVERITY

    gating: list[str] = []
    seen: set[str] = set()
    for tool, result in _external_entries(documents):
        fp = external_fingerprint(result)
        if fp is not None:
            seen.add(fp)
        unchanged = tool not in {"gitleaks", "tridelphi-verify"} and fp is not None and fp in baseline
        if fp is not None:
            result["baselineState"] = "unchanged" if unchanged else "new"
        if not unchanged and not is_suppressed(result):
            level = result.get("level")
            gating.append(
                SARIF_LEVEL_TO_SEVERITY.get(level if isinstance(level, str) else "", "warning")
            )
    return gating, seen


def partition(
    findings: Sequence[Finding], baseline: set[str]
) -> tuple[list[Finding], list[Finding], int]:
    """Split into (new, unchanged, stale-baseline-entry-count)."""
    if not baseline:
        return list(findings), [], 0
    new: list[Finding] = []
    unchanged: list[Finding] = []
    seen: set[str] = set()
    for finding in findings:
        fp = fingerprint(finding)
        seen.add(fp)
        (unchanged if fp in baseline else new).append(finding)
    return new, unchanged, len(baseline - seen)
