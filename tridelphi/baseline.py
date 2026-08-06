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
from pathlib import Path
from typing import Sequence

from .model import Finding
from .sarif import fingerprint

__all__ = ["DEFAULT_BASELINE", "load_baseline", "write_baseline", "partition"]

DEFAULT_BASELINE = ".tridelphi-baseline.json"
_VERSION = 1


def load_baseline(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    try:
        doc = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return set()
    entries = doc.get("fingerprints") or []
    return {e["fp"] for e in entries if isinstance(e, dict) and "fp" in e}


def write_baseline(path: Path, findings: Sequence[Finding], tool_version: str) -> int:
    entries = [
        {
            "fp": fingerprint(f),
            "rule": f.rule_id,
            "note": f"{f.context.workflow_file} :: {f.context.job_id}",
        }
        for f in sorted(findings, key=lambda f: f.sort_key)
    ]
    document = {
        "version": _VERSION,
        "generated_by": f"tridelphi {tool_version}",
        "fingerprints": entries,
    }
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return len(entries)


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
