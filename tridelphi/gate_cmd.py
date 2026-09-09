"""L6 — the spec's two closing processes: ``tridelphi gate`` and ``tridelphi attest``.

The original TRIAD spec ends the ladder with two separate invocations, and the
separation is the point:

* ``tridelphi gate <sarif>`` re-checks an already-produced SARIF document
  against the fail policy, as its own process with its own exit code. Scanning
  and gating being separate steps means the gate can run in a different job
  (or a different workflow entirely) from the scan, the scan's artifacts can be
  uploaded before the gate fails the build, and a policy change re-gates old
  scans without re-scanning.

* ``tridelphi attest <sarif>`` emits an in-toto Statement over the SARIF: the
  file's digest as the subject, and what produced it (tools, versions, counts)
  as the predicate. It is deliberately unsigned — signing is sigstore's job,
  not ours. Feed the evidence file to ``actions/attest-build-provenance``
  (``subject-path:``) and GitHub signs it with the workflow's OIDC identity.
  The statement contains no timestamp so it is byte-deterministic for a given
  SARIF and environment; determinism is a feature everywhere in TriDelPhi.

Both commands treat the SARIF as untrusted input (it may embed wrapped-scanner
output influenced by a hostile repo) and go through the same structural gate as
the ladder's runners.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

from . import __version__
from .fsutil import atomic_write_text
from .orchestrate import MAX_OUTPUT_BYTES, sarif_shape_error
from .sarif import severity_counts
from .severity import SEVERITY_ORDER as _SEVERITY_RANK

__all__ = ["run_attest", "run_gate"]

EVIDENCE_PREDICATE_TYPE = "https://girnarholdings.github.io/TriDelPhi/evidence/v1"


def _load_sarif(path: str, err) -> tuple[dict, bytes] | None:
    """Read and structurally validate SARIF, retaining the exact parsed bytes."""
    target = Path(path)
    try:
        if not target.is_file():
            print(f"tridelphi: {path} is not a file", file=err)
            return None
        with target.open("rb") as handle:
            raw = handle.read(MAX_OUTPUT_BYTES + 1)
        if len(raw) > MAX_OUTPUT_BYTES:
            print(f"tridelphi: {path} exceeds the size limit; refusing to parse", file=err)
            return None
        document = json.loads(raw.decode("utf-8"))
    except OSError as exc:
        print(f"tridelphi: cannot read {path}: {exc}", file=err)
        return None
    except (ValueError, RecursionError):
        print(f"tridelphi: {path} is not valid JSON", file=err)
        return None
    defect = sarif_shape_error(document)
    if defect is not None:
        print(f"tridelphi: {path}: {defect}", file=err)
        return None
    return document, raw


def _run_summaries(document: dict) -> list[dict]:
    """Per-run tool name, version and severity counts, in document order."""
    summaries = []
    for run in document["runs"]:
        driver = run["tool"]["driver"]
        counts = severity_counts(run.get("results", []))
        name = driver.get("name")
        version = driver.get("semanticVersion") or driver.get("version")
        summaries.append(
            {
                "tool": name if isinstance(name, str) else "unknown",
                "version": version if isinstance(version, str) else None,
                "results": sum(counts.values()),
                "severities": counts,
            }
        )
    return summaries


def run_gate(sarif_path: str, *, fail_on: str = "critical", out=None, err=None) -> int:
    """Enforce the fail policy against an existing SARIF document.

    Exit codes match the scanner's contract: 0 pass, 1 findings at or above
    ``fail_on``, 2 the document could not be read at all.
    """
    out = out or sys.stdout
    err = err or sys.stderr
    if fail_on not in {*_SEVERITY_RANK, "none"}:
        print(f"tridelphi: unknown fail threshold: {fail_on}", file=err)
        return 2
    loaded = _load_sarif(sarif_path, err)
    if loaded is None:
        return 2
    document, _raw = loaded

    summaries = _run_summaries(document)
    total = {"critical": 0, "warning": 0, "note": 0}
    for summary in summaries:
        for severity, count in summary["severities"].items():
            total[severity] += count
        line = ", ".join(f"{v} {k}" for k, v in summary["severities"].items() if v)
        print(f"  {summary['tool']}: {line or 'clean'}", file=out)

    if fail_on == "none":
        print("gate: pass (policy: fail-on none)", file=out)
        return 0
    threshold = _SEVERITY_RANK[fail_on]
    blocking = sum(
        count for severity, count in total.items() if _SEVERITY_RANK[severity] <= threshold
    )
    if blocking:
        print(
            f"gate: FAIL — {blocking} finding{'s' if blocking != 1 else ''} at or above "
            f"'{fail_on}' across {len(summaries)} run{'s' if len(summaries) != 1 else ''}",
            file=out,
        )
        return 1
    print(f"gate: pass — nothing at or above '{fail_on}'", file=out)
    return 0


def run_attest(
    sarif_path: str,
    *,
    evidence_path: str = "tridelphi-evidence.json",
    out=None,
    err=None,
) -> int:
    """Write an in-toto Statement over the SARIF file.

    Exit codes: 0 written, 2 the SARIF could not be read.
    """
    out = out or sys.stdout
    err = err or sys.stderr
    loaded = _load_sarif(sarif_path, err)
    if loaded is None:
        return 2
    document, raw = loaded
    digest = hashlib.sha256(raw).hexdigest()
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": Path(sarif_path).name, "digest": {"sha256": digest}}],
        "predicateType": EVIDENCE_PREDICATE_TYPE,
        "predicate": {
            "scanner": {"name": "tridelphi", "version": __version__},
            "runs": _run_summaries(document),
            # Populated under GitHub Actions; null elsewhere. No timestamp on
            # purpose — the statement must be reproducible from its inputs.
            "source": {
                "repository": os.environ.get("GITHUB_REPOSITORY"),
                "commit": os.environ.get("GITHUB_SHA"),
            },
        },
    }
    evidence = Path(evidence_path)
    try:
        atomic_write_text(
            evidence,
            json.dumps(statement, indent=2, sort_keys=True) + "\n",
            create_parent=True,
            mode=0o644,
        )
    except OSError as exc:
        print(f"tridelphi: cannot write {evidence_path}: {exc}", file=err)
        return 2
    print(f"wrote {evidence_path} (sha256:{digest[:12]}… over {Path(sarif_path).name})", file=out)
    print(
        "sign it: pass this file to actions/attest-build-provenance as subject-path",
        file=out,
    )
    return 0
