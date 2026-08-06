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

__all__ = [
    "ZizmorResult",
    "zizmor_path",
    "run_zizmor",
    "merge_runs",
    "summarize_external_run",
]


class ZizmorResult:
    """The outcome of asking zizmor to scan. Exactly one of ``sarif`` or
    ``diagnostic`` is set."""

    __slots__ = ("sarif", "diagnostic", "finding_count")

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

    cmd = [binary, "--format", "sarif"]
    if offline:
        cmd.append("--offline")
    cmd.append(str(workflows))

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(repo_root),
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
    except ValueError:
        return ZizmorResult(
            diagnostic=Diagnostic(
                "zizmor", "zizmor output was not valid SARIF JSON", "warning"
            )
        )

    count = sum(len(run.get("results", [])) for run in document.get("runs", []))
    return ZizmorResult(sarif=document, finding_count=count)


def _empty_run() -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "zizmor", "rules": []}}, "results": []}],
    }


def merge_runs(primary: dict[str, Any], external: dict[str, Any]) -> dict[str, Any]:
    """Append ``external``'s runs to ``primary``'s ``runs`` array.

    Kept as separate runs on purpose: each tool keeps its own driver metadata,
    rule set, and result provenance, which is exactly what SARIF's multi-run
    model is for. The result is deterministic — no reordering of ``primary``.
    """
    merged = dict(primary)
    merged_runs = list(primary.get("runs", []))
    for run in external.get("runs", []):
        merged_runs.append(run)
    merged["runs"] = merged_runs
    return merged


def summarize_external_run(result: ZizmorResult) -> str:
    """One human line for the text renderer."""
    if not result.ok:
        return "zizmor: skipped"
    n = result.finding_count
    return f"zizmor: {n} finding{'s' if n != 1 else ''} (merged into SARIF output)"
