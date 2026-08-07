"""The hardening ladder: orchestrate the L1-L3 open-source scanners.

TriDelPhi core is the L3 capability-graph analysis — the finding no per-rule
linter produces. The ladder wraps the commodity rungs below and beside it by
running best-of-breed open-source tools and merging their SARIF alongside ours:

    L1  secrets in the tree      gitleaks        (MIT)
    L2  known-bad dependencies   osv-scanner     (Apache-2.0)
    L3  CI boundary lint         zizmor          (MIT)  + tridelphi core

``--level N`` runs every rung up to and including N; rungs are cumulative
because the ladder's ordering is signal density, not preference. TriDelPhi core
always runs — it is the native layer, not a wrapped one.

Trust and safety properties, in order of importance:

* **Off by default.** A bare ``tridelphi .`` spawns no subprocess and touches
  no network. Rungs run only when explicitly requested.
* **Graceful when absent.** Each wrapped tool is a separate binary the user may
  not have. A missing binary is a diagnostic with an install hint, never a
  crash — the TriDelPhi findings always survive.
* **Hostile output is contained.** The wrapped tools scan attacker-influenced
  repo content, so their output is parsed defensively: bounded in size,
  JSON-decoded, and structurally checked before a byte of it reaches the merged
  SARIF document. Anything malformed becomes a diagnostic.
* **Honest about the network.** gitleaks and zizmor run fully offline;
  osv-scanner queries https://osv.dev to match lockfiles against known CVEs.
  A tool that needs the network says so in its credit line and is skipped (with
  a diagnostic) under ``--offline``.

Severity note: gitleaks emits SARIF results without a ``level``, which SARIF
defaults to "warning". A live credential in the tree is not a warning — the L1
rung exists to block on it — so gitleaks results are escalated to "error" both
in the merged SARIF and in gating. Other tools keep their own levels.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from .model import Diagnostic
from .orchestrate import run_zizmor

__all__ = [
    "LADDER",
    "ExternalRun",
    "ToolSpec",
    "credits_text",
    "run_ladder",
    "run_tool",
    "summarize_run",
]

# Refuse to parse tool output larger than this. The wrapped tools scan
# attacker-influenced content; a report this size is an attack or a bug, and
# either way it does not belong in memory or in the merged document.
MAX_OUTPUT_BYTES = 25 * 1024 * 1024

_SARIF_LEVEL_TO_SEVERITY = {"error": "critical", "warning": "warning", "note": "note", "none": "note"}


@dataclass(frozen=True)
class ToolSpec:
    """One wrapped open-source scanner: how to run it and whom to credit."""

    name: str
    level: int  # ladder rung (1-based); --level N runs every spec with level <= N
    rung: str  # human name of the rung, e.g. "L1 · secrets"
    what: str  # one line: what the tool contributes
    homepage: str
    license: str
    install_hint: str
    network: bool  # True if the tool talks to the internet while scanning
    ok_exit_codes: frozenset[int]  # exit codes that mean "ran fine" (findings included)
    timeout: int  # seconds
    severity_override: str | None = None  # force every result to this SARIF level
    # Exit codes that mean "nothing here for me to scan" — a clean empty run,
    # not a failure (e.g. osv-scanner in a repo with no lockfiles).
    no_targets_exit_codes: frozenset[int] = frozenset()


GITLEAKS = ToolSpec(
    name="gitleaks",
    level=1,
    rung="L1 · secrets",
    what="finds credentials committed to the tree before an attacker does",
    homepage="https://github.com/gitleaks/gitleaks",
    license="MIT",
    install_hint="https://github.com/gitleaks/gitleaks#installing",
    network=False,
    ok_exit_codes=frozenset({0, 1}),  # 1 = leaks found, which is a successful scan
    timeout=300,
    severity_override="error",
)

OSV_SCANNER = ToolSpec(
    name="osv-scanner",
    level=2,
    rung="L2 · supply chain",
    what="matches your lockfiles against the OSV database of known-vulnerable packages",
    homepage="https://github.com/google/osv-scanner",
    license="Apache-2.0",
    install_hint="https://google.github.io/osv-scanner/installation/",
    network=True,  # queries https://osv.dev
    ok_exit_codes=frozenset({0, 1}),  # 1 = vulnerabilities found
    timeout=300,
    no_targets_exit_codes=frozenset({128}),  # observed live: "No package sources found"
)

ZIZMOR = ToolSpec(
    name="zizmor",
    level=3,
    rung="L3 · CI boundary",
    what="lints GitHub Actions workflows for unpinned actions, template injection and more",
    homepage="https://github.com/zizmorcore/zizmor",
    license="MIT",
    install_hint="pipx install zizmor",
    network=False,  # we always pass --offline unless the user opts in
    ok_exit_codes=frozenset({0, 13, 14}),
    timeout=120,
)

# Ordered by rung. TriDelPhi core is not in this list on purpose: it is the
# native analysis and always runs; the ladder is only the wrapped tools.
LADDER: tuple[ToolSpec, ...] = (GITLEAKS, OSV_SCANNER, ZIZMOR)


class ExternalRun:
    """Outcome of one wrapped tool. Exactly one of ``sarif``/``diagnostic`` set."""

    __slots__ = ("diagnostic", "finding_count", "sarif", "severity_counts", "spec")

    def __init__(
        self,
        spec: ToolSpec,
        sarif: dict[str, Any] | None = None,
        diagnostic: Diagnostic | None = None,
    ) -> None:
        self.spec = spec
        self.sarif = sarif
        self.diagnostic = diagnostic
        self.severity_counts: dict[str, int] = {"critical": 0, "warning": 0, "note": 0}
        if sarif is not None:
            for run in sarif.get("runs", []):
                for result in run.get("results", []):
                    level = result.get("level") or "warning"  # SARIF default
                    severity = _SARIF_LEVEL_TO_SEVERITY.get(level, "warning")
                    self.severity_counts[severity] += 1
        self.finding_count = sum(self.severity_counts.values())

    @property
    def ok(self) -> bool:
        return self.sarif is not None


def _binary(spec: ToolSpec) -> str | None:
    return shutil.which(spec.name)


def _skip(spec: ToolSpec, message: str) -> ExternalRun:
    return ExternalRun(spec, diagnostic=Diagnostic(spec.name, message, "warning"))


def run_tool(
    spec: ToolSpec,
    repo_root: str | Path,
    *,
    offline: bool = False,
    zizmor_online: bool = False,
) -> ExternalRun:
    """Run one wrapped scanner over ``repo_root`` and contain its output.

    ``offline`` is the user's "no network at all" demand: tools that need the
    network are skipped with a diagnostic. ``zizmor_online`` is the separate
    opt-in to zizmor's online audits; ``offline`` always wins over it.
    """
    root = Path(repo_root)

    if spec.network and offline:
        return _skip(
            spec,
            f"{spec.name} needs the network (it queries a vulnerability database) and "
            "--offline is set; skipped. Drop --offline to run this rung.",
        )

    if spec is ZIZMOR:
        # Delegate to the existing zizmor runner so --with-zizmor and --level 3
        # share one code path and one set of tests. zizmor gets --offline unless
        # the user explicitly opted into its online audits.
        zres = run_zizmor(root, offline=offline or not zizmor_online, timeout=spec.timeout)
        if zres.sarif is not None:
            _normalize_uris(zres.sarif, root)
            _ensure_workflow_prefix(zres.sarif)
        return ExternalRun(ZIZMOR, sarif=zres.sarif, diagnostic=zres.diagnostic)

    binary = _binary(spec)
    if binary is None:
        return _skip(
            spec,
            f"{spec.rung} was requested but {spec.name} is not on PATH; skipped. "
            f"Install it ({spec.install_hint}) or lower --level. "
            "TriDelPhi's own findings are unaffected.",
        )

    with tempfile.TemporaryDirectory(prefix="tridelphi-") as tmp:
        report = Path(tmp) / f"{spec.name}.sarif"
        if spec is GITLEAKS:
            # `dir` scans the working tree (not git history) with URIs relative
            # to the scanned path, which is what code scanning wants.
            cmd = [
                binary, "dir", ".",
                "--no-banner",
                "--report-format", "sarif",
                "--report-path", str(report),
            ]
        elif spec is OSV_SCANNER:
            cmd = [
                binary, "scan", "source", "--recursive",
                "--format", "sarif",
                "--output", str(report),
                ".",
            ]
        else:  # pragma: no cover - registry and runner out of sync
            return _skip(spec, f"no runner wired for {spec.name}")

        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=spec.timeout,
                cwd=str(root),
            )
        except FileNotFoundError:  # pragma: no cover - race with which()
            return _skip(spec, f"{spec.name} vanished between lookup and run")
        except subprocess.TimeoutExpired:
            return _skip(spec, f"{spec.name} did not finish within {spec.timeout}s; skipped")

        if completed.returncode in spec.no_targets_exit_codes:
            return ExternalRun(spec, sarif=_empty_document(spec))
        if completed.returncode not in spec.ok_exit_codes:
            stderr = (completed.stderr or "").strip()[:200]
            return _skip(spec, f"{spec.name} exited {completed.returncode}: {stderr}")

        if not report.is_file():
            return _skip(spec, f"{spec.name} ran but wrote no report; skipped")
        if report.stat().st_size > MAX_OUTPUT_BYTES:
            return _skip(
                spec,
                f"{spec.name} produced a report over {MAX_OUTPUT_BYTES // (1024 * 1024)} MB; "
                "refusing to parse it",
            )
        raw = report.read_text(encoding="utf-8", errors="replace")

    document = _contained_parse(spec, raw)
    if isinstance(document, ExternalRun):
        return document
    _normalize_uris(document, root)
    if spec.severity_override:
        _override_levels(document, spec.severity_override)
    return ExternalRun(spec, sarif=document)


def _empty_document(spec: ToolSpec) -> dict[str, Any]:
    """A clean SARIF run for a tool that found nothing to scan."""
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": spec.name, "rules": []}}, "results": []}],
    }


def _contained_parse(spec: ToolSpec, raw: str) -> dict[str, Any] | ExternalRun:
    """Parse tool output defensively. Returns the document or a skip result."""
    try:
        document = json.loads(raw)
    except ValueError:
        return _skip(spec, f"{spec.name} output was not valid SARIF JSON; skipped")

    if not isinstance(document, dict) or not isinstance(document.get("runs"), list):
        return _skip(spec, f"{spec.name} output was not a SARIF document; skipped")
    for run in document["runs"]:
        if not isinstance(run, dict):
            return _skip(spec, f"{spec.name} output had a malformed run; skipped")
        results = run.get("results", [])
        if not isinstance(results, list) or any(not isinstance(r, dict) for r in results):
            return _skip(spec, f"{spec.name} output had malformed results; skipped")
        driver = run.get("tool", {})
        if not isinstance(driver, dict) or not isinstance(driver.get("driver"), dict):
            return _skip(spec, f"{spec.name} output had no tool.driver; skipped")
    return document


def _normalize_uris(document: dict[str, Any], root: Path) -> None:
    """Rewrite absolute ``file://`` URIs to repo-relative paths, in place.

    osv-scanner emits ``file:///abs/path/to/package-lock.json``; GitHub code
    scanning can only annotate files it can resolve relative to the repo root.
    zizmor emits URIs relative to the *enclosing git root* (observed live), so
    when the scanned root is a subdirectory of a git repo — monorepos, our own
    fixtures — the URIs carry a computable prefix that must be stripped. URIs
    outside the root are left untouched rather than guessed at.
    """
    resolved = root.resolve()
    git_prefix = _git_prefix(resolved)
    for run in document.get("runs", []):
        for result in run.get("results", []):
            for location in result.get("locations", []):
                physical = location.get("physicalLocation")
                if not isinstance(physical, dict):
                    continue
                artifact = physical.get("artifactLocation")
                if not isinstance(artifact, dict):
                    continue
                uri = artifact.get("uri")
                if not isinstance(uri, str):
                    continue
                new = _relativize(uri, resolved, git_prefix)
                if new is not None:
                    artifact["uri"] = new
                    artifact.pop("uriBaseId", None)


def _git_prefix(root: Path) -> str | None:
    """``root``'s path relative to the enclosing git root, or None if it is the
    git root itself (or not in one)."""
    for ancestor in root.parents:
        if (ancestor / ".git").exists():
            return root.relative_to(ancestor).as_posix() + "/"
    return None


def _relativize(uri: str, root: Path, git_prefix: str | None) -> str | None:
    if uri.startswith("file://"):
        path = Path(unquote(urlparse(uri).path))
    elif uri.startswith("/"):
        path = Path(uri)
    elif git_prefix and uri.startswith(git_prefix):
        # Relative to the enclosing git root rather than the scanned root.
        return uri[len(git_prefix):]
    else:
        return None  # already relative to the scanned root
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return None  # outside the repo; do not guess


def _ensure_workflow_prefix(document: dict[str, Any]) -> None:
    """Anchor zizmor's URIs under ``.github/workflows/``, in place.

    zizmor only ever scanned that directory (see run_zizmor), so every result
    file lives there. Outside a git repo it emits URIs relative to the scan
    target ("ci.yml"); inside one, _normalize_uris has already produced the
    fully prefixed form and this is a no-op.
    """
    for run in document.get("runs", []):
        for result in run.get("results", []):
            for location in result.get("locations", []):
                artifact = (location.get("physicalLocation") or {}).get("artifactLocation")
                if not isinstance(artifact, dict):
                    continue
                uri = artifact.get("uri")
                if isinstance(uri, str) and not uri.startswith((".github/workflows/", "/", "file:")):
                    artifact["uri"] = f".github/workflows/{uri}"


def _override_levels(document: dict[str, Any], level: str) -> None:
    """Force every result to ``level``, in place. See the module docstring."""
    for run in document.get("runs", []):
        for result in run.get("results", []):
            result["level"] = level


def run_ladder(
    repo_root: str | Path, *, level: int, offline: bool = False, zizmor_online: bool = False
) -> list[ExternalRun]:
    """Run every rung up to and including ``level``, in ladder order."""
    return [
        run_tool(spec, repo_root, offline=offline, zizmor_online=zizmor_online)
        for spec in LADDER
        if spec.level <= level
    ]


def summarize_run(run: ExternalRun) -> str:
    """One human line per tool for the text renderer."""
    if not run.ok:
        return f"{run.spec.name}: skipped"
    n = run.finding_count
    return f"{run.spec.name}: {n} finding{'s' if n != 1 else ''} (merged into SARIF output)"


def credits_text() -> str:
    """The attribution table for ``--credits``.

    TriDelPhi's ladder orchestrates other people's excellent work; naming them
    is part of the product, not a footnote.
    """
    lines = [
        "TriDelPhi wraps these open-source scanners for the ladder rungs.",
        "Install them to use --level; each is credited in the merged SARIF as its own run.",
        "",
    ]
    for spec in LADDER:
        net = "queries the network while scanning" if spec.network else "runs fully offline"
        lines.append(f"  {spec.rung:20} {spec.name}  ({spec.license})")
        lines.append(f"  {'':20} {spec.what}; {net}")
        lines.append(f"  {'':20} {spec.homepage}")
        lines.append("")
    lines.append("TriDelPhi core (the capability-graph analysis) is native and always runs.")
    return "\n".join(lines)
