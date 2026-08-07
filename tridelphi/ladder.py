"""The hardening ladder: orchestrate the L1-L6 open-source scanners.

TriDelPhi core is the L3 capability-graph analysis — the finding no per-rule
linter produces. The ladder wraps the commodity rungs below and beside it by
running best-of-breed open-source tools and merging their SARIF alongside ours:

    L1  secrets in the tree      gitleaks        (MIT)
    L2  known-bad dependencies   osv-scanner     (Apache-2.0)
    L3  CI boundary lint         zizmor          (MIT)  + tridelphi core
    L4  repo security posture    scorecard       (Apache-2.0)
    L5  code-level SAST          semgrep         (LGPL-2.1)
    L6  attest & gate            tridelphi attest / tridelphi gate (native)

L6 is not a wrapped tool: it is the spec's two closing processes, implemented
natively in gate_cmd.py — ``tridelphi gate`` re-checks a merged SARIF against
policy as its own step, and ``tridelphi attest`` emits an in-toto evidence
statement over the SARIF for downstream signing.

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
from .orchestrate import MAX_OUTPUT_BYTES, run_zizmor, sarif_shape_error

__all__ = [
    "LADDER",
    "ExternalRun",
    "ToolSpec",
    "credits_text",
    "run_ladder",
    "run_tool",
    "summarize_run",
]

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
    # How the tool reports: "sarif-file" (writes SARIF where told),
    # "sarif-stdout" is handled by the zizmor delegate, "scorecard-json"
    # (JSON on stdout, converted to SARIF by our adapter — observed live:
    # scorecard --local does not support --format sarif).
    output_format: str = "sarif-file"


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

SCORECARD = ToolSpec(
    name="scorecard",
    level=4,
    rung="L4 · repo posture",
    what="OSSF checks for security policy, binary artifacts, token permissions and pinning",
    homepage="https://github.com/ossf/scorecard",
    license="Apache-2.0",
    install_hint="https://github.com/ossf/scorecard#installation",
    # Local mode is file-based, but its Vulnerabilities check queries osv.dev,
    # so the honest label is network.
    network=True,
    ok_exit_codes=frozenset({0}),
    timeout=300,
    output_format="scorecard-json",
)

SEMGREP = ToolSpec(
    name="semgrep",
    level=5,
    rung="L5 · code SAST",
    what="rule-based static analysis of the application code itself",
    homepage="https://github.com/semgrep/semgrep",
    license="LGPL-2.1",
    install_hint="pipx install semgrep",
    network=True,  # fetches the p/security-audit ruleset from the registry
    ok_exit_codes=frozenset({0, 1}),
    timeout=600,
)

# Ordered by rung. TriDelPhi core is not in this list on purpose: it is the
# native analysis and always runs; the ladder is only the wrapped tools. L6 is
# native too (gate_cmd.py) — the ladder's registry ends at the wrapped rungs.
LADDER: tuple[ToolSpec, ...] = (GITLEAKS, OSV_SCANNER, ZIZMOR, SCORECARD, SEMGREP)
MAX_LEVEL = 6


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
            for result in _iter_results(sarif):
                # The level is attacker-influenced like the rest of the
                # document: anything that is not a known SARIF level string
                # (wrong type included) counts as the SARIF default, warning.
                level = result.get("level")
                if not isinstance(level, str):
                    level = "warning"
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
        elif spec is SCORECARD:
            # Local mode emits JSON on stdout only (no SARIF, no --output —
            # both observed live); the adapter below converts it.
            cmd = [binary, "--local", ".", "--format", "json"]
        elif spec is SEMGREP:
            # A named public ruleset with metrics off: never `--config auto`,
            # which uploads project metadata to the registry.
            cmd = [
                binary, "scan",
                "--config", "p/security-audit",
                "--sarif", "--output", str(report),
                "--metrics", "off",
                "--disable-version-check",
                "--quiet",
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

        if spec.output_format == "scorecard-json":
            raw = completed.stdout or ""
            if len(raw.encode("utf-8", errors="replace")) > MAX_OUTPUT_BYTES:
                return _skip(
                    spec,
                    f"{spec.name} produced over {MAX_OUTPUT_BYTES // (1024 * 1024)} MB "
                    "of output; refusing to parse it",
                )
        else:
            if not report.is_file():
                return _skip(spec, f"{spec.name} ran but wrote no report; skipped")
            if report.stat().st_size > MAX_OUTPUT_BYTES:
                return _skip(
                    spec,
                    f"{spec.name} produced a report over {MAX_OUTPUT_BYTES // (1024 * 1024)} MB; "
                    "refusing to parse it",
                )
            raw = report.read_text(encoding="utf-8", errors="replace")

    if spec.output_format == "scorecard-json":
        document = _scorecard_to_sarif(spec, raw)
    else:
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

    defect = sarif_shape_error(document)
    if defect is not None:
        return _skip(spec, f"{spec.name} {defect}; skipped")
    return document


_SCORECARD_DOCS = "https://github.com/ossf/scorecard/blob/main/docs/checks.md"


def _scorecard_to_sarif(spec: ToolSpec, raw: str) -> dict[str, Any] | ExternalRun:
    """Convert scorecard's local-mode JSON into a SARIF run.

    Mapping, chosen to be honest rather than alarming: a check is a finding
    only when its score says the posture is actually weak. Scores are 0-10;
    -1 means the check did not apply and is dropped.

        score 0-3   -> SARIF "warning"  (posture gap worth fixing)
        score 4-7   -> SARIF "note"     (partial credit, informational)
        score 8-10  -> no finding

    Results carry no file locations because local-mode scorecard reports
    repo-level posture, not line-level defects. Checks are sorted by name so
    the run is deterministic. The constructed document still goes through the
    shared shape gate afterwards — the converter is not exempt from the
    containment bar it feeds.
    """
    try:
        doc = json.loads(raw)
    except ValueError:
        return _skip(spec, f"{spec.name} output was not valid JSON; skipped")
    if not isinstance(doc, dict) or not isinstance(doc.get("checks"), list):
        return _skip(spec, f"{spec.name} output had no checks list; skipped")

    version = "unknown"
    meta = doc.get("scorecard")
    if isinstance(meta, dict) and isinstance(meta.get("version"), str):
        version = meta["version"].lstrip("v")

    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    checks = [c for c in doc["checks"] if isinstance(c, dict)]
    for check in sorted(checks, key=lambda c: str(c.get("name", ""))):
        name = check.get("name")
        score = check.get("score")
        if not isinstance(name, str) or not isinstance(score, int):
            continue
        if score < 0 or score >= 8:  # -1 = not applicable; 8+ = healthy
            continue
        level = "warning" if score <= 3 else "note"
        reason = check.get("reason")
        reason = reason if isinstance(reason, str) else ""
        rule_id = f"scorecard/{name}"
        anchor = name.lower()
        rules.append(
            {
                "id": rule_id,
                "name": name.replace("-", ""),
                "shortDescription": {"text": f"OSSF Scorecard: {name}"},
                "helpUri": f"{_SCORECARD_DOCS}#{anchor}",
            }
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f"{name} scored {score}/10: {reason}".strip()},
            }
        )

    document = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": spec.name,
                        "semanticVersion": version,
                        "informationUri": spec.homepage,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    defect = sarif_shape_error(document)
    if defect is not None:  # pragma: no cover - converter and gate out of sync
        return _skip(spec, f"{spec.name} converted {defect}; skipped")
    return document


def _iter_results(document: dict[str, Any]):
    """Results of every run, defensively: shapes the gate rejects yield nothing.

    Post-processing must never assume a shape ``sarif_shape_error`` has not
    checked — and must survive even documents that bypassed the gate (the
    internally constructed empty runs), so each level re-checks its own type.
    """
    runs = document.get("runs", [])
    if not isinstance(runs, list):
        return
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results", [])
        if not isinstance(results, list):
            continue
        for result in results:
            if isinstance(result, dict):
                yield result


def _iter_result_locations(document: dict[str, Any]):
    """Every location dict of every result, with the same defensive posture."""
    for result in _iter_results(document):
        locations = result.get("locations", [])
        if not isinstance(locations, list):
            continue
        for location in locations:
            if isinstance(location, dict):
                yield location


def _normalize_uris(document: dict[str, Any], root: Path) -> None:
    """Rewrite absolute ``file://`` URIs to repo-relative paths, in place.

    osv-scanner emits ``file:///abs/path/to/package-lock.json``; GitHub code
    scanning can only annotate files it can resolve relative to the repo root.
    zizmor emits URIs relative to the *enclosing git root* (observed live), so
    when the scanned root is a subdirectory of a git repo — monorepos, our own
    fixtures — the URIs carry a computable prefix that must be stripped. URIs
    outside the root are left untouched rather than guessed at -- except a
    relative URI that climbs out via "..", which is rewritten to an
    unambiguous absolute ``file://`` URI (see ``_relativize``): a wrapped
    scanner's output is attacker-influenced, and a "../"-escaping relative
    path is the one out-of-root shape that would otherwise look identical to
    a legitimate in-repo path to a downstream consumer resolving it.
    """
    resolved = root.resolve()
    git_prefix = _git_prefix(resolved)
    for location in _iter_result_locations(document):
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
    if (root / ".git").exists():
        return None  # root IS the git root; there is no prefix to strip
    for ancestor in root.parents:
        if (ancestor / ".git").exists():
            return root.relative_to(ancestor).as_posix() + "/"
    return None


def _relativize(uri: str, root: Path, git_prefix: str | None) -> str | None:
    if uri.startswith("file://"):
        path = Path(unquote(urlparse(uri).path))
    elif uri.startswith("/"):
        path = Path(uri)
    else:
        # A relative URI: either already relative to the scanned root, or (for
        # zizmor inside a monorepo) relative to the enclosing git root, in
        # which case the computable prefix is stripped first.
        candidate = uri
        if git_prefix and uri.startswith(git_prefix):
            candidate = uri[len(git_prefix):]
        # Either way it must not climb out via "..". Unlike an absolute or
        # file:// URI outside the root, a "../"-escaping relative URI is
        # indistinguishable from a legitimate in-repo path to a naive resolver,
        # so it cannot be passed through: rewrite it to an unambiguous absolute
        # file:// URI that can never be mistaken for a path inside the scanned
        # root. The check runs on the percent-decoded form because that is what
        # a URI consumer resolves ("%2e%2e/" is "../" to them).
        resolved = (root / unquote(candidate)).resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            return f"file://{resolved.as_posix()}"
        return candidate if candidate != uri else None
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
    for location in _iter_result_locations(document):
        physical = location.get("physicalLocation")
        if not isinstance(physical, dict):
            continue
        artifact = physical.get("artifactLocation")
        if not isinstance(artifact, dict):
            continue
        uri = artifact.get("uri")
        if isinstance(uri, str) and not uri.startswith((".github/workflows/", "/", "file:")):
            artifact["uri"] = f".github/workflows/{uri}"


def _override_levels(document: dict[str, Any], level: str) -> None:
    """Force every result to ``level``, in place. See the module docstring."""
    for result in _iter_results(document):
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
    lines.append(
        "L6 (attest & gate) is native too: `tridelphi attest` and `tridelphi gate` — "
        "no wrapped tool, nothing further to install."
    )
    return "\n".join(lines)
