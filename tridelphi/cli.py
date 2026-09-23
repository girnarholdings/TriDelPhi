"""Argument parsing, exit codes, orchestration. No analysis logic lives here.

Exit codes are an API:
    0  no findings at or above --fail-on
    1  findings at or above --fail-on
    2  execution error (bad path, unreadable root, bad arguments)

``--min-severity`` (what you see) and ``--fail-on`` (what breaks the build) are
separate axes. Conflating them is the classic linter mistake: it forces users to
choose between seeing near-misses and having a green build, and they resolve it
by uninstalling.

Every diagnostic goes to stderr so ``--format sarif > out.sarif`` stays valid
JSON.
"""

from __future__ import annotations

import argparse
import contextlib
import sys
import time
from collections.abc import Callable
from pathlib import Path

from . import __version__
from .api import AnalysisError, analyze
from .baseline import (
    DEFAULT_BASELINE,
    annotate_external_baseline,
    load_baseline,
    partition,
    write_baseline,
)
from .checklist import ExternalStatus as ChecklistStatus
from .checklist import item_counts, items_from_sarif, render_checklist, render_checklist_markdown
from .coverage import render_coverage
from .fsutil import atomic_write_text
from .html_report import render_html
from .ladder import ZIZMOR, credits_text, run_ladder, run_tool, summarize_run
from .model import RULES
from .orchestrate import merge_runs
from .render import render_text
from .sarif import dumps, fingerprint, to_sarif
from .severity import SARIF_LEVEL_TO_SEVERITY, should_fail
from .severity import SEVERITIES as _SEVERITIES

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tridelphi",
        description=(
            "Security guardrails for first-time builders: check code before installing "
            "it, check GitHub robots for secret-stealing paths, or check what your app ships."
        ),
        epilog=(
            "Run `tridelphi start` for the three plain-English starting points. "
            "Core/expose are local; registry targets and requested ladder tools say "
            "when they need the network."
        ),
    )
    parser.add_argument(
        "path", nargs="?", default=".",
        help=(
            "repository root, or a command: `start` shows the three beginner paths, "
            "`init` adds the scan workflow, `audit` runs all three native checks offline, `scan` "
            "audits someone else's code BEFORE you install it (a dir, an archive, "
            "npm:<pkg> or pypi:<pkg>), `fix` prints a remediation plan, `guard` "
            "fixes interactively, `expose` audits shipped-asset/DB/data exposure, "
            "`privatize` obfuscates built JS (default: .)"
        ),
    )
    parser.add_argument("command", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--force", action="store_true", help="with init: overwrite an existing workflow or hook")
    parser.add_argument(
        "--local", action="store_true",
        help="with init: no CI at all — install a git pre-push hook that runs the "
             "same scans on this machine before every push",
    )
    parser.add_argument(
        "--wizard", action="store_true",
        help="with init: click-through setup — choose level, expose, threshold, and write "
             "a one-line composite-action workflow",
    )
    parser.add_argument(
        "--app", action="store_true",
        help="with init: write the app-exposure workflow instead — build, then audit what "
             "your shipped product leaks. No ladder, no gate.",
    )
    parser.add_argument(
        "--from-source", action="store_true",
        help="with init: write the long transparent workflow (installs the CLI and runs "
             "every step in the open) instead of the short composite-action one",
    )
    parser.add_argument(
        "--markdown", action="store_true",
        help="with `fix`: render the plan as Markdown to paste into a PR or ticket",
    )
    parser.add_argument(
        "--include-warnings", action="store_true",
        help="with `fix`/`guard`: also handle the two-power near-misses, not just criticals",
    )
    parser.add_argument(
        "--apply", action="store_true",
        help="with `fix`: apply the automatic fixes (batch; every edit verified or rolled back)",
    )
    parser.add_argument(
        "-y", "--yes", action="store_true",
        help="with `guard`: apply verified fixes; with `verify --write-trust-lock`: "
             "deliberately replace an existing lock (never enables privatize)",
    )
    parser.add_argument(
        "--build-cmd", metavar="CMD",
        help="with `privatize`: a command that must still pass on the obfuscated build",
    )
    parser.add_argument(
        "--smoke-cmd", metavar="CMD",
        help="with `privatize`: a boot/smoke check; without it, privatize only writes "
             "a copy and never swaps your live output",
    )
    parser.add_argument(
        "--privatize-out", metavar="DIR",
        help="with `privatize`: the built-output directory to obfuscate (default: dist/build/out)",
    )
    parser.add_argument(
        "--asset-root",
        action="append",
        default=[],
        metavar="DIR",
        help=(
            "with `expose`: also treat this repo-relative directory as shipped output; "
            "repeat for monorepos or custom build folders"
        ),
    )
    parser.add_argument(
        "-f", "--format", choices=("text", "checklist", "sarif", "json", "html"), default=None,
        help=(
            "output format. Default: 'checklist' at an interactive terminal — the "
            "plain-language, no-jargon report a first-time user can act on — and "
            "'text' (the U/P/E detail) when stdout is a pipe, a file or CI, so "
            "existing scripts are unchanged. 'html' is browsable; 'sarif' is the "
            "machine contract."
        ),
    )
    parser.add_argument("--sarif-file", metavar="PATH", help="also write SARIF here")
    parser.add_argument("--html-file", metavar="PATH", help="also write an HTML report here")
    parser.add_argument(
        "--checklist-md-file", metavar="PATH",
        help=(
            "also write the checklist as GitHub Markdown here (status table + "
            "folded details) — what the PR bot posts, and what the email shows"
        ),
    )
    parser.add_argument("--min-severity", choices=_SEVERITIES, default="critical")
    parser.add_argument(
        "--fail-on", choices=(*_SEVERITIES, "none"), default="critical",
        help="exit 1 when a finding at or above this level exists (default: critical)",
    )
    parser.add_argument("--baseline", metavar="PATH", default=None)
    parser.add_argument("--no-baseline", action="store_true")
    parser.add_argument("--write-baseline", nargs="?", const=DEFAULT_BASELINE, metavar="PATH")
    parser.add_argument(
        "--assume-default-permissions", choices=("read", "write"), default="write",
        help="repository default GITHUB_TOKEN permission when a job declares none",
    )
    parser.add_argument(
        "--level", type=int, choices=(1, 2, 3, 4, 5, 6, 7), default=None,
        help=(
            "run the hardening ladder up to this rung: 1 secrets (gitleaks), "
            "2 +supply chain (osv-scanner, queries osv.dev), 3 +CI lint (zizmor), "
            "4 +repo posture (scorecard), 5 +code SAST (semgrep), 6 +attest "
            "(writes the evidence statement), 7 +trust (verify consumed actions "
            "against the trust-lock). Rungs are cumulative; core always runs. "
            "Omit --level to run the core Rule-of-Two scan only (no external "
            "tools) — the CLI has no default rung; the GitHub Action defaults to "
            "level 3. See --credits."
        ),
    )
    parser.add_argument(
        "--evidence-file", metavar="PATH", default="tridelphi-evidence.json",
        help="with `attest` or --level 6: where to write the in-toto evidence statement",
    )
    parser.add_argument(
        "--trust-lock", metavar="PATH", default=None,
        help="with `verify` or --level 7: the trust-lock file (default: .tridelphi/trust.lock)",
    )
    parser.add_argument(
        "--write-trust-lock", action="store_true",
        help="with `verify`: record full-SHA action identities and exit; replacing an "
             "existing lock also requires --yes (prefer --relock for normal updates)",
    )
    parser.add_argument(
        "--relock", action="store_true",
        help="with `verify`: re-record pins that moved (an intentional update), but "
             "refuse if an action changed owner — that needs a human",
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="with --level: skip rungs that need the network (osv-scanner)",
    )
    parser.add_argument(
        "--with-zizmor", action="store_true",
        help="also run zizmor (if installed) and merge its findings into the SARIF output",
    )
    parser.add_argument(
        "--zizmor-online", action="store_true",
        help="allow zizmor's online audits (requires GH_TOKEN; not air-gap safe)",
    )
    parser.add_argument(
        "--credits", action="store_true",
        help="print the open-source tools the ladder wraps, with licenses, and exit",
    )
    parser.add_argument("--strict-parse", action="store_true", help="unparseable workflow exits 2")
    parser.add_argument("--require-workflows", action="store_true")
    parser.add_argument("--self-check", action="store_true", help="validate SARIF against the schema")
    parser.add_argument("--explain", metavar="RULE_ID")
    parser.add_argument("--list-rules", action="store_true", help="print every rule id and exit")
    parser.add_argument(
        "--coverage", action="store_true",
        help="show coverage against Uber ADR's 17 agent threat techniques and exit",
    )
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"tridelphi {__version__}")
    return parser


def _explain(rule_id: str, out) -> int:
    candidates = [r for r in RULES if r.id == rule_id or r.id.split("/")[-1] == rule_id]
    if not candidates:
        print(f"unknown rule: {rule_id}", file=sys.stderr)
        print("known rules:", file=sys.stderr)
        for spec in RULES:
            print(f"  {spec.id}", file=sys.stderr)
        return 2
    spec = candidates[0]
    print(f"{spec.id}  ({spec.default_level})", file=out)
    print(f"\n{spec.short_description}\n", file=out)
    print(spec.full_description, file=out)
    if spec.adr_techniques:
        print("\nADR threat techniques: " + ", ".join(spec.adr_techniques), file=out)
    print(f"\n{spec.help_uri}", file=out)
    return 0


def _list_rules(out) -> int:
    for spec in RULES:
        print(f"{spec.default_level:8}  {spec.id}", file=out)
        print(f"          {spec.short_description}", file=out)
    return 0


def _default_format(stream) -> str:
    """What `--format` means when nobody said.

    A person at a terminal gets the checklist: the website promises plain
    English, and "0 critical · 0 warning" plus a rule id is not something a
    first-time reader can act on. Anything else — a pipe, a redirect, a CI log —
    keeps the `text` renderer, so every existing script and workflow that reads
    our stdout sees exactly what it saw before. `--format` always wins.
    """
    return "checklist" if hasattr(stream, "isatty") and stream.isatty() else "text"


def _cmd_init(args) -> int:
    from .init_cmd import run_init

    return run_init(
        args.command or ".",
        force=args.force,
        wizard=args.wizard,
        app=args.app,
        from_source=args.from_source,
        local=args.local,
    )


def _cmd_start(args) -> int:
    target = args.command or "."
    print(
        """TriDelPhi has three doors. Pick the sentence that sounds like your worry:

1. I am about to install code someone sent me.
   tridelphi scan ./download
   (Use npm:name or pypi:name only when you want TriDelPhi to download a package.)

2. I use GitHub Actions or an AI coding robot.
   tridelphi core TARGET
   (Reads TARGET/.github/workflows locally. Add --level 3 for downloaded scanners.)

3. I shipped a web app and worry I leaked a key, source map, or database.
   tridelphi expose TARGET
   (Reads committed/build files locally; it is not a live penetration test.)

Nothing is installed or changed by these checks. `tridelphi init TARGET` adds CI later.
""".replace("TARGET", target),
        end="",
    )
    return 0


def _cmd_scan(args) -> int:
    # The pre-install trust audit: read someone else's code — install hooks,
    # droppers, poisoned agent files, dishonest links — before the installer
    # ever runs. A sibling of the repo scan, not a ladder rung.
    from .scan_cmd import run_scan

    if not args.command:
        print(
            "tridelphi: scan needs a target: a directory, an archive "
            "(.tgz/.zip/.whl), npm:<package>, or pypi:<package>",
            file=sys.stderr,
        )
        return 2
    return run_scan(
        args.command,
        fmt="markdown" if args.markdown else args.format,
        sarif_file=args.sarif_file,
        checklist_md_file=args.checklist_md_file,
        fail_on=args.fail_on,
        tool_version=__version__,
    )


def _cmd_expose(args) -> int:
    # The exposure audit: shipped source maps + client secrets, DB config,
    # data hygiene. A sibling of the scan, not a ladder rung.
    from .expose_cmd import run_expose

    return run_expose(
        args.command or ".",
        fmt="markdown" if args.markdown else args.format,
        sarif_file=args.sarif_file,
        checklist_md_file=args.checklist_md_file,
        fail_on=args.fail_on,
        asset_roots=tuple(args.asset_root),
        tool_version=__version__,
    )


def _cmd_privatize(args) -> int:
    # The honest obfuscator: opt-in, consent-gated, verified-or-reverted,
    # and never reachable from --yes / fix --apply / guard -y.
    from .privatize import run_privatize

    return run_privatize(
        args.command or ".",
        build_cmd=args.build_cmd,
        smoke_cmd=args.smoke_cmd,
        privatize_out=args.privatize_out,
        assume_yes=args.yes,
    )


def _cmd_fix(args) -> int:
    if args.apply:
        # `fix --apply` is the batch spelling of guard: automatic fixers
        # only, every edit verified against a re-scan or rolled back.
        return _cmd_guard(args, yes=True)
    from .fix_cmd import run_fix

    return run_fix(
        args.command or ".",
        markdown=args.markdown,
        include_warnings=args.include_warnings,
    )


def _cmd_guard(args, *, yes: bool | None = None) -> int:
    from .guard_cmd import run_guard

    return run_guard(
        args.command or ".",
        yes=args.yes if yes is None else yes,
        include_warnings=args.include_warnings,
        level=args.level,
        offline=args.offline,
    )


def _cmd_gate(args) -> int:
    from .gate_cmd import run_gate

    if not args.command:
        print("tridelphi: gate needs a SARIF file: tridelphi gate out.sarif", file=sys.stderr)
        return 2
    return run_gate(args.command, fail_on=args.fail_on)


def _cmd_attest(args) -> int:
    from .gate_cmd import run_attest

    if not args.command:
        print(
            "tridelphi: attest needs a SARIF file: tridelphi attest out.sarif",
            file=sys.stderr,
        )
        return 2
    return run_attest(args.command, evidence_path=args.evidence_file)


def _cmd_verify(args) -> int:
    # L7: `tridelphi verify [repo]` checks the offline owner/SHA trust-lock.
    # Source action refs are not fabricated into artifact subjects for an
    # unrelated provenance protocol. It scans workflows, not a SARIF file.
    from .verify_cmd import run_verify

    want_sarif = args.format in ("sarif", "json")
    # Keep stdout clean for SARIF; the human summary goes to stderr then.
    code, document = run_verify(
        args.command or ".",
        trust_lock=args.trust_lock,
        write_lock=args.write_trust_lock,
        confirm_write=args.yes,
        relock=args.relock,
        offline=args.offline,
        fail_on=args.fail_on,
        tool_version=__version__,
        out=sys.stderr if want_sarif else sys.stdout,
    )
    if document is not None and want_sarif:
        sys.stdout.write(dumps(document))
    return code


# Subcommand registry: `tridelphi <name> …` dispatches here; anything else is
# a path to scan (`core` being the explicit spelling of the same). Each
# handler imports its implementation lazily so `tridelphi .` never pays for —
# or gains the capabilities of — the siblings it did not run.
_SUBCOMMANDS: dict[str, Callable[[argparse.Namespace], int]] = {
    "start": _cmd_start,
    "init": _cmd_init,
    "scan": _cmd_scan,
    "expose": _cmd_expose,
    "privatize": _cmd_privatize,
    "fix": _cmd_fix,
    "guard": _cmd_guard,
    "gate": _cmd_gate,
    "attest": _cmd_attest,
    "verify": _cmd_verify,
}


def _tolerate_undecodable_text() -> None:
    """Print a file name that is not valid UTF-8 as an escape, never a crash.

    Linux file names are bytes; Python hands an undecodable one over as lone
    surrogates, and a strict stdout then raised mid-report. A pull request can
    add such a file, so the report must survive it.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with contextlib.suppress(OSError, ValueError):
            reconfigure(errors="backslashreplace")


def main(argv: list[str] | None = None) -> int:
    _tolerate_undecodable_text()
    raw_args = sys.argv[1:] if argv is None else argv
    if raw_args and raw_args[0] == "audit":
        from .audit import main as audit_main

        return audit_main(raw_args[1:])
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.format is None:
        args.format = _default_format(sys.stdout)

    handler = _SUBCOMMANDS.get(args.path)
    if handler is not None:
        return handler(args)

    path = args.path
    if path == "core":
        path = args.command or "."
    elif args.command is not None:
        path = args.path

    if args.credits:
        print(credits_text(), file=sys.stdout)
        return 0
    if args.coverage:
        return render_coverage(sys.stdout)
    if args.list_rules:
        return _list_rules(sys.stdout)
    if args.explain:
        return _explain(args.explain, sys.stdout)

    started = time.monotonic()
    try:
        result = analyze(path, assume_default_permissions=args.assume_default_permissions)
    except AnalysisError as exc:
        print(f"tridelphi: {exc}", file=sys.stderr)
        return 2
    elapsed = time.monotonic() - started

    if result.files_scanned == 0:
        # "nothing to scan" and exit 0 is how someone ships a leaked key. This
        # scan reads `.github/workflows`; a repo with none is not a safe repo,
        # it is a repo we have said nothing about. Name the command that does
        # look at their app — for most people arriving here, that is the one
        # they actually wanted.
        print(
            f"tridelphi: no .github/workflows found under {path} — this scan checks "
            "GitHub Actions, so it has not looked at your app at all.",
            file=sys.stderr,
        )
        print(
            f"tridelphi: to check what your app itself ships (keys in browser "
            f"bundles, source maps, open database rules, committed credentials), "
            f"run:  tridelphi expose {path}",
            file=sys.stderr,
        )
        if args.require_workflows:
            return 2

    if args.strict_parse and result.diagnostics:
        for diagnostic in result.diagnostics:
            print(f"tridelphi: {diagnostic.path}: {diagnostic.message}", file=sys.stderr)
        return 2

    baseline: set[str] = set()
    baseline_path = Path(args.baseline) if args.baseline else Path(path) / DEFAULT_BASELINE
    if not args.no_baseline and baseline_path.is_file():
        baseline = load_baseline(baseline_path)
    new, _unchanged, stale = partition(list(result.findings), baseline)

    # Optional ladder orchestration. This is the only path that spawns
    # subprocesses, and only when explicitly requested — the default scan stays
    # offline and pure. `--level N` runs every rung up to N; `--with-zizmor`
    # remains as the single-tool spelling of rung 3's linter.
    external_runs = []
    if args.level is not None:
        external_runs = run_ladder(
            path, level=args.level, offline=args.offline, zizmor_online=args.zizmor_online
        )
    elif args.with_zizmor:
        external_runs = [run_tool(ZIZMOR, path, zizmor_online=args.zizmor_online)]

    external_summary: str | None = None
    external_sarifs = []
    # Per-tool status for the checklist renderer: did the rung run, and with
    # what result. A skipped (uninstalled) tool has ran=False.
    external_status: dict = {}
    for ext in external_runs:
        if ext.diagnostic is not None:
            print(f"tridelphi: {ext.diagnostic.message}", file=sys.stderr)
        items = items_from_sarif(ext.sarif) if ext.sarif is not None else None
        external_status[ext.spec.name] = ChecklistStatus(
            ran=ext.ok,
            counts=item_counts(items) if items is not None else dict(ext.severity_counts),
            items=items,
        )
        if ext.sarif is not None:
            external_sarifs.append(ext.sarif)
    trust_summary: str | None = None

    # L7 · trust runs after the content rungs: it consumes the same workflows
    # core parsed and folds its findings into the merged SARIF and the gate.
    if args.level is not None and args.level >= 7:
        from .verify_cmd import run_verify

        verify_code, verify_doc = run_verify(
            path,
            trust_lock=args.trust_lock,
            offline=args.offline,
            fail_on=args.fail_on,
            tool_version=__version__,
            out=sys.stderr,
        )
        if verify_code == 2 or (verify_code != 0 and verify_doc is None):
            print("tridelphi: L7 trust verification could not complete", file=sys.stderr)
            return 2
        if verify_doc is not None:
            external_sarifs.append(verify_doc)
            trust_counts = {s: 0 for s in _SEVERITIES}
            for result_obj in verify_doc["runs"][0]["results"]:
                sev = SARIF_LEVEL_TO_SEVERITY.get(result_obj.get("level"), "note")
                trust_counts[sev] += 1
            external_status["trust"] = ChecklistStatus(
                ran=True, counts=trust_counts, items=items_from_sarif(verify_doc)
            )
            n = len(verify_doc["runs"][0]["results"])
            trust_summary = f"trust: {n} finding{'s' if n != 1 else ''}"

    # Record after requested ladder tools run so their stable fingerprints are
    # part of the same ratchet. Missing/skipped tools contribute nothing and are
    # still named by their diagnostics. Gitleaks findings are never recordable.
    if args.write_baseline is not None:
        target = Path(args.write_baseline)
        try:
            count = write_baseline(target, result.findings, __version__, external_sarifs)
        except OSError as exc:
            print(f"tridelphi: could not write baseline: {exc}", file=sys.stderr)
            return 2
        print(f"wrote {count} fingerprints to {target}", file=sys.stderr)
        return 0

    external_gating, external_seen = annotate_external_baseline(
        external_sarifs, baseline if baseline else set()
    )
    # Baseline annotation happens after all rung documents exist. Rebuild each
    # beginner-facing status now so accepted external findings remain visible
    # in SARIF history without being presented as live problems.
    for ext in external_runs:
        if ext.sarif is None:
            continue
        live_items = items_from_sarif(ext.sarif)
        external_status[ext.spec.name] = ChecklistStatus(
            ran=ext.ok,
            counts=item_counts(live_items),
            items=live_items,
        )

    summary_parts: list[str] = []
    for ext in external_runs:
        if not ext.ok:
            summary_parts.append(summarize_run(ext))
            continue
        status = external_status[ext.spec.name]
        live_count = sum(status.counts.values())
        accepted_count = max(0, ext.finding_count - live_count)
        noun = "finding" if ext.finding_count == 1 else "findings"
        detail = f"{ext.finding_count} {noun} ({live_count} new"
        if accepted_count:
            detail += f", {accepted_count} accepted"
        detail += ")"
        summary_parts.append(f"{ext.spec.name}: {detail} (merged into SARIF output)")
    if trust_summary is not None:
        summary_parts.append(trust_summary)

    if summary_parts:
        external_summary = " · ".join(summary_parts)

    native_seen = {fingerprint(finding) for finding in result.findings}
    stale = len(baseline - native_seen - external_seen) if baseline else 0
    if stale:
        print(
            f"tridelphi: {stale} baseline entr{'y' if stale == 1 else 'ies'} no longer "
            "match any finding — run --write-baseline to prune",
            file=sys.stderr,
        )

    gating = new if baseline else list(result.findings)

    def build_sarif() -> dict:
        document = to_sarif(
            result.findings,
            tool_version=__version__,
            diagnostics=result.diagnostics,
            baseline=baseline if baseline else None,
            validate=args.self_check,
        )
        for external in external_sarifs:
            document = merge_runs(document, external)
        return document

    repo_label = str(Path(path).resolve().name) or path

    if args.format in ("sarif", "json"):
        sys.stdout.write(dumps(build_sarif()))
    elif args.format == "html":
        sys.stdout.write(
            render_html(
                result,
                repo_label=repo_label,
                external_summary=external_summary,
                baseline=baseline,
            )
        )
    elif args.format == "checklist":
        render_checklist(
            result,
            repo_label=repo_label,
            files_scanned=result.files_scanned,
            jobs_scanned=result.contexts_scanned,
            elapsed=elapsed,
            fail_on=args.fail_on,
            external=external_status,
            baseline=baseline,
            stream=sys.stdout,
        )
    elif not args.quiet:
        render_text(
            result,
            stream=sys.stdout,
            tool_version=__version__,
            min_severity=args.min_severity,
            elapsed=elapsed,
            no_color=args.no_color,
            new_count=len(new) if baseline else None,
            external_summary=external_summary,
            baseline=baseline,
        )
    else:
        counts = {s: sum(1 for f in gating if f.severity == s) for s in _SEVERITIES}
        print(
            f"tridelphi {__version__} · {result.files_scanned} workflows, "
            f"{result.contexts_scanned} jobs · {counts['critical']} critical, "
            f"{counts['warning']} warning",
        )

    try:
        if args.checklist_md_file:
            atomic_write_text(
                args.checklist_md_file,
                render_checklist_markdown(
                    result,
                    repo_label=repo_label,
                    files_scanned=result.files_scanned,
                    jobs_scanned=result.contexts_scanned,
                    fail_on=args.fail_on,
                    external=external_status,
                    baseline=baseline,
                ),
            )
        if args.sarif_file:
            atomic_write_text(args.sarif_file, dumps(build_sarif()))
        if args.html_file:
            atomic_write_text(
                args.html_file,
                render_html(
                    result,
                    repo_label=repo_label,
                    external_summary=external_summary,
                    baseline=baseline,
                ),
            )
    except OSError as exc:
        print(f"tridelphi: could not write report output: {exc}", file=sys.stderr)
        return 2
    # L6: the attest half runs inline when the scan reaches rung 6 and there is
    # a SARIF file on disk to attest over. The gate half is this process's own
    # exit code (and `tridelphi gate` re-checks it as a separate step).
    if args.level is not None and args.level >= 6:
        if args.sarif_file:
            from .gate_cmd import run_attest

            if run_attest(
                args.sarif_file, evidence_path=args.evidence_file, out=sys.stderr
            ) != 0:
                return 2
        else:
            print("tridelphi: --level 6 attestation needs --sarif-file; skipped", file=sys.stderr)
    if should_fail((f.severity for f in gating), args.fail_on):
        return 1
    # The gate covers the wrapped rungs too: a gitleaks secret or a zizmor error
    # fails the build under the same --fail-on threshold as a native finding.
    # Wrapped findings use stable line-insensitive fingerprints too. Gitleaks
    # credentials are the exception: they can never be waived into a baseline.
    if should_fail(external_gating, args.fail_on):
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
