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
import sys
import time
from pathlib import Path

from . import __version__
from .api import AnalysisError, analyze
from .baseline import DEFAULT_BASELINE, load_baseline, partition, write_baseline
from .checklist import ExternalStatus as ChecklistStatus
from .checklist import items_from_sarif, render_checklist, render_checklist_markdown
from .coverage import render_coverage
from .html_report import render_html
from .ladder import ZIZMOR, credits_text, run_ladder, run_tool, summarize_run
from .model import RULES
from .orchestrate import merge_runs
from .render import SEVERITY_ORDER, render_text
from .sarif import dumps, to_sarif

__all__ = ["build_parser", "main"]

_SEVERITIES = ("critical", "warning", "note")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tridelphi",
        description=(
            "Static Agents Rule of Two checker for GitHub Actions. Flags jobs that "
            "hold untrusted input, privilege and egress at once."
        ),
        epilog="Offline by design: no network calls, no account, no API token.",
    )
    parser.add_argument(
        "path", nargs="?", default=".",
        help=(
            "repository root, or a command: `init` adds the scan workflow, `fix` "
            "prints a remediation plan, `guard` fixes interactively (default: .)"
        ),
    )
    parser.add_argument("command", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--force", action="store_true", help="with init: overwrite an existing workflow")
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
        help="with `guard`: apply automatic fixes without prompting (never disables workflows)",
    )
    parser.add_argument(
        "-f", "--format", choices=("text", "checklist", "sarif", "json", "html"), default="text",
        help=(
            "output format (default: text; 'checklist' is the plain-language, "
            "no-jargon report a first-time user can act on; html is browsable)"
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
            "See --credits."
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
        help="with `verify`: record today's action identities and exit",
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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # `tridelphi init` sets up the scan workflow; `tridelphi core .` and
    # `tridelphi .` both scan; `gate` and `attest` are L6's two processes.
    if args.path == "init":
        from .init_cmd import run_init

        return run_init(args.command or ".", force=args.force)
    if args.path == "fix":
        if args.apply:
            # `fix --apply` is the batch spelling of guard: automatic fixers
            # only, every edit verified against a re-scan or rolled back.
            from .guard_cmd import run_guard

            return run_guard(
                args.command or ".",
                yes=True,
                include_warnings=args.include_warnings,
                level=args.level,
                offline=args.offline,
            )
        from .fix_cmd import run_fix

        return run_fix(
            args.command or ".",
            markdown=args.markdown,
            include_warnings=args.include_warnings,
        )
    if args.path == "guard":
        from .guard_cmd import run_guard

        return run_guard(
            args.command or ".",
            yes=args.yes,
            include_warnings=args.include_warnings,
            level=args.level,
            offline=args.offline,
        )
    if args.path == "gate":
        from .gate_cmd import run_gate

        if not args.command:
            print("tridelphi: gate needs a SARIF file: tridelphi gate out.sarif", file=sys.stderr)
            return 2
        return run_gate(args.command, fail_on=args.fail_on)
    if args.path == "attest":
        from .gate_cmd import run_attest

        if not args.command:
            print(
                "tridelphi: attest needs a SARIF file: tridelphi attest out.sarif",
                file=sys.stderr,
            )
            return 2
        return run_attest(args.command, evidence_path=args.evidence_file)
    if args.path == "verify":
        # L7: `tridelphi verify [repo]` checks the trust-lock (and, when gh is
        # present and online, upstream provenance). It scans the workflows, not
        # a SARIF file, so its argument is a repo root like a normal scan.
        from .verify_cmd import run_verify

        want_sarif = args.format in ("sarif", "json")
        # Keep stdout clean for SARIF; the human summary goes to stderr then.
        code, document = run_verify(
            args.command or ".",
            trust_lock=args.trust_lock,
            write_lock=args.write_trust_lock,
            offline=args.offline,
            fail_on=args.fail_on,
            tool_version=__version__,
            out=sys.stderr if want_sarif else sys.stdout,
        )
        if document is not None and want_sarif:
            sys.stdout.write(dumps(document))
        return code

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
        print(
            f"tridelphi: no .github/workflows found under {path} — nothing to scan",
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

    # --write-baseline records fingerprints and exits before the ladder: no
    # subprocess (or osv.dev query) should be spent on output that a recording
    # run immediately discards.
    if args.write_baseline is not None:
        target = Path(args.write_baseline)
        count = write_baseline(target, result.findings, __version__)
        print(f"wrote {count} fingerprints to {target}", file=sys.stderr)
        return 0

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
    external_counts = {s: 0 for s in _SEVERITIES}
    # Per-tool status for the checklist renderer: did the rung run, and with
    # what result. A skipped (uninstalled) tool has ran=False.
    external_status: dict = {}
    for ext in external_runs:
        if ext.diagnostic is not None:
            print(f"tridelphi: {ext.diagnostic.message}", file=sys.stderr)
        external_status[ext.spec.name] = ChecklistStatus(
            ran=ext.ok,
            counts=dict(ext.severity_counts),
            items=items_from_sarif(ext.sarif) if ext.sarif is not None else None,
        )
        if ext.sarif is not None:
            external_sarifs.append(ext.sarif)
            for severity, count in ext.severity_counts.items():
                external_counts[severity] += count
    summary_parts = [summarize_run(ext) for ext in external_runs]

    # L7 · trust runs after the content rungs: it consumes the same workflows
    # core parsed and folds its findings into the merged SARIF and the gate.
    if args.level is not None and args.level >= 7:
        from .verify_cmd import run_verify

        _code, verify_doc = run_verify(
            path,
            trust_lock=args.trust_lock,
            offline=args.offline,
            fail_on=args.fail_on,
            tool_version=__version__,
            out=sys.stderr,
        )
        if verify_doc is not None:
            external_sarifs.append(verify_doc)
            trust_counts = {s: 0 for s in _SEVERITIES}
            for result_obj in verify_doc["runs"][0]["results"]:
                sev = "critical" if result_obj.get("level") == "error" else "note"
                external_counts[sev] += 1
                trust_counts[sev] += 1
            external_status["trust"] = ChecklistStatus(
                ran=True, counts=trust_counts, items=items_from_sarif(verify_doc)
            )
            n = len(verify_doc["runs"][0]["results"])
            summary_parts.append(f"trust: {n} finding{'s' if n != 1 else ''}")

    if summary_parts:
        external_summary = " · ".join(summary_parts)

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
            render_html(result, repo_label=repo_label, external_summary=external_summary)
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
        )
    else:
        counts = {s: sum(1 for f in result.findings if f.severity == s) for s in _SEVERITIES}
        print(
            f"tridelphi {__version__} · {result.files_scanned} workflows, "
            f"{result.contexts_scanned} jobs · {counts['critical']} critical, "
            f"{counts['warning']} warning",
        )

    if args.checklist_md_file:
        Path(args.checklist_md_file).write_text(
            render_checklist_markdown(
                result,
                repo_label=repo_label,
                files_scanned=result.files_scanned,
                jobs_scanned=result.contexts_scanned,
                fail_on=args.fail_on,
                external=external_status,
            ),
            encoding="utf-8",
            newline="\n",
        )
    if args.sarif_file:
        Path(args.sarif_file).write_text(dumps(build_sarif()), encoding="utf-8", newline="\n")
    # L6: the attest half runs inline when the scan reaches rung 6 and there is
    # a SARIF file on disk to attest over. The gate half is this process's own
    # exit code (and `tridelphi gate` re-checks it as a separate step).
    if args.level is not None and args.level >= 6:
        if args.sarif_file:
            from .gate_cmd import run_attest

            run_attest(args.sarif_file, evidence_path=args.evidence_file, out=sys.stderr)
        else:
            print("tridelphi: --level 6 attestation needs --sarif-file; skipped", file=sys.stderr)
    if args.html_file:
        Path(args.html_file).write_text(
            render_html(result, repo_label=repo_label, external_summary=external_summary),
            encoding="utf-8",
            newline="\n",
        )

    if args.fail_on == "none":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    if any(SEVERITY_ORDER[f.severity] <= threshold for f in gating):
        return 1
    # The gate covers the wrapped rungs too: a gitleaks secret or a zizmor error
    # fails the build under the same --fail-on threshold as a native finding.
    # External findings are not baselined — they come from tools whose output
    # has no stable fingerprint, and a committed secret should never be waived.
    if any(
        count and SEVERITY_ORDER[severity] <= threshold
        for severity, count in external_counts.items()
    ):
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
