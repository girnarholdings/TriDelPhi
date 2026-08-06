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
from .html_report import render_html
from .model import RULES
from .orchestrate import merge_runs, run_zizmor, summarize_external_run
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
    parser.add_argument("path", nargs="?", default=".", help="repository root (default: .)")
    parser.add_argument("command", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument(
        "-f", "--format", choices=("text", "sarif", "json", "html"), default="text",
        help="output format (default: text; html is a browsable report)",
    )
    parser.add_argument("--sarif-file", metavar="PATH", help="also write SARIF here")
    parser.add_argument("--html-file", metavar="PATH", help="also write an HTML report here")
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
        "--with-zizmor", action="store_true",
        help="also run zizmor (if installed) and merge its findings into the SARIF output",
    )
    parser.add_argument(
        "--zizmor-online", action="store_true",
        help="allow zizmor's online audits (requires GH_TOKEN; not air-gap safe)",
    )
    parser.add_argument("--strict-parse", action="store_true", help="unparseable workflow exits 2")
    parser.add_argument("--require-workflows", action="store_true")
    parser.add_argument("--self-check", action="store_true", help="validate SARIF against the schema")
    parser.add_argument("--explain", metavar="RULE_ID")
    parser.add_argument("--list-rules", action="store_true", help="print every rule id and exit")
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

    # `tridelphi core .` and `tridelphi .` both work; `core` is canonical for
    # forward compatibility with later subcommands.
    path = args.path
    if path == "core":
        path = args.command or "."
    elif args.command is not None:
        path = args.path

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

    # Optional zizmor orchestration. This is the only place a subprocess runs,
    # and only when explicitly requested — the default scan stays offline.
    external_summary: str | None = None
    external_sarif = None
    if args.with_zizmor:
        zres = run_zizmor(path, offline=not args.zizmor_online)
        external_summary = summarize_external_run(zres)
        if zres.diagnostic is not None:
            print(f"tridelphi: {zres.diagnostic.message}", file=sys.stderr)
        external_sarif = zres.sarif

    baseline: set[str] = set()
    baseline_path = Path(args.baseline) if args.baseline else Path(path) / DEFAULT_BASELINE
    if not args.no_baseline and baseline_path.is_file():
        baseline = load_baseline(baseline_path)
    new, _unchanged, stale = partition(list(result.findings), baseline)

    if args.write_baseline is not None:
        target = Path(args.write_baseline)
        count = write_baseline(target, result.findings, __version__)
        print(f"wrote {count} fingerprints to {target}", file=sys.stderr)
        return 0

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
        if external_sarif is not None:
            document = merge_runs(document, external_sarif)
        return document

    repo_label = str(Path(path).resolve().name) or path

    if args.format in ("sarif", "json"):
        sys.stdout.write(dumps(build_sarif()))
    elif args.format == "html":
        sys.stdout.write(
            render_html(result, repo_label=repo_label, external_summary=external_summary)
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

    if args.sarif_file:
        Path(args.sarif_file).write_text(dumps(build_sarif()), encoding="utf-8", newline="\n")
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
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
