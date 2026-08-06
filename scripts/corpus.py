#!/usr/bin/env python3
"""Measure precision and noise on a corpus of real repositories.

The acceptance test in ``tests/test_thesis.py`` uses fixtures we authored, which
can only prove that our matcher matches our fixture. This script is the
falsifiable version: point it at real repositories and get a number.

It is deliberately separate from the package. `tridelphi core` itself makes no
network calls; cloning is an explicit, operator-initiated step, and analysis of
the clones is fully offline afterwards.

    # one repo per line: owner/name
    python scripts/corpus.py --repos corpus.txt --clone-dir /tmp/corpus
    python scripts/corpus.py --clone-dir /tmp/corpus --report corpus-report.json

The number worth publishing is the last one printed: how many repositories have
a finding that only the composition analysis reaches.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tridelphi.api import analyze  # noqa: E402

COMPOSITION_RULES = {
    "tridelphi/agent-config-ingress",
    "tridelphi/agent-prompt-injection",
    "tridelphi/agent-hook-execution",
    "tridelphi/cross-job-untrusted-flow",
    "tridelphi/workflow-run-upstream-execution",
}


def clone(repos: list[str], clone_dir: Path, depth: int = 1) -> None:
    clone_dir.mkdir(parents=True, exist_ok=True)
    for index, name in enumerate(repos, start=1):
        target = clone_dir / name.replace("/", "__")
        if target.exists():
            continue
        print(f"[{index}/{len(repos)}] cloning {name}", file=sys.stderr)
        subprocess.run(
            [
                "git", "clone", "--quiet", "--depth", str(depth),
                "--filter=blob:none", f"https://github.com/{name}.git", str(target),
            ],
            check=False,
        )


def scan(clone_dir: Path) -> dict:
    repos = sorted(p for p in clone_dir.iterdir() if p.is_dir())
    rows = []
    rule_counts: Counter[str] = Counter()
    totals = Counter()

    for repo in repos:
        try:
            result = analyze(repo)
        except Exception as exc:  # a corpus run must never die on one repo
            rows.append({"repo": repo.name, "error": repr(exc)})
            continue

        gating = [f for f in result.findings if f.severity in ("critical", "warning")]
        criticals = [f for f in result.findings if f.severity == "critical"]
        composition = [f for f in criticals if f.rule_id in COMPOSITION_RULES]
        for finding in result.findings:
            rule_counts[finding.rule_id] += 1

        totals["repos"] += 1
        totals["jobs"] += result.contexts_scanned
        totals["critical"] += len(criticals)
        totals["gating"] += len(gating)
        totals["repos_with_critical"] += bool(criticals)
        totals["repos_with_composition"] += bool(composition)

        rows.append(
            {
                "repo": repo.name,
                "jobs": result.contexts_scanned,
                "workflows": result.files_scanned,
                "critical": len(criticals),
                "gating": len(gating),
                "composition_only": sorted({f.rule_id for f in composition}),
                "findings": [
                    {
                        "rule": f.rule_id,
                        "severity": f.severity,
                        "job": f.context.job_id,
                        "file": f.context.workflow_file,
                        "line": f.primary_position.line,
                        "message": f.message,
                    }
                    for f in gating
                ],
            }
        )

    return {"totals": dict(totals), "by_rule": dict(rule_counts), "repos": rows}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repos", type=Path, help="file with one owner/name per line")
    parser.add_argument("--clone-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    if args.repos:
        names = [
            line.strip()
            for line in args.repos.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        clone(names, args.clone_dir)

    if not args.clone_dir.is_dir():
        print(f"no such directory: {args.clone_dir}", file=sys.stderr)
        return 2

    report = scan(args.clone_dir)
    if args.report:
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    totals = report["totals"]
    repos = max(totals.get("repos", 0), 1)
    jobs = max(totals.get("jobs", 0), 1)

    print(f"repositories scanned      {totals.get('repos', 0)}")
    print(f"jobs scanned              {totals.get('jobs', 0)}")
    print(f"criticals                 {totals.get('critical', 0)}")
    print(f"criticals per 100 jobs    {100 * totals.get('critical', 0) / jobs:.1f}")
    print(f"repos with any critical   {totals.get('repos_with_critical', 0)} "
          f"({100 * totals.get('repos_with_critical', 0) / repos:.0f}%)")
    print()
    print("findings by rule:")
    for rule, count in sorted(report["by_rule"].items(), key=lambda kv: -kv[1]):
        print(f"  {count:5}  {rule}")
    print()
    print(
        "repos where only the composition analysis fires: "
        f"{totals.get('repos_with_composition', 0)}"
    )
    print(
        "  ^ this is the number that decides whether the product is a tool or a "
        "blog post. Triage a random 50 by hand before quoting it."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
