#!/usr/bin/env python3
"""Brute-force TriDelPhi's detection against every attack variant we can spell.

White-hat robustness testing. For each synthetic attack shape (see
tests/redteam_corpus.py) this expands the payload space, runs the scanner
offline in a temp directory, and reports which variants are CAUGHT and which
would SLIP PAST. A slip is a real detection gap — the encoding an attacker would
reach for to evade us — and it should be fixed before it is found in the wild.

    python scripts/redteam.py                # human summary
    python scripts/redteam.py --json out.json
    python scripts/redteam.py --show-missed  # print every gap in full

Nothing here touches a live system: payloads are inert placeholders, there is no
network, and every case is torn down after it is scanned.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from redteam_corpus import Case, attack_cases, control_cases

from tridelphi.api import analyze


def _gating(findings) -> list:
    return [f for f in findings if f.severity in ("critical", "warning")]


def evaluate(case: Case) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        root = case.materialize(Path(tmp))
        result = analyze(root)
    gating = _gating(result.findings)
    rules = sorted({f.rule_id for f in gating})

    if case.kind == "control":
        ok = not gating
        return {
            "name": case.name,
            "kind": "control",
            "ok": ok,
            "detail": "clean" if ok else f"false positive: {rules}",
            "rules": rules,
        }

    hit = any((case.expect_rule or "") in r for r in rules)
    return {
        "name": case.name,
        "kind": "attack",
        "ok": hit,
        "detail": "caught" if hit else f"MISSED — expected ~{case.expect_rule}, got {rules or 'nothing'}",
        "rules": rules,
    }


def run() -> dict:
    rows = [evaluate(c) for c in attack_cases()] + [evaluate(c) for c in control_cases()]
    attacks = [r for r in rows if r["kind"] == "attack"]
    controls = [r for r in rows if r["kind"] == "control"]
    return {
        "rows": rows,
        "attacks_total": len(attacks),
        "attacks_caught": sum(r["ok"] for r in attacks),
        "controls_total": len(controls),
        "controls_clean": sum(r["ok"] for r in controls),
        "by_rule": dict(Counter(rule for r in rows for rule in r["rules"])),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, help="write the full matrix here")
    parser.add_argument("--show-missed", action="store_true", help="print every gap in full")
    args = parser.parse_args()

    report = run()
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    missed = [r for r in report["rows"] if not r["ok"]]

    ac, at = report["attacks_caught"], report["attacks_total"]
    cc, ct = report["controls_clean"], report["controls_total"]
    print("TriDelPhi red-team sweep — synthetic attack shapes, offline\n")
    print(f"  attacks caught   {ac}/{at}   ({100 * ac / max(at, 1):.0f}%)")
    print(f"  controls clean   {cc}/{ct}   ({100 * cc / max(ct, 1):.0f}%)")
    print()
    print("  findings by rule:")
    for rule, n in sorted(report["by_rule"].items(), key=lambda kv: -kv[1]):
        print(f"    {n:4}  {rule}")

    if missed:
        print(f"\n  {len(missed)} GAP(S):")
        for r in missed:
            print(f"    [{r['kind']}] {r['name']}")
            if args.show_missed:
                print(f"           {r['detail']}")
        return 1

    print("\n  no gaps — every attack shape caught, every control clean.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
