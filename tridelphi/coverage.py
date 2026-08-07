"""Coverage against Uber's ADR agent threat-technique taxonomy.

A security tool that only advertises what it catches is not much use for
planning. This renders the whole 17-technique taxonomy and states, per
technique, whether TriDelPhi reaches it — and where it cannot, why, and what
kind of tool can.

The honesty is the point. Roughly half the taxonomy is runtime-only: nothing in
a repository distinguishes a benign agent session from a hijacked one. Claiming
static coverage of those would be the same failure as flagging a compliant job
critical, and it would send a team away believing they were covered.
"""

from __future__ import annotations

from typing import TextIO

from .model import RULES
from .tables import Tables, load_tables

__all__ = ["coverage_rows", "render_coverage"]

def _status(row: dict) -> tuple[str, str]:
    """(marker, label) for a technique.

    Three honest states, and the third one matters: a technique that is
    statically reachable but has no rule yet is a *gap in this tool*, not a
    limit of static analysis. Collapsing it into "runtime-only" would hide our
    own backlog behind a claim about the problem domain.
    """
    if row["rules"]:
        return ("[x]", "detected" if row["reach"] == "static" else "partial")
    if row["reach"] == "runtime":
        return ("[-]", "runtime-only")
    return ("[ ]", "gap — statically reachable, no rule yet")


def coverage_rows(tables: Tables | None = None) -> list[dict]:
    """One row per ADR technique, with the rules that detect it."""
    tables = tables or load_tables()
    techniques = tables.section("adr_techniques", "techniques", []) or []

    by_technique: dict[str, list[str]] = {}
    for spec in RULES:
        for technique in spec.adr_techniques:
            by_technique.setdefault(technique, []).append(spec.id)

    rows = []
    for entry in techniques:
        tid = str(entry.get("id"))
        rows.append(
            {
                "id": tid,
                "name": str(entry.get("name")),
                "reach": str(entry.get("reach")),
                "note": " ".join(str(entry.get("note", "")).split()),
                "rules": sorted(by_technique.get(tid, [])),
            }
        )
    return rows


def render_coverage(out: TextIO, *, tables: Tables | None = None) -> int:
    rows = coverage_rows(tables)
    detected = [r for r in rows if r["rules"]]
    runtime_only = [r for r in rows if r["reach"] == "runtime"]

    print("ADR agent threat techniques — what a static scan reaches\n", file=out)
    print(
        "Taxonomy: Uber ADR (MLSys 2026, arXiv:2605.17380), 17 techniques.\n"
        "ADR detects these at runtime by observing agent sessions. TriDelPhi\n"
        "finds the configurations where they would land, before anything runs.\n",
        file=out,
    )

    width = max(len(r["name"]) for r in rows)
    gaps = []
    for row in rows:
        mark, label = _status(row)
        if label.startswith("gap"):
            gaps.append(row)
        print(f"{mark} {row['name']:<{width}}   {label}", file=out)
        for rule in row["rules"]:
            print(f"      {'':<{width}}   {rule}", file=out)
        if not row["rules"]:
            print(f"      {'':<{width}}   {row['note']}", file=out)

    reachable = len(rows) - len(runtime_only)
    print(
        f"\n{len(detected)} of {reachable} statically reachable techniques have a rule; "
        f"{len(runtime_only)} of {len(rows)} are runtime-only.",
        file=out,
    )
    if gaps:
        print(
            f"{len(gaps)} reachable technique(s) have no rule yet: "
            + ", ".join(g["name"] for g in gaps),
            file=out,
        )
    print(
        "\nRuntime-only means no repository content distinguishes a benign agent\n"
        "session from a hijacked one — those need session telemetry, which is what\n"
        "Uber's ADR does. Static analysis and runtime detection are complementary\n"
        "halves of agent security, not competitors.",
        file=out,
    )
    return 0
