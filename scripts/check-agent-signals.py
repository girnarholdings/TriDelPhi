#!/usr/bin/env python3
"""Fail when the reviewed AI-agent behavior table is incomplete or stale."""

from __future__ import annotations

import argparse
from datetime import date

from tridelphi.tables import load_tables


def review_errors(*, today: date | None = None, max_age_days: int = 120) -> list[str]:
    today = today or date.today()
    agents = load_tables().section("agent_signals", "agents", []) or []
    errors: list[str] = []
    seen: set[str] = set()
    for index, agent in enumerate(agents):
        if not isinstance(agent, dict):
            errors.append(f"entry {index + 1} is not a mapping")
            continue
        agent_id = str(agent.get("id") or f"entry-{index + 1}")
        if agent_id in seen:
            errors.append(f"{agent_id}: duplicate id")
        seen.add(agent_id)
        if agent.get("restore_state") not in {"known", "none", "unknown"}:
            errors.append(f"{agent_id}: restore_state must be known, none, or unknown")
        for field in ("display", "evidence", "reviewed_at", "reviewed_versions"):
            if not agent.get(field):
                errors.append(f"{agent_id}: missing {field}")
        try:
            reviewed = date.fromisoformat(str(agent.get("reviewed_at")))
        except ValueError:
            errors.append(f"{agent_id}: reviewed_at is not YYYY-MM-DD")
            continue
        age = (today - reviewed).days
        if age < 0:
            errors.append(f"{agent_id}: reviewed_at is in the future")
        elif age > max_age_days:
            errors.append(
                f"{agent_id}: restore behavior review is {age} days old "
                f"(limit {max_age_days})"
            )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-age-days", type=int, default=120)
    args = parser.parse_args()
    if args.max_age_days <= 0:
        parser.error("--max-age-days must be positive")
    errors = review_errors(max_age_days=args.max_age_days)
    if errors:
        print("Agent restore-semantics review is required:")
        for error in errors:
            print(f"  - {error}")
        return 1
    print("Agent restore-semantics evidence is complete and within review age.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
