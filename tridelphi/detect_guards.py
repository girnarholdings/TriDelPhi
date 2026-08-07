"""Weak authorization guards on untrusted-triggered jobs.

`github.actor` and `github.triggering_actor` are *identity*, not *authorization*,
and both are spoofable. The Dependabot confused-deputy trick makes `github.actor`
read as `dependabot[bot]` on an attacker's PR; git authorship is trivially
forged (Manifold Security showed two git commands fooling an AI reviewer into
merging malicious code). A job on an attacker-reachable trigger whose only gate
is an actor-name comparison believes it is protected and is not.

The correct gate is the commenter's `author_association` (OWNER / MEMBER /
COLLABORATOR) or a real permission lookup. This maps to ADR's *Agent Identity
Spoofing* — a technique our own --coverage previously listed as a gap.

Reported as its own warning, not through the U/P/E join: a false sense of
authorization is a distinct problem from holding the three capabilities.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from .model import CapabilityHit, ExecutionContext
from .tables import Tables

__all__ = ["detect"]

# An actor-identity reference used as a guard.
_ACTOR_REF = re.compile(r"github\.(?:triggering_actor|actor)\b")
# Signals that a real authorization check is present, which makes the guard OK.
_STRONG = (
    "author_association",
    "permission",  # e.g. a check-permissions action output
    "OWNER",
    "MEMBER",
    "COLLABORATOR",
)


def _guard_expressions(context: ExecutionContext) -> Iterator[tuple[str, object]]:
    """Every `if:` expression in the job — job-level and step-level — with a
    node to anchor a position on."""
    if context.job_if:
        yield context.job_if, None
    steps = context.body.get("steps")
    if steps is not None:
        for step in steps.seq():
            if not step.is_mapping():
                continue
            node = step.get("if")
            if node is not None and node.text:
                yield node.text, node


def detect(context: ExecutionContext, tables: Tables) -> list[CapabilityHit]:
    # Only meaningful where an attacker can actually reach the job.
    privileged = set(tables.tuple_of("triggers", "privileged_untrusted"))
    if not (set(context.triggers) & privileged):
        return []

    hits: list[CapabilityHit] = []
    for expr, node in _guard_expressions(context):
        if not _ACTOR_REF.search(expr):
            continue
        if any(strong in expr for strong in _STRONG):
            continue
        position = node.value_position() if node is not None else context.position
        hits.append(
            CapabilityHit(
                capability="P",
                kind="weak-actor-guard",
                reason=(
                    "the only authorization gate is a `github.actor` comparison, which "
                    "is spoofable (Dependabot confused-deputy, forged git identity) and "
                    "is not an authorization check — gate on `author_association` or a "
                    "real permission lookup instead"
                ),
                position=position,
            )
        )
    return sorted(hits, key=lambda h: h.sort_key)
