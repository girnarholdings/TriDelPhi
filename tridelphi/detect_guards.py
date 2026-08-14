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

__all__ = ["detect", "has_strong_association_gate"]

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

_TRUSTED_ASSOCIATIONS = ("OWNER", "MEMBER", "COLLABORATOR")


def _split_top_level_or(expr: str) -> list[str]:
    """Split ``expr`` on ``||`` at parenthesis depth 0, respecting quotes.

    A GitHub Actions ``if:`` is a boolean expression; an ``||`` at the top level
    is a genuine alternative — the whole gate is only as strong as its *weakest*
    alternative. An ``||`` nested inside parentheses (or inside a quoted string)
    is not a top-level alternative and must not split.
    """
    parts: list[str] = []
    depth = 0
    quote = ""
    start = 0
    i = 0
    while i < len(expr):
        c = expr[i]
        if quote:
            if c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        elif c == "|" and depth == 0 and i + 1 < len(expr) and expr[i + 1] == "|":
            parts.append(expr[start:i])
            i += 2
            start = i
            continue
        i += 1
    parts.append(expr[start:])
    return parts


# Substrings that mean the association test is INVERTED — it admits exactly the
# strangers it appears to exclude. Compared against a whitespace-stripped copy.
_INVERSIONS = ("!contains", "!=", "==false", "=='false'", '=="false"')


def _is_positive_association_term(term: str) -> bool:
    """Is this single (top-level) term a positive author_association membership
    test — ``contains(fromJSON('[…trusted…]'), …author_association)`` — with no
    inversion? Additional ``&&`` conditions only narrow it, so they are fine."""
    compact = term.replace(" ", "")
    if "author_association" not in compact:
        return False
    if not any(assoc in term for assoc in _TRUSTED_ASSOCIATIONS):
        return False
    if "contains(" not in compact:
        return False
    if any(bad in compact for bad in _INVERSIONS):
        return False
    return re.search(r"!\s*contains", term) is None


def has_strong_association_gate(context: ExecutionContext) -> bool:
    """Does a job-level ``if:`` gate the event author on ``author_association``?

    This is the gate our own remediation recommends (see ``rule.py``): only
    OWNER / MEMBER / COLLABORATOR authors can make the job run, so a drive-by
    stranger's text never reaches it. If the detectors did not honour it, a user
    who applies our exact advice would still be red — advice the tool gives must
    be advice the tool accepts.

    Evaluated structurally, and **failing closed**, because a lexical
    substring check was bypassable two ways (both were real):

      * ``contains(…author_association) || github.event.action == 'created'`` —
        an ``||`` alternative that is true for everyone opens the gate, yet the
        text still contains ``author_association`` + a trusted name and no
        ``!=``/``!contains``.
      * ``contains(…author_association) == false`` — the literal *inverse* of a
        gate (it fires only for non-trusted authors), which no ``!=``/
        ``!contains`` substring catches.

    So: split on top-level ``||`` and require **every** alternative to be a
    positive association membership test with no inversion. Anything that does
    not match that shape is treated as *not* a strong gate — over-reporting a
    critical is the safe direction; silently accepting a defeated gate is not.
    Step-level gates do not count — they protect one step, not the job the
    finding is about.
    """
    expr = context.job_if or ""
    if "author_association" not in expr:
        return False
    return all(_is_positive_association_term(d) for d in _split_top_level_or(expr))


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
