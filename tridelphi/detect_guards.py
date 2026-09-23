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
from collections.abc import Iterable, Iterator

from .model import CapabilityHit, ExecutionContext
from .steps import iter_steps
from .tables import Tables

__all__ = [
    "association_gate",
    "detect",
    "has_strong_association_gate",
    "is_vetted",
    "trigger_association_field",
    "trigger_association_gate",
    "vetted_event_prefixes",
]

# An actor-identity reference used as a guard.
_ACTOR_REF = re.compile(r"github\.(?:triggering_actor|actor)\b")
_TRUSTED_ASSOCIATIONS = ("OWNER", "MEMBER", "COLLABORATOR")
_TRUSTED_NAME = re.compile(rf"\b(?:{'|'.join(_TRUSTED_ASSOCIATIONS)})\b")
# The event object whose author an association test names:
# `github.event.comment.author_association` vets the commenter, nobody else.
_ASSOCIATION_FIELD = re.compile(r"github\.event\.([A-Za-z_]+)\.author_association\b")


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


def _call_arguments(expr: str, name: str) -> Iterator[tuple[str, ...]]:
    """Yield balanced, quote-aware arguments for calls with the given name."""
    pattern = re.compile(rf"\b{re.escape(name)}\s*\(")
    for match in pattern.finditer(expr):
        args: list[str] = []
        depth = 0
        quote = ""
        start = match.end()
        i = start
        while i < len(expr):
            char = expr[i]
            if quote:
                if char == quote:
                    quote = ""
            elif char in "'\"":
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                if depth == 0:
                    args.append(expr[start:i].strip())
                    yield tuple(args)
                    break
                depth -= 1
            elif char == "," and depth == 0:
                args.append(expr[start:i].strip())
                start = i + 1
            i += 1


def _is_positive_association_term(term: str) -> bool:
    """Is this single (top-level) term a positive author_association membership
    test — ``contains(fromJSON('[…trusted…]'), …author_association)`` — with no
    inversion? Additional ``&&`` conditions only narrow it, so they are fine."""
    compact = term.replace(" ", "")
    if "author_association" not in compact:
        return False
    if any(bad in compact for bad in _INVERSIONS):
        return False
    if re.search(r"!\s*contains", term) is not None:
        return False
    return any(
        len(args) >= 2
        and _TRUSTED_NAME.search(args[0]) is not None
        and "author_association" in args[1]
        for args in _call_arguments(term, "contains")
    )


def _vetted_objects(term: str) -> set[str]:
    """Event objects whose author a positive membership test in ``term`` vets."""
    vetted: set[str] = set()
    for args in _call_arguments(term, "contains"):
        if len(args) >= 2 and _TRUSTED_NAME.search(args[0]) is not None:
            vetted.update(_ASSOCIATION_FIELD.findall(args[1]))
    return vetted


def vetted_event_prefixes(context: ExecutionContext) -> tuple[str, ...]:
    """Event-payload prefixes whose *author* the job-level gate vets.

    An ``author_association`` test vouches for one person: the author of the
    object it names. ``contains(…, github.event.comment.author_association)``
    admits a trusted commenter and says nothing about the stranger who wrote
    the issue or pull request that comment sits on. So that gate clears
    ``github.event.comment.*`` and nothing else — the issue title, the PR body
    and the PR's code stay untrusted.

    Trusting every ``github.event.*`` path behind any association test was a
    bypass two ways: a maintainer's ``/command`` on an attacker's issue ran the
    attacker's title through the shell with the gate reported as protection,
    and a gate on ``issue.author_association`` let any stranger's comment
    through on a maintainer's issue.

    Alternatives joined by a top-level ``||`` each admit the job on their own,
    so only an object every alternative vets is vetted; anything that is not a
    positive membership test vets nothing (fail closed).
    """
    expr = context.job_if or ""
    if "author_association" not in expr:
        return ()
    vetted: set[str] | None = None
    for term in _split_top_level_or(expr):
        if not _is_positive_association_term(term):
            return ()
        objects = _vetted_objects(term)
        vetted = objects if vetted is None else vetted & objects
    return tuple(sorted(f"github.event.{name}." for name in vetted or ()))


def _normalise(path: str) -> str:
    return path.replace("['", ".").replace("']", "").replace('["', ".").replace('"]', "")


def is_vetted(path: str, prefixes: tuple[str, ...]) -> bool:
    """Is this context path written by an author the gate vetted?"""
    if not prefixes:
        return False
    normalised = _normalise(path).rstrip(".")
    # The head branch name is chosen by the pull request's author.
    if normalised == "github.head_ref":
        normalised = "github.event.pull_request.head.ref"
    # A trailing dot lets `toJSON(github.event.comment)` — the vetted object
    # itself — match the prefix `github.event.comment.`.
    return (normalised + ".").startswith(prefixes)


# Payload objects whose author GitHub reports as `author_association`.
_GATEABLE_OBJECTS = ("comment", "issue", "pull_request", "review", "discussion")
_TRUSTED_LIST = "fromJSON('[\"OWNER\",\"MEMBER\",\"COLLABORATOR\"]')"


# Whose association the gate must test, by trigger: the author of the event's
# own object. On `pull_request_target` there is no comment, so a comment gate
# there is never true and silently switches the job off.
_TRIGGER_ASSOCIATION = (
    ("issue_comment", "github.event.comment.author_association"),
    ("pull_request_review_comment", "github.event.comment.author_association"),
    ("pull_request_review", "github.event.review.author_association"),
    ("discussion_comment", "github.event.comment.author_association"),
    ("discussion", "github.event.discussion.author_association"),
    ("issues", "github.event.issue.author_association"),
    ("pull_request_target", "github.event.pull_request.author_association"),
    ("pull_request", "github.event.pull_request.author_association"),
)


def trigger_association_field(triggers: Iterable[str]) -> str | None:
    """The association field that vets the author of this job's triggering event."""
    present = set(triggers)
    return next((field for trigger, field in _TRIGGER_ASSOCIATION if trigger in present), None)


def trigger_association_gate(triggers: Iterable[str]) -> str:
    """A job ``if:`` vetting the triggering author; the commenter when unknown."""
    field = trigger_association_field(triggers) or "github.event.comment.author_association"
    return f"contains({_TRUSTED_LIST}, {field})"


def association_gate(paths: Iterable[str]) -> str | None:
    """A job ``if:`` that vets the author of every one of ``paths``, or None.

    The advice and the auto-fix both build their gate here, from the text that
    was actually injected, so the gate they recommend is one the detectors
    accept: an issue body is vetted by the issue author's association, a
    comment by the commenter's. None means some path has no author GitHub can
    vouch for (a ``workflow_run`` field, a wildcard), and no gate will do.
    """
    fields: list[str] = []
    for path in paths:
        normalised = _normalise(path).rstrip(".")
        if normalised == "github.head_ref":
            normalised = "github.event.pull_request.head.ref"
        parts = normalised.split(".")
        if len(parts) < 3 or parts[:2] != ["github", "event"] or parts[2] not in _GATEABLE_OBJECTS:
            return None
        field = f"github.event.{parts[2]}.author_association"
        if field not in fields:
            fields.append(field)
    if not fields:
        return None
    return " && ".join(f"contains({_TRUSTED_LIST}, {field})" for field in fields)


def has_strong_association_gate(context: ExecutionContext) -> bool:
    """Does a job-level ``if:`` gate the event author on ``author_association``?

    True means *some* author is vetted; which payload that makes trustworthy is
    :func:`vetted_event_prefixes`' question, and the detectors ask that one.

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
    return bool(vetted_event_prefixes(context))


def _is_strong_association_expression(expr: str) -> bool:
    if "author_association" not in expr:
        return False
    return all(_is_positive_association_term(d) for d in _split_top_level_or(expr))


def _guard_expressions(context: ExecutionContext) -> Iterator[tuple[str, object]]:
    """Every `if:` expression in the job — job-level and step-level — with a
    node to anchor a position on."""
    if context.job_if:
        yield context.job_if, None
    for step in iter_steps(context.body):
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
        if _is_strong_association_expression(expr):
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
