"""The one severity vocabulary, defined once.

Every part of the tool — the core scan, the wrapped ladder tools, the gate,
the exposure audit, the pre-install scan — speaks in three words: ``critical``,
``warning``, ``note``. SARIF speaks in four: ``error``, ``warning``, ``note``,
``none``. The maps between the two, and the ordering that decides what breaks
a build, used to be re-typed in eight modules; each copy was one bumped
severity away from disagreeing with the gate. Now they live here, and a module
that ranks or translates a severity imports the table instead of restating it.
"""

from __future__ import annotations

from collections.abc import Iterable

__all__ = [
    "SARIF_LEVEL_TO_SEVERITY",
    "SEVERITIES",
    "SEVERITY_ORDER",
    "SEVERITY_TO_SARIF_LEVEL",
    "at_or_above",
    "should_fail",
]

SEVERITIES: tuple[str, ...] = ("critical", "warning", "note")

# Lower rank = more severe. `min()` over ranks finds the worst finding.
SEVERITY_ORDER: dict[str, int] = {"critical": 0, "warning": 1, "note": 2}

# SARIF's `level` vocabulary, both directions. `none` folds into `note`: a
# tool that says "informational" gets read, not gated.
SARIF_LEVEL_TO_SEVERITY: dict[str, str] = {
    "error": "critical",
    "warning": "warning",
    "note": "note",
    "none": "note",
}
SEVERITY_TO_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "warning": "warning",
    "note": "note",
}


def at_or_above(severity: str, threshold: str) -> bool:
    """True when ``severity`` is at least as severe as ``threshold``.

    An unknown severity ranks below everything (never gates); an unknown
    threshold ranks as most-severe, so only criticals would trip it.
    """
    return SEVERITY_ORDER.get(severity, len(SEVERITIES)) <= SEVERITY_ORDER.get(threshold, 0)


def should_fail(severities: Iterable[str], fail_on: str) -> bool:
    """The ``--fail-on`` gate, in one place: does any severity trip it?

    ``fail_on == "none"`` never fails — the caller asked to look, not to
    block. Every command that turns findings into an exit code routes
    through this so the CLI, the gate, and the sibling scans cannot drift.
    """
    if fail_on == "none":
        return False
    return any(at_or_above(severity, fail_on) for severity in severities)
