"""Walking a job's steps — shared by every detector and the parser.

Six modules walk ``steps:`` and read ``uses:``; four of them had grown their
own private copy of the same two helpers. The helpers are small, but the
duplication was not free: the copies had already drifted on whether a
non-mapping step is skipped or crashes, and a detector that guesses wrong
about that turns a malformed workflow into a scan error instead of a finding.

The semantics, stated once:

* a step that is not a mapping is skipped — a stray string in a ``steps:``
  list is the workflow author's YAML problem, not a scan crash;
* the action name is everything before the ``@`` in ``uses:``, stripped, and
  a step with no ``uses:`` has the empty name, so prefix checks just work.
"""

from __future__ import annotations

from collections.abc import Iterator

from .yamlnode import YamlNode

__all__ = ["iter_steps", "uses_name"]


def iter_steps(body: YamlNode) -> Iterator[YamlNode]:
    """Yield each mapping step under ``body["steps"]``; nothing on absence."""
    steps = body.get("steps")
    if steps is None:
        return
    for step in steps.seq():
        if step.is_mapping():
            yield step


def uses_name(step: YamlNode) -> str:
    """The action a step ``uses:``, without its ref — '' when it runs a shell."""
    uses = step.get("uses")
    return uses.text.split("@", 1)[0].strip() if uses is not None else ""
