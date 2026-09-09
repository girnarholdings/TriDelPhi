"""Resource-budget validation for parsed JSON/YAML object graphs."""

from __future__ import annotations

from typing import Any

__all__ = ["structure_error"]


def structure_error(
    value: Any,
    *,
    max_nodes: int = 500_000,
    max_depth: int = 100,
    max_collection_items: int = 100_000,
    max_string_chars: int = 1_000_000,
) -> str | None:
    """Return a concise defect when a parsed object graph exceeds its budget.

    File-size limits do not contain YAML aliases: a tiny document can reference
    one collection thousands of times or form a recursive alias. Count every
    occurrence, reject active cycles, and bound depth, collection fan-out and
    string size before any detector recursively walks the object.
    """

    limits = (max_nodes, max_depth, max_collection_items, max_string_chars)
    if any(not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in limits):
        raise ValueError("structure limits must be non-negative integers")

    nodes = 0
    active: set[int] = set()
    stack: list[tuple[Any, int, bool]] = [(value, 0, False)]
    while stack:
        current, depth, leaving = stack.pop()
        container = isinstance(current, (dict, list, tuple))
        identity = id(current) if container else 0
        if leaving:
            active.discard(identity)
            continue

        nodes += 1
        if nodes > max_nodes:
            return f"structure exceeds {max_nodes:,} nodes"
        if depth > max_depth:
            return f"structure exceeds depth {max_depth}"
        if isinstance(current, str) and len(current) > max_string_chars:
            return f"structure contains a string over {max_string_chars:,} characters"
        if not container:
            continue
        if identity in active:
            return "structure contains a recursive alias"
        if len(current) > max_collection_items:
            return f"collection exceeds {max_collection_items:,} items"

        active.add(identity)
        stack.append((current, depth, True))
        if isinstance(current, dict):
            for key, child in reversed(tuple(current.items())):
                stack.append((child, depth + 1, False))
                stack.append((key, depth + 1, False))
        else:
            for child in reversed(current):
                stack.append((child, depth + 1, False))
    return None
