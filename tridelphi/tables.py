"""Loading for the tunable data tables.

The tables are a shared contract: ``parse.py`` needs the agent-config filenames
to build the repo inventory and the detectors need the same list to reason about
them. Splitting ownership guarantees drift, so there is exactly one loader and
one immutable object passed everywhere.

ruamel does the parsing here too. PyYAML is not used anywhere in this package:
it resolves ``on:`` to ``True`` and ``no``/``off`` to ``False``, which silently
corrupts any table using those as keys.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources
from typing import Any

from ruamel.yaml import YAML

__all__ = ["Tables", "load_tables"]

_FILES = ("triggers", "untrusted_expressions", "agent_signals", "egress", "adr_techniques")


class Tables:
    """Immutable view over the data tables."""

    __slots__ = ("_data",)

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def section(self, table: str, key: str, default: Any = None) -> Any:
        return self._data.get(table, {}).get(key, default if default is not None else [])

    def tuple_of(self, table: str, key: str) -> tuple[str, ...]:
        value = self._data.get(table, {}).get(key) or ()
        return tuple(str(v) for v in value)


def _load_one(name: str) -> Any:
    yaml = YAML(typ="rt")
    text = resources.files(f"{__package__}.data").joinpath(f"{name}.yml").read_text("utf-8")
    return yaml.load(text)


@lru_cache(maxsize=1)
def load_tables() -> Tables:
    return Tables({name: _load_one(name) for name in _FILES})
