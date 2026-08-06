"""Positioned navigation over a ruamel round-trip parse.

ruamel only attaches ``.lc`` to containers (``CommentedMap`` / ``CommentedSeq``);
scalars carry nothing. A detector handed a bare ``LiteralScalarString`` therefore
has no way to say where it came from. ``YamlNode`` keeps the parent and the key
alongside the value so navigation yields positions, and detectors never touch a
ruamel type directly.

Line math inside a block scalar is exact for literal (``|``) blocks, which are
>95% of ``run:`` bodies in the wild. Folded (``>``) and plain multi-line scalars
fold source lines into one logical line, so content offsets stop corresponding to
source offsets; those degrade to the owning key's line. The degradation always
undershoots to a real construct, never to an unrelated one.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from ruamel.yaml.scalarstring import LiteralScalarString

from .model import Position

__all__ = ["YamlNode"]


def _lc_line(container: Any, accessor: str, key: Any) -> int | None:
    """Read a 0-indexed ``.lc`` coordinate, tolerating keys ruamel has no entry
    for (merge keys ``<<:`` are present in the mapping but absent from ``.lc``)."""
    lc = getattr(container, "lc", None)
    if lc is None:
        return None
    try:
        coord = getattr(lc, accessor)(key)
    except (KeyError, IndexError, TypeError, AttributeError):
        return None
    if not coord:
        return None
    return coord[0]


def _lc_col(container: Any, accessor: str, key: Any) -> int | None:
    lc = getattr(container, "lc", None)
    if lc is None:
        return None
    try:
        coord = getattr(lc, accessor)(key)
    except (KeyError, IndexError, TypeError, AttributeError):
        return None
    if not coord or len(coord) < 2:
        return None
    return coord[1]


class YamlNode:
    """A YAML value plus enough context to locate it in source.

    Navigation returns ``YamlNode``; ``.value`` unwraps to the plain object.
    Missing keys yield ``None`` from :meth:`get` rather than raising, because
    workflow files in the wild are frequently partial.
    """

    __slots__ = ("_file", "_key", "_lines", "_parent", "value")

    def __init__(
        self,
        value: Any,
        file: str,
        lines: tuple[str, ...],
        parent: Any = None,
        key: Any = None,
    ) -> None:
        self.value = value
        self._file = file
        self._lines = lines
        self._parent = parent
        self._key = key

    # -- construction ----------------------------------------------------

    @classmethod
    def root(cls, value: Any, file: str, source: str) -> YamlNode:
        return cls(value, file, tuple(source.splitlines()))

    def _child(self, value: Any, key: Any) -> YamlNode:
        return YamlNode(value, self._file, self._lines, parent=self.value, key=key)

    # -- navigation ------------------------------------------------------

    def get(self, key: Any, default: Any = None) -> YamlNode | None:
        if not isinstance(self.value, dict):
            return None
        if key not in self.value:
            return None if default is None else self._child(default, key)
        return self._child(self.value[key], key)

    def __getitem__(self, key: Any) -> YamlNode:
        if isinstance(self.value, (list, tuple)):
            return self._child(self.value[key], key)
        return self._child(self.value[key], key)

    def __contains__(self, key: Any) -> bool:
        return isinstance(self.value, dict) and key in self.value

    def __iter__(self) -> Iterator[YamlNode]:
        if isinstance(self.value, (list, tuple)):
            for i, item in enumerate(self.value):
                yield self._child(item, i)
        elif isinstance(self.value, dict):
            for k in self.value:
                yield self._child(self.value[k], k)

    def items(self) -> Iterator[tuple[Any, YamlNode]]:
        if not isinstance(self.value, dict):
            return
        for k in self.value:
            yield k, self._child(self.value[k], k)

    def keys(self) -> tuple[Any, ...]:
        if not isinstance(self.value, dict):
            return ()
        return tuple(self.value.keys())

    def seq(self) -> tuple[YamlNode, ...]:
        """This node as a sequence. A bare scalar becomes a one-element
        sequence, which is how GitHub treats several workflow keys."""
        if isinstance(self.value, (list, tuple)):
            return tuple(self._child(v, i) for i, v in enumerate(self.value))
        if self.value is None:
            return ()
        return (self,)

    # -- scalar helpers --------------------------------------------------

    @property
    def text(self) -> str:
        return self.value if isinstance(self.value, str) else ""

    def is_mapping(self) -> bool:
        return isinstance(self.value, dict)

    # -- positions -------------------------------------------------------

    def position(self) -> Position:
        """Position of this node's *key* token, 1-indexed.

        Anchoring on the key rather than the value matters for null-valued
        mappings, where ruamel's ``lc.value()`` returns the *next* key's line.
        """
        line = col = None
        if self._parent is not None and self._key is not None:
            if isinstance(self._key, int):
                line = _lc_line(self._parent, "item", self._key)
                col = _lc_col(self._parent, "item", self._key)
            else:
                line = _lc_line(self._parent, "key", self._key)
                col = _lc_col(self._parent, "key", self._key)
        if line is None:
            line = _lc_line(self.value, "line", None)
        if line is None:
            lc = getattr(self.value, "lc", None)
            line = getattr(lc, "line", None) if lc is not None else None
            col = getattr(lc, "col", None) if lc is not None else col
        if line is None:
            return Position(file=self._file, line=1)
        return Position(
            file=self._file,
            line=line + 1,
            column=None if col is None else col + 1,
            snippet=self._source_line(line + 1),
        )

    def value_position(self) -> Position:
        """Position of this node's *value* token, 1-indexed."""
        if self._parent is not None and self._key is not None and not isinstance(self._key, int):
            line = _lc_line(self._parent, "value", self._key)
            col = _lc_col(self._parent, "value", self._key)
            if line is not None:
                return Position(
                    file=self._file,
                    line=line + 1,
                    column=None if col is None else col + 1,
                    snippet=self._source_line(line + 1),
                )
        return self.position()

    def _source_line(self, line_1indexed: int) -> str | None:
        idx = line_1indexed - 1
        if 0 <= idx < len(self._lines):
            return self._lines[idx].strip() or None
        return None

    def _is_literal_block(self) -> bool:
        return isinstance(self.value, LiteralScalarString)

    def scalar_line(self, content_line_index: int) -> Position:
        """Source position of line ``content_line_index`` of a multi-line scalar.

        Exact for literal (``|``) blocks. Everything else degrades to the
        owning key's line, which is a real construct and never misleading.
        """
        base = self.value_position()
        if not self._is_literal_block() or content_line_index < 0:
            return base
        line = base.line + 1 + content_line_index
        return Position(file=self._file, line=line, snippet=self._source_line(line))

    def find_substring(self, needle: str) -> Position:
        """Position of the first source line of this scalar containing ``needle``.

        Falls back to the node position when the scalar is not a literal block
        or the needle spans a fold.
        """
        text = self.text
        if not text or needle not in text:
            return self.value_position()
        for i, line in enumerate(text.splitlines()):
            if needle in line:
                return self.scalar_line(i)
        return self.value_position()
