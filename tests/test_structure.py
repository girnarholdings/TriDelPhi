from __future__ import annotations

import pytest

from tridelphi.structure import structure_error


def test_structure_budget_detects_cycles_depth_fanout_and_strings():
    recursive: list = []
    recursive.append(recursive)
    assert "recursive alias" in structure_error(recursive)
    assert "depth" in structure_error([[[1]]], max_depth=1)
    assert "collection" in structure_error([1, 2], max_collection_items=1)
    assert "string" in structure_error("long", max_string_chars=3)
    assert "nodes" in structure_error([1, 2], max_nodes=2)


def test_structure_budget_counts_shared_alias_occurrences():
    shared = ["value"]
    assert "nodes" in structure_error([shared, shared, shared], max_nodes=6)


@pytest.mark.parametrize("bad", (-1, True))
def test_structure_budget_rejects_invalid_limits(bad):
    with pytest.raises(ValueError):
        structure_error({}, max_nodes=bad)
