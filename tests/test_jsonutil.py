"""The JSONC reader behind MCP and editor config discovery.

A config it cannot read does not vanish — it is reported as unknown — but an
unknown config is analysed as nothing, so every valid file it refuses is a
server whose tools the report never names.
"""

from __future__ import annotations

import pytest

from tridelphi.jsonutil import loads_jsonc
from tridelphi.parse import build_inventory


def test_comments_and_trailing_commas_outside_strings():
    text = '{\n  // line\n  "a": "x // not a comment", /* block */\n  "b": [1, 2,],\n}\n'
    assert loads_jsonc(text) == {"a": "x // not a comment", "b": [1, 2]}


def test_byte_order_mark_is_accepted():
    assert loads_jsonc('﻿{"a": 1}') == {"a": 1}


def test_unterminated_block_comment_is_an_error():
    with pytest.raises(ValueError):
        loads_jsonc('{"a": 1} /* never closed')


def test_bom_saved_mcp_config_is_analysed_not_unknown(tmp_path, tables):
    """Windows editors save a byte-order mark; the file used to land in
    `unknown_config_paths`, so its remote server was never modelled."""
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "mcp.json").write_text(
        '﻿{"servers": {"remote": {"url": "https://mcp.example.com/sse"}}}',
        encoding="utf-8",
    )
    inventory, _ = build_inventory(tmp_path, tables)
    assert [server.name for server in inventory.mcp_servers] == ["remote"]
    assert inventory.mcp_servers[0].remote
    assert inventory.unknown_config_paths == ()
