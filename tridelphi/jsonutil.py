"""Small, dependency-free JSON-with-comments reader for editor config files.

VS Code and agent configuration commonly use JSONC. Falling back to strict
``json.loads`` made a valid commented MCP file silently disappear from the
security model. This lexer removes comments and trailing commas only outside
strings, then delegates all actual JSON semantics to the standard library.
"""

from __future__ import annotations

import json
from typing import Any

__all__ = ["loads_jsonc"]


def loads_jsonc(text: str) -> Any:
    # Editors on Windows save JSON with a UTF-8 byte-order mark, and the
    # standard library refuses it, which turned a valid MCP config into an
    # "unknown" one instead of an analysed one.
    if text.startswith("\ufeff"):
        text = text[1:]
    stripped: list[str] = []
    i = 0
    in_string = False
    escaped = False
    while i < len(text):
        char = text[i]
        if in_string:
            stripped.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            i += 1
            continue
        if char == '"':
            in_string = True
            stripped.append(char)
            i += 1
            continue
        if char == "/" and i + 1 < len(text) and text[i + 1] == "/":
            stripped.extend("  ")
            i += 2
            while i < len(text) and text[i] not in "\r\n":
                stripped.append(" ")
                i += 1
            continue
        if char == "/" and i + 1 < len(text) and text[i + 1] == "*":
            stripped.extend("  ")
            i += 2
            while i + 1 < len(text) and text[i : i + 2] != "*/":
                stripped.append(text[i] if text[i] in "\r\n" else " ")
                i += 1
            if i + 1 >= len(text):
                raise ValueError("unterminated JSONC block comment")
            stripped.extend("  ")
            i += 2
            continue
        stripped.append(char)
        i += 1

    # Remove a comma only when the next non-whitespace token is ] or }, and
    # only outside a string. Whitespace/newlines stay in place for diagnostics.
    source = "".join(stripped)
    clean: list[str] = []
    i = 0
    in_string = False
    escaped = False
    while i < len(source):
        char = source[i]
        if in_string:
            clean.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            i += 1
            continue
        if char == '"':
            in_string = True
            clean.append(char)
            i += 1
            continue
        if char == ",":
            look = i + 1
            while look < len(source) and source[look].isspace():
                look += 1
            if look < len(source) and source[look] in "]}":
                clean.append(" ")
                i += 1
                continue
        clean.append(char)
        i += 1
    return json.loads("".join(clean))
