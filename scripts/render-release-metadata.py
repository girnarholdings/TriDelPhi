#!/usr/bin/env python3
"""Render the static site's release constants from tridelphi.release."""

from __future__ import annotations

import json
from pathlib import Path

from tridelphi.release import ACTION_REPO, ACTION_SHA, ACTION_TAG, action_uses, install_command


def render() -> str:
    values = {
        "actionRepo": ACTION_REPO,
        "actionSha": ACTION_SHA,
        "actionTag": ACTION_TAG,
        "actionUses": action_uses(),
        "install": install_command(),
        "installPinned": install_command(pinned=True),
    }
    lines = [
        "// Generated from tridelphi/release.py by scripts/render-release-metadata.py.",
        "// Do not edit release strings here by hand.",
        "window.TRIDELPHI_RELEASE = Object.freeze({",
    ]
    entries = list(values.items())
    for index, (key, value) in enumerate(entries):
        comma = "," if index + 1 < len(entries) else ""
        lines.append(f"  {key}: {json.dumps(value)}{comma}")
    lines.append("});")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    (root / "site" / "release.js").write_text(render(), encoding="utf-8", newline="\n")
