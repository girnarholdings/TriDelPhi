"""Every third-party action pin must agree across the repo's own workflows, the
composite action, the workflows `tridelphi init` generates, and the Setup Studio.

The same actions are pinned by SHA in all four places, and a bump that edits
only the workflow files — the ones a reviewer looks at — would silently leave the
templates users receive on the old commit, and the trust story ("we pin what we
tell you to pin") stops being true. This test turns that drift into a failing
build with the exact SHAs named, so a pin bump is finished in one change or not
merged. (The update bot that used to make exactly that half-change is gone; the
procedure is in docs/RELEASES.md under "Dependencies".)
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tridelphi.init_cmd import APP_WORKFLOW, FIX_WORKFLOW, WORKFLOW, render_action_workflow
from tridelphi.release import ACTION_REPO

_USES = re.compile(r"uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([0-9a-f]{40})")


def _pins(text: str) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for action, sha in _USES.findall(text):
        if action.startswith(ACTION_REPO):
            continue  # our own pin is governed by tridelphi/release.py and its test
        found.setdefault(action, set()).add(sha)
    return found


def _repo_pins(repo_root: Path) -> dict[str, set[str]]:
    merged: dict[str, set[str]] = {}
    for path in [*(repo_root / ".github" / "workflows").glob("*.yml"), repo_root / "action.yml"]:
        for action, shas in _pins(path.read_text(encoding="utf-8")).items():
            merged.setdefault(action, set()).update(shas)
    return merged


def test_repo_workflows_pin_each_action_to_one_sha(repo_root):
    split = {a: s for a, s in _repo_pins(repo_root).items() if len(s) > 1}
    assert not split, f"an action is pinned to different SHAs within the repo: {split}"


@pytest.mark.parametrize("name, text", [
    ("init WORKFLOW", WORKFLOW),
    ("init FIX_WORKFLOW", FIX_WORKFLOW),
    ("init APP_WORKFLOW", APP_WORKFLOW),
    ("init composite workflow", render_action_workflow(level=7, expose=True)),
])
def test_generated_workflows_match_repo_pins(repo_root, name, text):
    repo = _repo_pins(repo_root)
    for action, shas in _pins(text).items():
        assert action in repo, f"{name} pins {action}, which the repo itself never uses"
        assert shas == repo[action], (
            f"{name} pins {action}@{sorted(shas)} but the repo pins {sorted(repo[action])}; "
            "bump both in the same change"
        )


def test_setup_studio_matches_repo_pins(repo_root):
    repo = _repo_pins(repo_root)
    text = (repo_root / "site" / "setup.html").read_text(encoding="utf-8")
    studio = {}
    for action, sha in re.findall(r'"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-f]{40})', text):
        if not action.startswith(ACTION_REPO):
            studio.setdefault(action, set()).add(sha)
    assert studio, "the Setup Studio should pin at least one action by SHA"
    for action, shas in studio.items():
        assert shas == repo.get(action), (
            f"site/setup.html pins {action}@{sorted(shas)} but the repo pins "
            f"{sorted(repo.get(action, set()))}"
        )
