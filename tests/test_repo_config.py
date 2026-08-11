"""Invariants for this repository's own automation config.

These are not tests of the tool — they are tests of the repo that ships it,
codifying rules that were each learned by breaking something. A broken
dependency bot produces pull requests that can never merge, which is exactly
the "why is CI red and what do I do" experience TriDelPhi exists to remove.
"""

from __future__ import annotations

import re

import pytest

yaml = pytest.importorskip("ruamel.yaml")


def _load(path):
    from ruamel.yaml import YAML

    return YAML(typ="safe").load(path.read_text(encoding="utf-8"))


def _closure_packages(repo_root) -> dict[str, str]:
    """Every package pinned in a hash-pinned scanner closure -> the file."""
    found: dict[str, str] = {}
    for freeze in sorted((repo_root / "scripts").glob("*-requirements.txt")):
        for line in freeze.read_text(encoding="utf-8").splitlines():
            m = re.match(r"^([A-Za-z0-9._-]+)==", line)
            if m:
                found.setdefault(m.group(1).lower().replace("_", "-"), freeze.name)
    return found


def test_dependabot_never_watches_a_package_inside_a_pinned_closure(repo_root):
    """The bug this encodes: `allow` names *dependencies*, but Dependabot edits
    every file a named dependency appears in. `jsonschema` sat in both
    pyproject.toml and semgrep's closure, so watching it dragged the closure
    along — and since semgrep constrains its own dependencies exactly, the
    result was a pull request that failed with ResolutionImpossible and could
    never be merged or rebased into working.

    A closure moves only by being regenerated wholesale for a scanner upgrade.
    So nothing inside one may be watched individually.
    """
    config = _load(repo_root / ".github" / "dependabot.yml")
    closure = _closure_packages(repo_root)
    assert closure, "no closures found — this test would silently pass forever"

    offenders = []
    for update in config["updates"]:
        if update.get("package-ecosystem") != "pip":
            continue
        for entry in update.get("allow", []):
            name = str(entry.get("dependency-name", "")).lower().replace("_", "-")
            if name in closure:
                offenders.append(f"{name} (pinned in {closure[name]})")
    assert not offenders, (
        "Dependabot is watching packages that live in a hash-pinned closure, so "
        "it will open unmergeable pull requests against it: "
        + "; ".join(sorted(offenders))
    )


def test_dependabot_groups_every_ecosystem(repo_root):
    """Ungrouped, one weekly sweep opened six separate action bumps that each
    tripped the trust-lock independently — six reviews, six re-locks, and a
    rebase treadmill. Grouping makes a sweep one decision."""
    config = _load(repo_root / ".github" / "dependabot.yml")
    ungrouped = [
        u.get("package-ecosystem")
        for u in config["updates"]
        if not u.get("groups")
    ]
    assert not ungrouped, f"these ecosystems would open one PR per package: {ungrouped}"


def test_pip_updates_are_scoped_by_an_allow_list(repo_root):
    """Without `allow`, the pip ecosystem walks the whole tree and finds the
    closures. The allow list is the only thing keeping it to pyproject.toml."""
    config = _load(repo_root / ".github" / "dependabot.yml")
    pip = [u for u in config["updates"] if u.get("package-ecosystem") == "pip"]
    assert pip, "the pip ecosystem is not configured at all"
    for update in pip:
        assert update.get("allow"), (
            "the pip ecosystem needs an explicit `allow` list; without one "
            "Dependabot will open pull requests against scripts/*-requirements.txt"
        )
