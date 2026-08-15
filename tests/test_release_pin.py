"""The advertised install and Action pin must resolve.

This file exists because both of them silently stopped resolving, and nothing
caught it. The site, the README and the Setup Studio all told a new user to run
`pipx install tridelphi` while the package 404'd on PyPI, and every `uses:` line
said `@v3` while only `v3.1.0` and `v3.0.0-beta` were tagged. Those are the
first two commands anybody runs. A product-level audit found them; a test should
have.

The rule enforced here: every user-facing surface reads its install line and its
`uses:` pin from `tridelphi.release`, so there is exactly one place to change at
release time and drift fails the build instead of a stranger's first run.
"""

from __future__ import annotations

import re

import pytest

from tridelphi.release import ACTION_REPO, ACTION_SHA, PYPI_PUBLISHED, install_command

# What a new user reads before they have any reason to trust us. `docs/` is
# builder documentation and `docs/RELEASES.md` in particular exists to describe
# the state we have not reached yet, so the install-string rule does not apply
# there — the pin rule below still does.
_USER_FACING = ("README.md", "site/index.html", "site/setup.html")

# Any `girnarholdings/TriDelPhi@<ref>` we publish anywhere. Test fixtures are
# excluded: they are deliberately-broken sample repos, not instructions.
_PINNED = tuple(
    f"{d}{f}" for d, f in (
        ("", "README.md"), ("", "action.yml"),
        ("site/", "index.html"), ("site/", "setup.html"),
        ("docs/", "MARKETPLACE.md"), ("docs/", "RELEASES.md"), ("docs/", "REPO_SETUP.md"),
    )
)

_USES_RE = re.compile(re.escape(ACTION_REPO) + r"@([A-Za-z0-9._\-]+)")


@pytest.mark.parametrize("relpath", _PINNED)
def test_every_advertised_pin_is_the_one_release_pin(repo_root, relpath):
    """A pin that does not resolve is worse than no pin: the user follows the
    instruction, CI fails on a reference error, and nothing in the message says
    the docs were wrong."""
    text = (repo_root / relpath).read_text(encoding="utf-8")
    refs = set(_USES_RE.findall(text))
    stale = refs - {ACTION_SHA}
    assert not stale, (
        f"{relpath} advertises {sorted(stale)}; the only pin we publish is "
        f"ACTION_SHA. Change tridelphi/release.py, not the file."
    )


_TAG = re.compile(r"<[^>]+>")


def _commands(text: str) -> list[str]:
    """The lines of a page that read as "type this".

    Deliberately not a substring search over the whole file: prose *about* a
    command ("why not `pipx install tridelphi`? because it 404s") is the honest
    thing to write, and a rule that forbids naming the broken command would push
    us back toward silence about it. What must not appear is the command sitting
    on its own line where a reader will copy it.
    """
    out = []
    for line in text.splitlines():
        bare = _TAG.sub("", line).strip().lstrip("$").strip()
        if bare:
            out.append(bare)
    return out


@pytest.mark.parametrize("relpath", _USER_FACING)
def test_no_user_facing_surface_advertises_an_install_that_404s(repo_root, relpath):
    if PYPI_PUBLISHED:
        pytest.skip("published — the short install line is correct now")
    for line in _commands((repo_root / relpath).read_text(encoding="utf-8")):
        for dead in ("pipx install tridelphi", "pip install tridelphi", "uvx tridelphi"):
            assert not line.startswith(dead), (
                f"{relpath} puts `{dead}` on a line a reader will copy, but the "
                "package is not on PyPI. Flip PYPI_PUBLISHED in "
                "tridelphi/release.py at first publish; until then every install "
                "line must come from install_command()."
            )


@pytest.mark.parametrize("relpath", _USER_FACING)
def test_every_user_facing_surface_shows_the_working_install(repo_root, relpath):
    text = (repo_root / relpath).read_text(encoding="utf-8")
    assert install_command() in text or install_command(tool="pip") in text, (
        f"{relpath} never shows a working install command"
    )


def test_the_pin_is_immutable(repo_root):
    """We advertise a commit SHA, not a moving tag, for the same reason the
    repo pins `actions/checkout` by SHA: a tag can be repointed at code the
    user never agreed to run. The readable version lives in a trailing comment.
    """
    assert re.fullmatch(r"[0-9a-f]{40}", ACTION_SHA), "the pin must be a full commit SHA"


def test_ci_installs_are_pinned_and_local_installs_are_not():
    """Opposite defaults on purpose. An unpinned install inside a job that holds
    a repository token is the supply-chain shape this tool exists to flag, so
    every generated workflow gets the immutable form. A person at a laptop gets
    the short one — they re-run it to pick up a fix, and a 40-character SHA in
    the hero install box is a reason not to try the tool at all."""
    from tridelphi.init_cmd import APP_WORKFLOW, FIX_WORKFLOW, WORKFLOW

    assert ACTION_SHA not in install_command()
    if not PYPI_PUBLISHED:
        assert ACTION_SHA in install_command(pinned=True)
    for template in (WORKFLOW, FIX_WORKFLOW, APP_WORKFLOW):
        for line in template.splitlines():
            if line.strip().startswith("run:") and "install" in line and "tridelphi" in line:
                assert install_command(pinned=True) in line, (
                    f"unpinned install in a generated workflow: {line.strip()!r}"
                )
