"""What we tell users to type — install command and Action pin, in one place.

Every surface that advertises an install (`README`, the site, `tridelphi init`'s
generated workflows, the Setup Studio) used to spell it out by hand. They drifted:
the README and the site said `pipx install tridelphi` while the package was not on
PyPI, and every `uses:` line said `@v3` while only `v3.1.0` and `v3.0.0-beta`
existed. Both are the *first command a new user runs*, so both were a 404.

The fix is structural, not editorial: the strings live here, everything reads them,
and ``tests/test_release_pin.py`` fails the build if any surface drifts again.

Two switches, and only two, need touching at release time:

``PYPI_PUBLISHED``
    Flip to ``True`` the moment `tridelphi` exists on PyPI. Every advertised
    install becomes the short registry form.

``ACTION_SHA`` / ``ACTION_TAG``
    The commit users pin. We advertise a **SHA with the tag in a comment** — the
    same discipline this repo already applies to `actions/checkout` and friends,
    and the one GitHub itself recommends — so the pin is immutable and resolves
    today. ``ACTION_TAG`` names what that SHA is meant to be; once the tag is
    actually pushed, see `docs/RELEASES.md` for the one-line switch to it.
"""

from __future__ import annotations

__all__ = [
    "ACTION_REF",
    "ACTION_REPO",
    "ACTION_SHA",
    "ACTION_TAG",
    "action_uses",
    "install_command",
]

ACTION_REPO = "girnarholdings/TriDelPhi"

# The commit every advertised `uses:` line pins to. It must be a commit on the
# default branch that carries the current security posture — never an older
# release tag. (`v3.1.0` is commit 04bc341, which predates the August 2026
# remediation of the fix-bot authorization bypass; pinning users to it would
# hand them the vulnerable bot.)
ACTION_SHA = "d5c01388c21de9c1d12159087890d12d2d917990"
ACTION_TAG = "v3.1.1"

# `tridelphi` is not on PyPI yet, so the short install line is aspirational and
# the git URL is the one that actually works. Flip this at first publish.
PYPI_PUBLISHED = False


def action_uses() -> str:
    """The `uses:` value for the composite Action, SHA-pinned with the tag named.

    Rendered as ``owner/repo@<sha> # <tag>`` — immutable, resolvable today, and
    readable by a human who wants to know which version they are on.
    """
    return f"{ACTION_REPO}@{ACTION_SHA} # {ACTION_TAG}"


def install_command(*, tool: str = "pipx") -> str:
    """The install line that works right now.

    ``tool`` is ``pipx`` (isolated, what we recommend) or ``pip`` (into the
    current environment). Until the package is on PyPI this returns the git
    form, which installs the same commit the Action pins — so a user's CLI and
    their CI agree on a version instead of silently differing.
    """
    prefix = "pipx install" if tool == "pipx" else "pip install"
    if PYPI_PUBLISHED:
        return f"{prefix} tridelphi"
    return f"{prefix} git+https://github.com/{ACTION_REPO}@{ACTION_SHA}"


# The full `uses:` line as it appears in generated workflow YAML.
ACTION_REF = action_uses()
