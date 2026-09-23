"""Invariants for this repository's own dependency pins.

These are not tests of the tool — they are tests of the repo that ships it.
Dependency upkeep used to be Dependabot's job. It is now ``scripts/deps.py``
(an OSV advisory check plus a wholesale closure regenerator) and a weekly
workflow, so these tests make sure the replacement cannot quietly go blind:
every pinned file stays visible to the checker, one flaw counts once, and a
closure is only ever written whole, from releases old enough to trust.
"""

from __future__ import annotations

import argparse
import re
import runpy
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def deps(repo_root):
    return runpy.run_path(str(repo_root / "scripts" / "deps.py"))


def _tracked(repo_root: Path, pattern: str) -> set[str]:
    try:
        out = subprocess.run(
            ["git", "ls-files", pattern], cwd=repo_root, capture_output=True, text=True, check=True
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    return {line for line in out.splitlines() if not line.startswith("tests/fixtures/")}


# --- the repository ------------------------------------------------------------


def test_no_dependency_bot_config(repo_root):
    """Dependabot was removed on purpose; scripts/deps.py says why. A config
    coming back would restart pull requests against the hash-pinned closures,
    which can only move whole — the failure mode that sank #47."""
    for name in ("dependabot.yml", "dependabot.yaml"):
        assert not (repo_root / ".github" / name).exists(), (
            f".github/{name} is back. Dependency upkeep is scripts/deps.py plus "
            ".github/workflows/dependency-advisories.yml; remove the bot config or "
            "update this test together with that decision."
        )


def test_advisory_check_sees_every_pinned_file(repo_root, deps):
    """The checker protects only what it can see. Every committed lockfile and
    closure must contribute pins, so adding one cannot leave it unmonitored."""
    pins = deps["all_pins"](repo_root)
    sources = {p.source for p in pins}
    expected = _tracked(repo_root, "*package-lock.json") | _tracked(
        repo_root, "scripts/*-requirements.txt"
    )
    assert expected, "no lockfiles found — this test would silently pass forever"
    missing = sorted(expected - sources)
    assert not missing, f"scripts/deps.py check does not read: {missing}"
    ecosystems = {p.ecosystem for p in pins}
    assert {"PyPI", "npm", "GitHub Actions", "Go"} <= ecosystems, ecosystems


def test_setup_scripts_run_no_unpinned_npx_package(repo_root, deps):
    """`npx -y name` fetches and runs the newest release at that moment — the
    same hole a lockfile closes, on the machine an agent works from."""
    specs = deps["npx_specs"](repo_root)
    unpinned = [f"{source}: {spec}" for spec, source in specs
                if not deps["_NPX_PINNED"].match(spec)]
    assert not unpinned, f"npx packages without an exact version: {unpinned}"
    assert {p.name for p in deps["npx_pins"](repo_root)} >= {s.split("@")[0] for s, _ in specs}


def test_every_action_pin_names_its_version(repo_root):
    """OSV looks an action up by release version, and the version lives only in
    the trailing comment. A bare SHA is invisible to the advisory check."""
    bare = []
    files = [*sorted((repo_root / ".github" / "workflows").glob("*.y*ml")), repo_root / "action.yml"]
    for path in files:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"uses:\s*\S+@[0-9a-f]{40}", line) and not re.search(r"#\s*v?\d", line):
                bare.append(f"{path.relative_to(repo_root)}:{number}")
    assert not bare, f"SHA pins without a `# vX.Y.Z` comment: {bare}"


def test_ladder_labels_match_the_closures(repo_root):
    """install-ladder.sh prints "installed semgrep vX (verified)" from its own
    variable while pip installs whatever the closure pins. Nothing tied the two
    together, and a log line that misstates the installed version is worse
    than none."""
    script = (repo_root / "scripts" / "install-ladder.sh").read_text(encoding="utf-8")
    for tool in ("semgrep", "zizmor"):
        label = re.search(rf"^{tool.upper()}_VERSION=(\S+)$", script, re.MULTILINE)
        closure = (repo_root / "scripts" / f"{tool}-requirements.txt").read_text(encoding="utf-8")
        pinned = re.search(rf"^{tool}==(\S+)", closure, re.MULTILINE)
        assert label and pinned, tool
        assert label.group(1) == pinned.group(1), (
            f"install-ladder.sh says {tool} {label.group(1)}, the closure pins {pinned.group(1)}"
        )


def test_closures_are_generated_whole_and_fully_hashed(repo_root):
    """A closure moves only by regeneration, and --require-hashes needs every
    entry hashed. The header names the command, so nobody hand-edits a line."""
    for closure in sorted((repo_root / "scripts").glob("*-requirements.txt")):
        text = closure.read_text(encoding="utf-8")
        assert "scripts/deps.py pin-closure" in text, f"{closure.name} was not generated"
        entries = re.split(r"^(?=[A-Za-z0-9._-]+==)", text, flags=re.MULTILINE)[1:]
        assert entries, closure.name
        for entry in entries:
            name = entry.split("==", 1)[0]
            hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", entry)
            assert hashes, f"{closure.name}: {name} has no artifact digest"


# --- scripts/deps.py -----------------------------------------------------------


def _vuln(vid, *aliases, fixed="9.9.9", name="pkg"):
    return {
        "id": vid,
        "aliases": list(aliases),
        "summary": f"summary of {vid}",
        "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"name": name}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": fixed}]}]}],
    }


def test_one_flaw_published_twice_counts_once(deps):
    """The self-scan once reported "7 vulnerable dependencies" for two packages:
    every mcp flaw arrived as both a GHSA and a PYSEC record. Merge on aliases."""
    Pin = deps["Pin"]
    pin = Pin("PyPI", "pkg", "1.0", "scripts/x-requirements.txt")
    records = {
        "GHSA-aaaa": _vuln("GHSA-aaaa", "CVE-1", "PYSEC-1"),
        "PYSEC-1": _vuln("PYSEC-1", "CVE-1", "GHSA-aaaa"),
        "GHSA-bbbb": _vuln("GHSA-bbbb", "CVE-2", fixed="2.0"),
    }
    found = deps["advisories"](
        [pin, Pin("PyPI", "clean", "1.0", "x")],
        query_batch=lambda pins: [list(records), []],
        fetch=records.__getitem__,
    )
    assert len(found) == 2
    assert {a.ids for a in found} == {("CVE-1", "GHSA-aaaa", "PYSEC-1"), ("CVE-2", "GHSA-bbbb")}
    assert {a.fixed for a in found} == {("9.9.9",), ("2.0",)}


def test_range_floors_are_checked(tmp_path, deps):
    """`pytest>=8` admitted a release with a published tmpdir flaw even though
    CI resolved a fixed one. The floor is what the range promises is fine."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["ruamel.yaml>=0.18,<0.20", "foo<2"]\n'
        '[project.optional-dependencies]\ndev = ["pytest>=8,<10", "bar[extra]==1.2.3; python_version<\'4\'"]\n',
        encoding="utf-8",
    )
    pins = {(p.name, p.version) for p in deps["pyproject_floor_pins"](tmp_path)}
    assert pins == {("ruamel.yaml", "0.18"), ("pytest", "8"), ("bar", "1.2.3")}


def test_ladder_binaries_map_to_go_modules(repo_root, deps):
    pins = {p.name: p.version for p in deps["ladder_binary_pins"](repo_root)}
    script = (repo_root / "scripts" / "install-ladder.sh").read_text(encoding="utf-8")
    gitleaks = re.search(r"^GITLEAKS_VERSION=(\S+)$", script, re.MULTILINE).group(1)
    assert pins[f"github.com/zricethezav/gitleaks/v{gitleaks.split('.')[0]}"] == gitleaks
    assert len(pins) == 3, pins


def test_check_refuses_to_report_clean_on_nothing(tmp_path, deps, capsys):
    assert deps["cmd_check"](argparse.Namespace(root=str(tmp_path))) == 2
    assert "refusing" in capsys.readouterr().out.lower()


def test_rendered_closure_round_trips(tmp_path, deps):
    Release = deps["Release"]
    now = datetime.now(UTC)
    releases = [Release("alpha", "1.0", ("a" * 64, "b" * 64), now), Release("beta", "2.0", ("c" * 64,), now)]
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "tool-requirements.txt").write_text(
        deps["render_closure"](releases, ["alpha==1.0"], "scripts/tool-requirements.txt"),
        encoding="utf-8",
    )
    pins = {(p.name, p.version) for p in deps["closure_pins"](tmp_path)}
    assert pins == {("alpha", "1.0"), ("beta", "2.0")}
    text = (scripts / "tool-requirements.txt").read_text(encoding="utf-8")
    assert text.count("--hash=sha256:") == 3
    assert not text.rstrip().endswith("\\"), "a trailing continuation would swallow the next line"


def test_closure_resolves_as_of_the_cutoff(deps, tmp_path):
    """A release younger than the cutoff is excluded and the closure resolved
    again — pip has no "exclude newer", so the script does it by name."""
    Release = deps["Release"]
    now = datetime(2026, 9, 23, tzinfo=UTC)
    fresh, old = now - timedelta(days=1), now - timedelta(days=30)

    def resolver(requirements, python, workdir, excluded):
        return [("lib", "1.0" if "2.0" in excluded.get("lib", set()) else "2.0")]

    def release(name, version):
        return Release(name, version, ("d" * 64,), fresh if version == "2.0" else old)

    project = {"releases": {
        "1.0": [{"upload_time_iso_8601": old.isoformat()}],
        "2.0": [{"upload_time_iso_8601": fresh.isoformat()}],
    }}
    releases, excluded = deps["settle"](
        ["tool==1"], Path("python"), tmp_path, min_age_days=7, now=now,
        release=release, project=lambda name: project, resolver=resolver,
    )
    assert [(r.name, r.version) for r in releases] == [("lib", "1.0")]
    assert excluded == {"lib": {"2.0"}}


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "http://api.osv.dev/v1/querybatch",
    "https://api.osv.dev.evil.example/v1/querybatch",
    "https://pypi.org:8443/pypi/x/json",
])
def test_advisory_client_fetches_only_its_two_https_endpoints(deps, url):
    """urllib honours file:// and any host it is handed; the check must not."""
    with pytest.raises(ValueError):
        deps["_http_json"](url)
