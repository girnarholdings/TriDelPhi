#!/usr/bin/env python3
"""Keep this repository's pinned dependencies current without a bot.

    python3 scripts/deps.py check
    python3 scripts/deps.py pin-closure semgrep==1.177.0 -o scripts/semgrep-requirements.txt

This replaces Dependabot, and the replacement is deliberately smaller than what
it replaces. Dependabot did two jobs here: it told us when something we pin had
a published vulnerability, and it opened pull requests to move pins. The first
job is essential and is ``check``. The second job cost more than it saved: its
action bumps each tripped the trust-lock separately, its pip bumps could not
touch the hash-pinned scanner closures without breaking them, and a third-party
bot with write access to pull requests is exactly the supply-chain surface this
project tells other people to shrink.

``check``
    Queries OSV (https://osv.dev) for every version this repository pins or
    admits: the scanner closures in ``scripts/*-requirements.txt``, every
    committed ``package-lock.json``, the SHA-pinned actions (by the version in
    their trailing comment), the scanner binaries in ``install-ladder.sh``, and
    the *lowest* version each ``pyproject.toml`` range admits. Exits 1 when any
    of them has a known advisory. Aliases are merged, so one flaw published as
    both a GHSA and a PYSEC record counts once.

``pin-closure``
    Regenerates one hash-pinned closure wholesale. A closure is only coherent
    as a whole — semgrep pins several of its own dependencies exactly — so it
    never moves one line at a time. The command resolves the requirement
    without running any package code (``pip install --dry-run --only-binary``),
    records the sha256 of every artifact PyPI publishes for each resolved
    release, refuses releases younger than ``--min-age-days`` or with a known
    advisory, and proves the file by installing it with ``--require-hashes``
    into a clean virtual environment.

Standard library only, so it runs on a bare runner before anything is installed.
"""

from __future__ import annotations

import argparse
import functools
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
PYPI_RELEASE = "https://pypi.org/pypi/{name}/{version}/json"
PYPI_PROJECT = "https://pypi.org/pypi/{name}/json"
TIMEOUT = 60

# The prebuilt scanners install-ladder.sh downloads, by the variable that pins
# each one, mapped to the Go module OSV files their advisories under. The major
# version suffix (/v8, /v2, ...) is derived from the pinned version.
LADDER_BINARIES = {
    "GITLEAKS_VERSION": "github.com/zricethezav/gitleaks",
    "OSV_SCANNER_VERSION": "github.com/google/osv-scanner",
    "SCORECARD_VERSION": "github.com/ossf/scorecard",
}

_USES = re.compile(
    r"uses:\s*['\"]?(?P<repo>[\w.-]+/[\w.-]+)(?:/[\w./-]*)?@(?P<sha>[0-9a-f]{40})['\"]?"
    r"\s*#\s*v?(?P<version>[0-9][\w.+-]*)"
)
_PIN = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)==(?P<version>[^\s;\\]+)")
_FLOOR = re.compile(r"^\s*(?P<name>[A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*(?P<spec>[^;]*)")


@dataclass(frozen=True)
class Pin:
    ecosystem: str  # OSV ecosystem name
    name: str
    version: str
    source: str  # repo-relative file that pins it


@dataclass(frozen=True)
class Advisory:
    pin: Pin
    ids: tuple[str, ...]  # every alias OSV knows for the one flaw
    severity: str
    fixed: tuple[str, ...]
    summary: str


# --- what the repository pins -------------------------------------------------


def _rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _skipped(path: Path, root: Path) -> bool:
    parts = path.relative_to(root).parts
    return "node_modules" in parts or parts[:2] == ("tests", "fixtures")


def closure_pins(root: Path) -> list[Pin]:
    pins = []
    for req in sorted((root / "scripts").glob("*-requirements.txt")):
        for line in req.read_text(encoding="utf-8").splitlines():
            m = _PIN.match(line)
            if m:
                pins.append(Pin("PyPI", m["name"], m["version"], _rel(req, root)))
    return pins


def npm_lock_pins(root: Path) -> list[Pin]:
    pins = []
    for lock in sorted(root.rglob("package-lock.json")):
        if _skipped(lock, root):
            continue
        data = json.loads(lock.read_text(encoding="utf-8"))
        for key, meta in (data.get("packages") or {}).items():
            if not key or not isinstance(meta, dict) or "version" not in meta:
                continue
            if meta.get("link"):
                continue
            name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
            pins.append(Pin("npm", name, meta["version"], _rel(lock, root)))
    return pins


def action_pins(root: Path) -> list[Pin]:
    files = sorted((root / ".github" / "workflows").glob("*.y*ml"))
    files += [p for p in (root / "action.yml", root / "action.yaml") if p.exists()]
    files += sorted((root / ".github" / "actions").glob("*/action.y*ml"))
    pins, seen = [], set()
    for wf in files:
        for line in wf.read_text(encoding="utf-8").splitlines():
            m = _USES.search(line)
            if not m:
                continue
            key = (m["repo"].lower(), m["version"])
            if key not in seen:
                seen.add(key)
                pins.append(Pin("GitHub Actions", m["repo"], m["version"], _rel(wf, root)))
    return pins


def ladder_binary_pins(root: Path) -> list[Pin]:
    script = root / "scripts" / "install-ladder.sh"
    if not script.exists():
        return []
    text = script.read_text(encoding="utf-8")
    pins = []
    for var, module in LADDER_BINARIES.items():
        m = re.search(rf"^{var}=([0-9][\w.]*)\s*$", text, re.MULTILINE)
        if not m:
            continue
        version = m.group(1)
        major = int(version.split(".", 1)[0])
        path = f"{module}/v{major}" if major >= 2 else module
        pins.append(Pin("Go", path, version, _rel(script, root)))
    return pins


def pyproject_floor_pins(root: Path) -> list[Pin]:
    """The lowest version each declared range admits.

    A range is a promise that every version inside it is acceptable. When the
    floor has a published advisory the promise is false even if today's
    resolver happens to pick something newer — a pinned lockfile, an offline
    mirror or a constraints file elsewhere will take the floor at its word.
    """
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return []
    project = tomllib.loads(pyproject.read_text(encoding="utf-8")).get("project", {})
    requirements = list(project.get("dependencies", []))
    for extra in (project.get("optional-dependencies") or {}).values():
        requirements.extend(extra)
    pins = []
    for requirement in requirements:
        m = _FLOOR.match(requirement)
        if not m:
            continue
        for clause in m["spec"].split(","):
            clause = clause.strip()
            if clause.startswith((">=", "==")):
                version = clause[2:].strip()
                if version and "*" not in version:
                    pins.append(Pin("PyPI", m["name"], version, "pyproject.toml"))
                break
    return pins


# `npx -y name@1.2.3` in a setup script: the one npm package run outside a
# lockfile. A bare `npx -y name` runs whatever is newest at that moment.
_NPX = re.compile(r"\bnpx\s+(?:-y|--yes)\s+(?P<spec>[^\s;&|]+)")
_NPX_PINNED = re.compile(r"^(?P<name>(?:@[\w.-]+/)?[\w.-]+)@(?P<version>\d+\.\d+\.\d+[\w.+-]*)$")
SETUP_SCRIPTS = (".cursor/install.sh", ".devcontainer/*.sh", "scripts/*.sh")


def npx_specs(root: Path) -> list[tuple[str, str]]:
    """Every ``npx -y`` package spec in a setup script, with its file."""
    found = []
    for pattern in SETUP_SCRIPTS:
        for script in sorted(root.glob(pattern)):
            for line in script.read_text(encoding="utf-8").splitlines():
                if line.lstrip().startswith("#"):
                    continue
                found.extend((m["spec"], _rel(script, root)) for m in _NPX.finditer(line))
    return found


def npx_pins(root: Path) -> list[Pin]:
    pins = []
    for spec, source in npx_specs(root):
        if m := _NPX_PINNED.match(spec):
            pins.append(Pin("npm", m["name"], m["version"], source))
    return pins


def all_pins(root: Path) -> list[Pin]:
    return (
        closure_pins(root)
        + npm_lock_pins(root)
        + npx_pins(root)
        + action_pins(root)
        + ladder_binary_pins(root)
        + pyproject_floor_pins(root)
    )


# --- talking to OSV and PyPI ----------------------------------------------------


def _http_json(url: str, payload: dict | None = None) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "tridelphi-deps"},
    )
    # Only the fixed https:// endpoints above ever reach this call.
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return json.load(response)


def osv_query_batch(pins: list[Pin]) -> list[list[str]]:
    """Advisory ids per pin, in order."""
    ids: list[list[str]] = []
    for start in range(0, len(pins), 500):
        chunk = pins[start : start + 500]
        body = {
            "queries": [
                {"package": {"ecosystem": p.ecosystem, "name": p.name}, "version": p.version}
                for p in chunk
            ]
        }
        results = _http_json(OSV_BATCH, body).get("results", [])
        if len(results) != len(chunk):
            raise RuntimeError("OSV returned a different number of results than queries")
        for result in results:
            ids.append([v["id"] for v in (result.get("vulns") or [])])
    return ids


def osv_vuln(vuln_id: str) -> dict:
    return _http_json(OSV_VULN + urllib.parse.quote(vuln_id, safe=""))


def advisories(
    pins: list[Pin],
    *,
    query_batch: Callable[[list[Pin]], list[list[str]]] = osv_query_batch,
    fetch: Callable[[str], dict] = osv_vuln,
) -> list[Advisory]:
    """One Advisory per distinct flaw per pin, aliases merged."""
    found: list[Advisory] = []
    cache: dict[str, dict] = {}
    for pin, ids in zip(pins, query_batch(pins), strict=True):
        if not ids:
            continue
        for vid in ids:
            cache.setdefault(vid, fetch(vid))
        groups: list[set[str]] = []
        for vid in ids:
            linked = {vid, *cache[vid].get("aliases", []), *cache[vid].get("upstream", [])}
            merged = [g for g in groups if g & linked]
            for g in merged:
                groups.remove(g)
                linked |= g
            groups.append(linked)
        for group in groups:
            members = [cache[v] for v in ids if v in group]
            found.append(_advisory(pin, group, members))
    return found


def _advisory(pin: Pin, group: set[str], records: list[dict]) -> Advisory:
    severity, fixed, summary = "", set(), ""
    for record in records:
        severity = severity or str(record.get("database_specific", {}).get("severity", ""))
        summary = summary or str(record.get("summary", ""))
        for affected in record.get("affected", []):
            if affected.get("package", {}).get("name", "").lower() != pin.name.lower():
                continue
            for rng in affected.get("ranges", []):
                fixed.update(e["fixed"] for e in rng.get("events", []) if "fixed" in e)
    return Advisory(pin, tuple(sorted(group)), severity or "unrated", tuple(sorted(fixed)), summary)


def pypi_release(name: str, version: str) -> dict:
    url = PYPI_RELEASE.format(name=urllib.parse.quote(name), version=urllib.parse.quote(version))
    return _http_json(url)


def pypi_project(name: str) -> dict:
    return _http_json(PYPI_PROJECT.format(name=urllib.parse.quote(name)))


# --- check ---------------------------------------------------------------------


def format_advisories(found: Iterable[Advisory]) -> list[str]:
    lines = []
    for adv in sorted(found, key=lambda a: (a.pin.source, a.pin.name.lower(), a.ids)):
        fixed = f"fixed in {', '.join(adv.fixed)}" if adv.fixed else "no fixed version yet"
        lines.append(
            f"{adv.pin.source}: {adv.pin.name} {adv.pin.version} — {adv.severity} — "
            f"{' / '.join(adv.ids)} — {fixed}"
        )
        if adv.summary:
            lines.append(f"    {adv.summary}")
    return lines


def cmd_check(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    pins = all_pins(root)
    if not pins:
        print("No pinned dependencies found — refusing to report a clean result.")
        return 2
    try:
        found = advisories(pins)
    except (urllib.error.URLError, TimeoutError, RuntimeError, ValueError) as exc:
        print(f"Could not reach OSV, so nothing was checked: {exc}")
        return 2
    sources = sorted({p.source for p in pins})
    print(f"Checked {len(pins)} pinned versions across {len(sources)} files against OSV.")
    if not found:
        print("No known advisories.")
        return 0
    flaws = {(a.pin.name.lower(), a.ids) for a in found}
    print(f"{len(flaws)} known advisor{'y' if len(flaws) == 1 else 'ies'} — upgrade these:")
    for line in format_advisories(found):
        print(f"  {line}")
    return 1


# --- pin-closure -----------------------------------------------------------------


@dataclass(frozen=True)
class Release:
    name: str
    version: str
    hashes: tuple[str, ...]
    uploaded: datetime


def _venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _pip(python: Path, *args: str) -> None:
    subprocess.run(
        [str(python), "-m", "pip", *args, "--disable-pip-version-check", "--no-input",
         "--quiet", "--no-cache-dir"],
        check=True,
    )


def resolve(
    requirements: list[str], python: Path, workdir: Path, excluded: dict[str, set[str]]
) -> list[tuple[str, str]]:
    """Exact (name, version) set pip would install, without running package code.

    ``--dry-run --only-binary`` reads wheel metadata and installs nothing, so no
    setup.py or build backend from the closure executes on the machine doing
    the pinning. ``excluded`` versions become ``!=`` constraints.
    """
    constraints = workdir / "constraints.txt"
    constraints.write_text(
        "".join(
            f"{name}{','.join(f'!={v}' for v in sorted(versions))}\n"
            for name, versions in sorted(excluded.items())
        ),
        encoding="utf-8",
    )
    report = workdir / "report.json"
    _pip(python, "install", "--dry-run", "--ignore-installed", "--only-binary=:all:",
         "--report", str(report), "-c", str(constraints), *requirements)
    return parse_report(json.loads(report.read_text(encoding="utf-8")))


def parse_report(report: dict) -> list[tuple[str, str]]:
    pairs = {(i["metadata"]["name"], i["metadata"]["version"]) for i in report.get("install", [])}
    return sorted(pairs, key=lambda p: f"{p[0]}=={p[1]}".lower())


def _uploaded(files: list[dict]) -> datetime | None:
    stamps = [
        datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00"))
        for f in files
        if f.get("upload_time_iso_8601")
    ]
    return min(stamps) if stamps else None


def release_from_pypi(name: str, version: str, meta: dict) -> Release:
    files = meta.get("urls") or []
    if not files:
        raise ValueError(f"PyPI lists no artifacts for {name}=={version}")
    if any(f.get("yanked") for f in files):
        raise ValueError(f"{name}=={version} has a yanked artifact on PyPI")
    uploaded = _uploaded(files)
    if uploaded is None:
        raise ValueError(f"PyPI gives no upload time for {name}=={version}")
    return Release(name, version, tuple(f["digests"]["sha256"] for f in files), uploaded)


def versions_uploaded_after(project: dict, cutoff: datetime) -> set[str]:
    """Every release of a project whose first artifact is newer than ``cutoff``."""
    fresh = set()
    for version, files in (project.get("releases") or {}).items():
        uploaded = _uploaded(files or [])
        if uploaded is not None and uploaded > cutoff:
            fresh.add(version)
    return fresh


def render_closure(releases: list[Release], requirements: list[str], output: str) -> str:
    wanted = " ".join(requirements)
    lines = [
        f"# {wanted} and its full dependency closure, pinned by version AND artifact",
        "# digest for `pip install --require-hashes`. Every sha256 is the digest PyPI",
        "# publishes for that release's artifacts, so the pin holds on any platform pip",
        "# resolves to. Generated — never edit one line; a closure only moves whole:",
        "#",
        f"#     python3 scripts/deps.py pin-closure {wanted} -o {output}",
        "",
    ]
    for release in releases:
        lines.append(f"{release.name}=={release.version} \\")
        for i, digest in enumerate(release.hashes):
            tail = " \\" if i < len(release.hashes) - 1 else ""
            lines.append(f"    --hash=sha256:{digest}{tail}")
    return "\n".join(lines) + "\n"


def verify_install(path: Path, python: str, workdir: Path, smoke: str | None) -> None:
    """Install the written closure exactly as install-ladder.sh will."""
    venv = workdir / f"verify-{len(list(workdir.glob('verify-*')))}"
    subprocess.run([python, "-m", "venv", str(venv)], check=True)
    vpy = _venv_python(venv)
    _pip(vpy, "install", "--only-binary=:all:", "--require-hashes", "-r", str(path))
    _pip(vpy, "check")
    if smoke:
        env = {**os.environ, "PATH": str(vpy.parent) + os.pathsep + os.environ.get("PATH", "")}
        # The operator typed this command on their own command line.
        subprocess.run(smoke, shell=True, check=True, env=env)


def settle(
    requirements: list[str],
    python: Path,
    workdir: Path,
    *,
    min_age_days: int,
    now: datetime,
    release: Callable[[str, str], Release],
    project: Callable[[str], dict],
    resolver: Callable[..., list[tuple[str, str]]] = resolve,
    attempts: int = 10,
) -> tuple[list[Release], dict[str, set[str]]]:
    """Resolve as of ``min_age_days`` ago.

    A new upload is when a hijacked maintainer account does its damage, and
    such releases are usually pulled within days. pip has no "exclude newer"
    switch, so every release younger than the cutoff is excluded by name and
    the closure is resolved again, until what remains is old enough.
    """
    cutoff = now - timedelta(days=min_age_days)
    excluded: dict[str, set[str]] = {}
    for _ in range(attempts):
        releases = [release(n, v) for n, v in resolver(requirements, python, workdir, excluded)]
        fresh = [r for r in releases if r.uploaded > cutoff]
        if not fresh:
            return releases, excluded
        for r in fresh:
            excluded.setdefault(r.name, set()).update(versions_uploaded_after(project(r.name), cutoff))
    raise RuntimeError("the closure did not settle on releases older than the cutoff")


def cmd_pin_closure(args: argparse.Namespace) -> int:
    output = Path(args.output).resolve()
    rel_output = output.relative_to(ROOT).as_posix() if output.is_relative_to(ROOT) else str(output)
    with tempfile.TemporaryDirectory(prefix="tridelphi-closure-") as tmp:
        work = Path(tmp)
        venv = work / "resolve"
        subprocess.run([args.python, "-m", "venv", str(venv)], check=True)
        try:
            releases, excluded = settle(
                args.requirements, _venv_python(venv), work,
                min_age_days=0 if args.allow_fresh else args.min_age_days,
                now=datetime.now(UTC),
                release=functools.cache(lambda n, v: release_from_pypi(n, v, pypi_release(n, v))),
                project=functools.cache(pypi_project),
            )
        except (RuntimeError, subprocess.CalledProcessError) as exc:
            print(f"Could not resolve a closure older than {args.min_age_days} days: {exc}")
            print("A requested version may itself be too new; pass --allow-fresh to accept it.")
            return 1
        for name, versions in sorted(excluded.items()):
            print(f"Skipped releases younger than {args.min_age_days} days: "
                  f"{name} {', '.join(sorted(versions))}")
        found = advisories([Pin("PyPI", r.name, r.version, rel_output) for r in releases])
        if found and not args.allow_vulnerable:
            print("Refusing to write the closure; these releases have known advisories:")
            for line in format_advisories(found):
                print(f"  {line}")
            return 1
        candidate = work / "closure.txt"
        candidate.write_text(render_closure(releases, args.requirements, rel_output), encoding="utf-8")
        for python in args.verify_python or [args.python]:
            verify_install(candidate, python, work, args.smoke)
        output.write_text(candidate.read_text(encoding="utf-8"), encoding="utf-8")
    print(f"Wrote {len(releases)} pinned releases to {rel_output} and verified the install.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="fail when a pinned dependency has a known advisory")
    check.add_argument("--root", default=str(ROOT))
    check.set_defaults(func=cmd_check)

    pin = sub.add_parser("pin-closure", help="regenerate a hash-pinned closure wholesale")
    pin.add_argument("requirements", nargs="+", help="top-level requirement(s), e.g. semgrep==1.177.0")
    pin.add_argument("-o", "--output", required=True, help="closure file to write")
    pin.add_argument("--python", default=sys.executable, help="interpreter to resolve for")
    pin.add_argument(
        "--verify-python", action="append",
        help="also prove the install on this interpreter (repeatable)",
    )
    pin.add_argument("--min-age-days", type=int, default=7)
    pin.add_argument("--allow-fresh", action="store_true", help="accept releases younger than the minimum age")
    pin.add_argument("--allow-vulnerable", action="store_true", help="accept releases with known advisories")
    pin.add_argument("--smoke", help="command to run inside the verified environment, e.g. 'semgrep --version'")
    pin.set_defaults(func=cmd_pin_closure)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
