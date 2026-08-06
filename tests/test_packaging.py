"""Packaging and repo-hygiene checks.

The data files are the failure mode worth guarding: the vendored SARIF schema
and the YAML tables live inside the package, and `pip install -e .` leaves the
repo on disk so a missing `package-data` entry stays invisible until a real user
installs a wheel. These tests assert the resource-loading path that a wheel
install exercises; CI additionally builds a wheel and installs it clean.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from tridelphi.sarif import load_schema
from tridelphi.tables import load_tables

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "tridelphi" / "data"


def test_schema_loads_as_a_package_resource():
    """Loaded via importlib.resources, not a repo-relative path."""
    schema = load_schema()
    assert schema["$schema"].startswith("http://json-schema.org/draft-04/")


def test_tables_load_as_package_resources():
    tables = load_tables()
    assert tables.section("agent_signals", "agents"), "agent table is empty"
    assert tables.tuple_of("untrusted_expressions", "paths")
    assert tables.tuple_of("triggers", "fork_reachable")
    assert tables.tuple_of("egress", "network_commands")


def test_every_data_file_is_declared_as_package_data():
    """A new data file that no glob matches would not ship in the wheel."""
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    patterns = config["tool"]["setuptools"]["package-data"]["tridelphi"]

    on_disk = sorted(p.name for p in DATA_DIR.iterdir() if p.is_file())
    assert on_disk, "no data files found"

    for name in on_disk:
        suffix = Path(name).suffix
        assert any(pat.endswith(f"*{suffix}") for pat in patterns), (
            f"tridelphi/data/{name} matches no package-data pattern {patterns} — "
            "it would be missing from a wheel install"
        )


def test_console_script_entry_point_is_declared():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert config["project"]["scripts"]["tridelphi"] == "tridelphi.cli:main"


def test_runtime_dependencies_stay_minimal():
    """The dependency allowlist is a security property, not a preference: this
    is an auditable tool and every runtime import is attack surface."""
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    deps = config["project"]["dependencies"]
    names = {d.split(">")[0].split("<")[0].split("=")[0].strip().lower() for d in deps}
    assert names == {"ruamel.yaml"}, f"unexpected runtime dependency: {names}"


def test_no_network_imports_in_the_execution_path():
    """`tridelphi .` must not be able to phone home.

    orchestrate.py is exempt: it shells out to zizmor, but only behind an
    explicit --with-zizmor flag, and it makes no network calls of its own.
    """
    banned = ("import requests", "import urllib.request", "import http.client", "import socket")
    offenders = []
    for source in (ROOT / "tridelphi").glob("*.py"):
        text = source.read_text()
        for needle in banned:
            if needle in text:
                offenders.append(f"{source.name}: {needle}")
    assert not offenders, f"network imports in the execution path: {offenders}"


@pytest.mark.parametrize("workflow", ["ci.yml", "pages.yml"])
def test_our_own_workflows_parse(workflow):
    """We ship a workflow analyser; our own workflows must be analysable."""
    from tridelphi.api import analyze

    path = ROOT / ".github" / "workflows" / workflow
    assert path.is_file(), f"{workflow} is missing"
    result = analyze(ROOT)
    assert not result.diagnostics, (
        "our own workflows produced parse diagnostics: "
        + "; ".join(f"{d.path}: {d.message}" for d in result.diagnostics)
    )


def test_ci_ok_gates_every_job():
    """The aggregating check must depend on every other job in ci.yml.

    `ci-ok` is the single required status check in branch protection. If someone
    adds a job and forgets to wire it into `needs:`, the branch still merges on a
    green `ci-ok` while the new job's failure goes unnoticed — silently widening
    what can merge, which is the exact failure this repo already lived through.
    """
    from ruamel.yaml import YAML

    workflow = YAML().load((ROOT / ".github/workflows/ci.yml").read_text())
    jobs = set(workflow["jobs"]) - {"ci-ok"}
    needs = set(workflow["jobs"]["ci-ok"]["needs"])
    assert jobs == needs, (
        f"ci-ok does not gate every job. Not in needs: {sorted(jobs - needs)}; "
        f"stale entries: {sorted(needs - jobs)}"
    )


def test_site_is_self_contained():
    """The landing page must render with no network access.

    A CDN font or remote script silently degrades to a blank or unstyled page
    for anyone behind a proxy — and it is exactly what the Pages deploy check
    enforces, so it is asserted here too where it fails fast.
    """
    import re

    page = (ROOT / "site" / "index.html").read_text()
    external = re.findall(r'(?:src|href)\s*=\s*["\'](https?://[^"\']+)', page)
    # Prose links out to the project and to reference material; asset
    # references are what must stay local.
    assets = [u for u in external if re.search(r"\.(css|js|woff2?|ttf|png|jpg|svg)$", u)]
    assert not assets, f"site/index.html loads external assets: {assets}"
    assert "<title>" in page
