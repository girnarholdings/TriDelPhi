"""The SARIF output contract survives ladder merging.

TriDelPhi core owns the schema contract (see ``test_sarif_schema.py``); this
module proves that contract still holds once ``tridelphi/ladder.py`` and
``tridelphi/orchestrate.py::merge_runs`` splice in external tools' own SARIF as
additional runs. Two failure modes matter here and nowhere else:

* a URI/level rewrite the ladder applies to an external run (escalating
  gitleaks to "error", relativizing paths) could itself produce a schema
  violation;
* merging could disturb the determinism or the run ordering of TriDelPhi's own
  (primary) run, which is the one a future gate diffs.

Live tests (real gitleaks/osv-scanner/zizmor) are skipped when the binaries
are absent. Stub-based tests (see ``test_ladder.py::make_stub``) exercise the
same merge/serialize path everywhere.
"""

from __future__ import annotations

import json
import os
import shutil

import pytest
from conftest import run_cli
from test_ladder import make_stub, stub_sarif

from tridelphi import __version__
from tridelphi.sarif import dumps as sarif_dumps
from tridelphi.sarif import load_schema

MALICIOUS = "tests/fixtures/malicious/comment-and-control"

_HAVE_GITLEAKS = shutil.which("gitleaks") is not None
_HAVE_OSV_SCANNER = shutil.which("osv-scanner") is not None
_HAVE_ZIZMOR = shutil.which("zizmor") is not None
_HAVE_ALL_TOOLS = _HAVE_GITLEAKS and _HAVE_OSV_SCANNER and _HAVE_ZIZMOR


def _validator():
    """Reuse the validation helper pattern from ``test_sarif_schema.py``:
    draft-04, asserted rather than assumed."""
    from jsonschema.validators import validator_for

    schema = load_schema()
    validator_cls = validator_for(schema)
    validator_cls.check_schema(schema)
    return validator_cls(schema)


def _assert_schema_valid(document: dict) -> None:
    validator = _validator()
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.path))
    if errors:
        detail = "\n".join(f"{list(e.path)}: {e.message}" for e in errors[:10])
        pytest.fail(f"{len(errors)} schema violation(s) in merged SARIF:\n{detail}")


def _make_stdout_stub(bin_dir, name: str, sarif: dict) -> None:
    """Install a fake scanner that writes SARIF to stdout, the convention
    zizmor uses (unlike gitleaks/osv-scanner, which write to a report file).
    """
    import stat
    import textwrap

    payload = json.dumps(sarif)
    script = textwrap.dedent(
        f"""\
        #!/usr/bin/env python3
        import sys
        sys.stdout.write({payload!r})
        sys.exit(0)
        """
    )
    path = bin_dir / name
    path.write_text(script)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


# --- fixtures ------------------------------------------------------------


@pytest.fixture
def all_tools_repo(tmp_path):
    """A repo real gitleaks, osv-scanner and zizmor each find something in:
    the malicious fixture (unpinned action + template injection, for zizmor,
    plus TriDelPhi's own U+P+E critical), an inert planted token shaped like a
    GitHub PAT (for gitleaks), and a lockfile pinning a known-vulnerable
    lodash (for osv-scanner, which needs the network)."""
    repo = tmp_path / "repo"
    shutil.copytree("tests/fixtures/malicious/comment-and-control", repo)
    (repo / "leaky.py").write_text(
        'token = "ghp_x7Qm9Kp2Rt4Vw8Yz3Bn6Df1Hj5Lk0Sg2Xc4V"\n'
    )
    (repo / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "all-tools-repo",
                "version": "1.0.0",
                "lockfileVersion": 2,
                "requires": True,
                "packages": {
                    "": {"name": "all-tools-repo", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}},
                    "node_modules/lodash": {"version": "4.17.20"},
                },
                "dependencies": {"lodash": {"version": "4.17.20"}},
            }
        )
    )
    return repo


@pytest.fixture
def stub_env(tmp_path, monkeypatch):
    """A bin dir prepended to PATH, with gitleaks/osv-scanner/zizmor stubs
    installable individually. Mirrors ``test_ladder.py::stub_path``."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return bin_dir


# --- 1. schema validity of the real merged document -----------------------


@pytest.mark.skipif(
    not _HAVE_ALL_TOOLS,
    reason="needs real gitleaks, osv-scanner and zizmor on PATH",
)
def test_merged_document_with_real_findings_validates(all_tools_repo, repo_root):
    """``--level 3`` against a repo every wrapped tool has something to say
    about: the merged document — all four runs — must validate against the
    vendored OASIS schema. A violation here is either our URI/level rewrite
    (a bug in ladder.py to fix) or a genuinely non-conformant upstream tool
    (documented, not silently patched)."""
    result = run_cli(
        [str(all_tools_repo), "--level", "3", "--format", "sarif"],
        cwd=repo_root,
    )
    document = json.loads(result.stdout)

    names = [r["tool"]["driver"]["name"] for r in document["runs"]]
    assert names == ["tridelphi", "gitleaks", "osv-scanner", "zizmor"], names

    counts = {r["tool"]["driver"]["name"]: len(r.get("results", [])) for r in document["runs"]}
    # Every rung must have actually found something, or the test proves
    # nothing about a populated merged document.
    assert counts["tridelphi"] >= 1, "expected TriDelPhi's own critical finding"
    assert counts["gitleaks"] >= 1, "expected gitleaks to flag the planted token"
    assert counts["osv-scanner"] >= 1, "expected osv-scanner to flag lodash 4.17.20"
    assert counts["zizmor"] >= 1, "expected zizmor to flag the unpinned action / template injection"

    assert document["version"] == "2.1.0"
    assert "$schema" in document

    _assert_schema_valid(document)


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="needs real gitleaks on PATH")
def test_gitleaks_own_sarif_validates_standalone(all_tools_repo):
    """Document gitleaks's own output (as the ladder normalizes it) is itself
    schema-conformant — i.e. any violation found in the merged document above
    would be attributable to our merge/rewrite, not to gitleaks."""
    from tridelphi.ladder import GITLEAKS, run_tool

    res = run_tool(GITLEAKS, all_tools_repo)
    assert res.ok
    _assert_schema_valid(res.sarif)


@pytest.mark.skipif(shutil.which("osv-scanner") is None, reason="needs real osv-scanner on PATH")
def test_osv_scanner_own_sarif_validates_standalone(all_tools_repo):
    from tridelphi.ladder import OSV_SCANNER, run_tool

    res = run_tool(OSV_SCANNER, all_tools_repo)
    assert res.ok
    _assert_schema_valid(res.sarif)


@pytest.mark.skipif(shutil.which("zizmor") is None, reason="needs real zizmor on PATH")
def test_zizmor_own_sarif_validates_standalone(all_tools_repo):
    from tridelphi.ladder import ZIZMOR, run_tool

    res = run_tool(ZIZMOR, all_tools_repo)
    assert res.ok
    _assert_schema_valid(res.sarif)


# --- 2. the primary run survives merging unchanged -------------------------


def test_primary_run_is_first_and_survives_merge_byte_identical(stub_env, repo_root):
    """TriDelPhi's own run must be ``runs[0]`` and byte-identical to what a
    no-ladder scan produces — merging must not perturb the run a future gate
    diffs. Stub-based so it proves the property on every machine, not only
    ones with gitleaks installed."""
    make_stub(stub_env, "gitleaks", stub_sarif("gitleaks", []))

    plain = run_cli([MALICIOUS, "--format", "sarif"], cwd=repo_root)
    ladder = run_cli([MALICIOUS, "--level", "1", "--format", "sarif"], cwd=repo_root)

    assert plain.returncode in (0, 1)
    assert ladder.returncode in (0, 1)

    plain_doc = json.loads(plain.stdout)
    ladder_doc = json.loads(ladder.stdout)

    assert ladder_doc["runs"][0]["tool"]["driver"]["name"] == "tridelphi"
    assert len(ladder_doc["runs"]) == 2  # tridelphi + gitleaks
    assert plain_doc["runs"] == [ladder_doc["runs"][0]]

    # Byte-identical, not just structurally equal: serialize each primary run
    # on its own through the same dumps() the CLI uses.
    plain_primary_bytes = sarif_dumps({"runs": [plain_doc["runs"][0]]})
    ladder_primary_bytes = sarif_dumps({"runs": [ladder_doc["runs"][0]]})
    assert plain_primary_bytes == ladder_primary_bytes


def test_primary_run_survives_merge_at_every_level(stub_env, repo_root):
    """Same property, but across --level 1/2/3 with every rung stubbed, to
    catch a rewrite that only triggers once all three external runs exist."""
    make_stub(stub_env, "gitleaks", stub_sarif("gitleaks", []))
    make_stub(stub_env, "osv-scanner", stub_sarif("osv-scanner", []))
    _make_stdout_stub(stub_env, "zizmor", stub_sarif("zizmor", []))

    plain = run_cli([MALICIOUS, "--format", "sarif"], cwd=repo_root)
    plain_primary = sarif_dumps({"runs": [json.loads(plain.stdout)["runs"][0]]})

    for level in (1, 2, 3):
        ladder = run_cli([MALICIOUS, "--level", str(level), "--format", "sarif"], cwd=repo_root)
        ladder_doc = json.loads(ladder.stdout)
        assert ladder_doc["runs"][0]["tool"]["driver"]["name"] == "tridelphi"
        ladder_primary = sarif_dumps({"runs": [ladder_doc["runs"][0]]})
        assert ladder_primary == plain_primary, f"primary run diverged at --level {level}"


# --- 3. determinism across two consecutive stub runs ------------------------


def test_two_consecutive_stub_runs_are_byte_identical(stub_env, repo_root):
    """A stub gitleaks removes real-world nondeterminism (tool internals,
    timing, ordering) so this isolates *our* serialization: two consecutive
    ``--level 1`` invocations must produce identical bytes on stdout."""
    make_stub(
        stub_env,
        "gitleaks",
        stub_sarif(
            "gitleaks",
            [
                {
                    "ruleId": "generic-api-key",
                    "message": {"text": "possible secret"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "leaky.py"},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                }
            ],
        ),
        exit_code=1,
    )

    first = run_cli([MALICIOUS, "--level", "1", "--format", "sarif"], cwd=repo_root)
    second = run_cli([MALICIOUS, "--level", "1", "--format", "sarif"], cwd=repo_root)

    assert first.returncode == second.returncode == 1
    assert first.stdout == second.stdout
    assert json.loads(first.stdout)  # still valid JSON


def test_two_consecutive_stub_runs_all_tools_are_byte_identical(stub_env, repo_root):
    """Same determinism property with all three rungs stubbed and present, so
    a nondeterministic merge order across three appended runs would be
    caught, not just a two-run case."""
    make_stub(stub_env, "gitleaks", stub_sarif("gitleaks", []))
    make_stub(
        stub_env,
        "osv-scanner",
        stub_sarif(
            "osv-scanner",
            [
                {
                    "ruleId": "CVE-2020-28500",
                    "level": "warning",
                    "message": {"text": "lodash vulnerable"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": "package-lock.json"}}}
                    ],
                }
            ],
        ),
        exit_code=1,
    )
    _make_stdout_stub(
        stub_env,
        "zizmor",
        stub_sarif(
            "zizmor",
            [
                {
                    "ruleId": "unpinned-uses",
                    "level": "error",
                    "message": {"text": "action not pinned to a SHA"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": ".github/workflows/assist.yml"},
                                "region": {"startLine": 13},
                            }
                        }
                    ],
                }
            ],
        ),
    )

    first = run_cli([MALICIOUS, "--level", "3", "--format", "sarif"], cwd=repo_root)
    second = run_cli([MALICIOUS, "--level", "3", "--format", "sarif"], cwd=repo_root)

    assert first.stdout == second.stdout
    document = json.loads(first.stdout)
    names = [r["tool"]["driver"]["name"] for r in document["runs"]]
    assert names == ["tridelphi", "gitleaks", "osv-scanner", "zizmor"]


# --- 4. document-level invariants with every tool present -------------------


def test_merged_document_declares_version_and_schema_with_every_tool(stub_env, repo_root):
    """The merged document must still be a well-formed top-level SARIF
    document — version, $schema — and every run must keep its own
    ``tool.driver.name`` rather than collapsing into TriDelPhi's. Stub-based
    so this holds even where the real tools are not installed."""
    make_stub(stub_env, "gitleaks", stub_sarif("gitleaks", []))
    make_stub(stub_env, "osv-scanner", stub_sarif("osv-scanner", []))
    _make_stdout_stub(stub_env, "zizmor", stub_sarif("zizmor", []))

    result = run_cli([MALICIOUS, "--level", "3", "--format", "sarif"], cwd=repo_root)
    document = json.loads(result.stdout)

    assert document["version"] == "2.1.0"
    assert document["$schema"]

    names = [r["tool"]["driver"]["name"] for r in document["runs"]]
    assert names == ["tridelphi", "gitleaks", "osv-scanner", "zizmor"]
    assert len(names) == len(set(names)), "each run must keep its own driver name"

    _assert_schema_valid(document)


def test_merged_document_with_stub_tools_validates(stub_env, repo_root):
    """A populated (non-empty) merged document with every stub rung present
    must still validate — the stub-based counterpart to test 1 above, so this
    property is checked without needing the real binaries."""
    make_stub(
        stub_env,
        "gitleaks",
        stub_sarif(
            "gitleaks",
            [
                {
                    "ruleId": "github-pat",
                    "message": {"text": "possible secret"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "leaky.py"},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                }
            ],
        ),
        exit_code=1,
    )
    make_stub(
        stub_env,
        "osv-scanner",
        stub_sarif(
            "osv-scanner",
            [
                {
                    "ruleId": "CVE-2020-28500",
                    "level": "warning",
                    "message": {"text": "lodash vulnerable"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": "package-lock.json"}}}
                    ],
                }
            ],
        ),
        exit_code=1,
    )
    _make_stdout_stub(
        stub_env,
        "zizmor",
        stub_sarif(
            "zizmor",
            [
                {
                    "ruleId": "unpinned-uses",
                    "level": "error",
                    "message": {"text": "action not pinned to a SHA"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": ".github/workflows/assist.yml"},
                                "region": {"startLine": 13},
                            }
                        }
                    ],
                }
            ],
        ),
    )

    result = run_cli([MALICIOUS, "--level", "3", "--format", "sarif"], cwd=repo_root)
    document = json.loads(result.stdout)
    _assert_schema_valid(document)
