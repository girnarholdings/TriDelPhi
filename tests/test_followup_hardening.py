"""Acceptance tests for the post-briefing security layers."""

from __future__ import annotations

import io
import json
import textwrap
from pathlib import Path

import pytest

import tridelphi.parse as parse_module
from tridelphi.api import analyze
from tridelphi.baseline import annotate_external_baseline, external_fingerprint, write_baseline
from tridelphi.expose import ExposureLimits, analyze_exposure
from tridelphi.expose_cmd import run_expose
from tridelphi.fsutil import atomic_copy_file, atomic_write_text
from tridelphi.parse import parse_repo


def _repo(tmp_path: Path, workflow: str, extra: dict[str, str] | None = None) -> Path:
    root = tmp_path / "repo"
    target = root / ".github" / "workflows" / "ci.yml"
    target.parent.mkdir(parents=True)
    target.write_text(textwrap.dedent(workflow).lstrip(), encoding="utf-8")
    for rel, body in (extra or {}).items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


def _rule_ids(root: Path) -> list[str]:
    return [finding.rule_id for finding in analyze(root).findings]


def test_exact_job_cap_does_not_silently_skip_later_workflows(tmp_path, monkeypatch):
    root = _repo(tmp_path, "on: push\njobs:\n  one:\n    runs-on: ubuntu-latest\n")
    (root / ".github/workflows/second.yml").write_text(
        "on: push\njobs:\n  two:\n    runs-on: ubuntu-latest\n", encoding="utf-8"
    )
    monkeypatch.setattr(parse_module, "_MAX_CONTEXTS", 1)
    result = analyze(root)
    assert any("remaining workflows not scanned" in diagnostic.message for diagnostic in result.diagnostics)


def test_tar_entry_limit_is_checked_before_reading_all_headers(tmp_path, monkeypatch):
    import tarfile

    import tridelphi.preflight as preflight

    archive = tmp_path / "many.tar"
    with tarfile.open(archive, "w") as writer:
        for index in range(3):
            writer.addfile(tarfile.TarInfo(f"file-{index}"), io.BytesIO())
    monkeypatch.setattr(preflight, "_MAX_EXTRACT_ENTRIES", 1)
    monkeypatch.setattr(tarfile.TarFile, "getmembers", lambda _self: pytest.fail("unbounded headers"))
    with pytest.raises(ValueError, match="entries"):
        preflight.extract_archive(archive, tmp_path / "extracted")


def test_unrelated_step_output_is_not_overtainted(tmp_path):
    root = _repo(
        tmp_path,
        """
        on: issues
        jobs:
          producer:
            permissions: {contents: read}
            runs-on: ubuntu-latest
            outputs:
              safe: ${{ steps.safe.outputs.value }}
            steps:
              - id: attacker
                run: echo "value=${{ github.event.issue.title }}" >> "$GITHUB_OUTPUT"
              - id: safe
                run: echo "value=release" >> "$GITHUB_OUTPUT"
          publish:
            needs: producer
            permissions: {contents: write}
            runs-on: ubuntu-latest
            steps:
              - run: curl -d "${{ needs.producer.outputs.safe }}" https://example.com
        """,
    )
    assert "tridelphi/cross-job-untrusted-flow" not in _rule_ids(root)


def test_bracket_notation_cross_job_output_is_tainted(tmp_path):
    root = _repo(
        tmp_path,
        """
        on: issues
        jobs:
          producer:
            permissions: {contents: read}
            runs-on: ubuntu-latest
            outputs:
              title: ${{ steps.bad.outputs.value }}
            steps:
              - id: bad
                run: echo "value=${{ github.event.issue.title }}" >> "$GITHUB_OUTPUT"
          publish:
            needs: producer
            permissions: {contents: write}
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ needs['producer']['outputs']['title'] }}" | curl -d @- https://example.com
        """,
    )
    assert "tridelphi/cross-job-untrusted-flow" in _rule_ids(root)


def test_differently_named_artifact_is_not_joined(tmp_path):
    root = _repo(
        tmp_path,
        """
        on: pull_request_target
        jobs:
          build:
            permissions: {contents: read}
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@0123456789012345678901234567890123456789
                with:
                  ref: refs/pull/${{ github.event.pull_request.number }}/head
              - uses: actions/upload-artifact@0123456789012345678901234567890123456789
                with:
                  name: untrusted-build
                  path: dist
          publish:
            needs: build
            permissions: {contents: write}
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@0123456789012345678901234567890123456789
                with:
                  name: reviewed-release
              - run: ./publish.sh
        """,
    )
    assert "tridelphi/cross-job-untrusted-flow" not in _rule_ids(root)


def test_only_artifact_written_from_untrusted_data_is_tainted(tmp_path):
    root = _repo(
        tmp_path,
        """
        on: issues
        jobs:
          build:
            permissions: {contents: read}
            runs-on: ubuntu-latest
            steps:
              - run: |
                  mkdir -p tainted safe
                  echo "${{ github.event.issue.title }}" > tainted/payload.sh
                  echo "reviewed" > safe/report.txt
              - uses: actions/upload-artifact@0123456789012345678901234567890123456789
                with: {name: attacker-data, path: tainted}
              - uses: actions/upload-artifact@0123456789012345678901234567890123456789
                with: {name: reviewed-data, path: safe}
          publish_bad:
            needs: build
            permissions: {contents: write}
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@0123456789012345678901234567890123456789
                with: {name: attacker-data}
              - run: sh payload.sh
          publish_good:
            needs: build
            permissions: {contents: write}
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@0123456789012345678901234567890123456789
                with: {name: reviewed-data}
              - run: cat report.txt
        """,
    )
    cross = [
        finding
        for finding in analyze(root).findings
        if finding.rule_id == "tridelphi/cross-job-untrusted-flow"
    ]
    assert [finding.context.job_id for finding in cross] == ["publish_bad"]


def test_output_name_prefix_does_not_create_a_false_cross_job_edge(tmp_path):
    root = _repo(
        tmp_path,
        """
        on: issues
        jobs:
          producer:
            permissions: {contents: read}
            runs-on: ubuntu-latest
            outputs:
              title: ${{ steps.bad.outputs.value }}
            steps:
              - id: bad
                run: echo "value=${{ github.event.issue.title }}" >> "$GITHUB_OUTPUT"
          publish:
            needs: producer
            permissions: {contents: write}
            runs-on: ubuntu-latest
            steps:
              - run: curl -d "${{ needs.producer.outputs.title_suffix }}" https://example.com
        """,
    )
    assert "tridelphi/cross-job-untrusted-flow" not in _rule_ids(root)


def test_unknown_agent_action_is_visible_not_passed(tmp_path):
    root = _repo(
        tmp_path,
        """
        on: pull_request
        permissions: {contents: read}
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - uses: acme/next-ai-agent@0123456789012345678901234567890123456789
        """,
    )
    finding = next(
        finding
        for finding in analyze(root).findings
        if finding.rule_id == "tridelphi/agent-semantics-unknown"
    )
    assert finding.severity == "warning"
    assert "unknown, not a pass" in finding.message


def test_jsonc_mcp_config_is_inventory_not_a_silent_miss(tmp_path, tables):
    root = _repo(
        tmp_path,
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps: []\n",
        {
            ".vscode/mcp.json": """
            {
              // JSONC is what VS Code writes.
              "servers": {
                "deployer": {"url": "https://mcp.example.test",},
              },
            }
            """,
        },
    )
    inventory = parse_repo(root, tables).inventory
    assert [server.name for server in inventory.mcp_servers] == ["deployer"]
    assert inventory.unknown_config_paths == ()


def test_non_object_or_malformed_mcp_config_fails_safe(tmp_path, tables):
    for index, body in enumerate(('["not", "an", "object"]', '{"servers": {"deploy": []}}')):
        root = _repo(
            tmp_path / str(index),
            "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps: []\n",
            {".mcp.json": body},
        )
        inventory = parse_repo(root, tables).inventory
        assert inventory.unknown_config_paths == (".mcp.json",)


def test_agent_inventory_limit_is_visible_not_a_silent_partial_scan(
    tmp_path, tables, monkeypatch
):
    root = _repo(
        tmp_path,
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps: []\n",
        {
            ".cursor/rules/a.md": "one",
            ".cursor/rules/b.md": "two",
            ".cursor/rules/c.md": "three",
        },
    )
    monkeypatch.setattr(parse_module, "_MAX_INVENTORY_ENTRIES", 2)
    outcome = parse_repo(root, tables)
    assert any("configuration discovery exceeded" in item.message for item in outcome.diagnostics)


def test_workflow_directory_entry_limit_is_visible(tmp_path, tables, monkeypatch):
    root = _repo(
        tmp_path,
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps: []\n",
        {
            ".github/workflows/not-a-workflow-1.txt": "one",
            ".github/workflows/not-a-workflow-2.txt": "two",
        },
    )
    monkeypatch.setattr(parse_module, "_MAX_WORKFLOW_ENTRIES", 2)
    outcome = parse_repo(root, tables)
    assert any("workflow discovery exceeded" in item.message for item in outcome.diagnostics)


def test_worker_has_no_deployable_default_webhook_secret(repo_root):
    config = (repo_root / "bot" / "wrangler.toml").read_text(encoding="utf-8")
    ignore = (repo_root / ".gitignore").read_text(encoding="utf-8")
    assert "GITHUB_WEBHOOK_SECRET =" not in config
    assert "bot/.dev.vars" in ignore
    assert (repo_root / "bot" / ".dev.vars.example").is_file()


def test_repeated_yaml_aliases_are_budgeted_before_detector_walks(
    tmp_path, tables, monkeypatch
):
    from tridelphi.structure import structure_error

    root = _repo(
        tmp_path,
        """
        on: push
        shared: &shared [one, two]
        repeated: [*shared, *shared, *shared]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps: []
        """,
    )
    monkeypatch.setattr(
        parse_module,
        "structure_error",
        lambda document: structure_error(document, max_nodes=8),
    )
    outcome = parse_repo(root, tables)
    assert outcome.contexts == ()
    assert any("structure exceeds" in item.message for item in outcome.diagnostics)


def test_workflow_job_limit_is_fail_visible(tmp_path, tables, monkeypatch):
    root = _repo(
        tmp_path,
        """
        on: push
        jobs:
          one: {runs-on: ubuntu-latest, steps: []}
          two: {runs-on: ubuntu-latest, steps: []}
        """,
    )
    monkeypatch.setattr(parse_module, "_MAX_JOBS_PER_WORKFLOW", 1)
    outcome = parse_repo(root, tables)
    assert outcome.contexts == ()
    assert any("more than 1 jobs" in item.message for item in outcome.diagnostics)


def test_mcp_parent_directory_symlink_is_unknown_not_followed(tmp_path, tables):
    root = _repo(
        tmp_path,
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps: []\n",
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "mcp.json").write_text(
        '{"servers":{"deployer":{"url":"https://outside.invalid"}}}',
        encoding="utf-8",
    )
    (root / ".vscode").symlink_to(outside, target_is_directory=True)
    inventory = parse_repo(root, tables).inventory
    assert inventory.mcp_servers == ()
    assert inventory.unknown_config_paths == (".vscode/mcp.json",)


def test_atomic_output_refuses_a_symlinked_ancestor(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "reports").symlink_to(outside, target_is_directory=True)

    with pytest.raises(OSError, match="symlinked directory"):
        atomic_write_text(root / "reports" / "nested" / "out.sarif", "{}", create_parent=True)

    assert not (outside / "nested" / "out.sarif").exists()


def test_atomic_artifact_copy_refuses_symlinks_and_size_overflow(tmp_path):
    source = tmp_path / "source.sarif"
    source.write_text('{"runs":[]}', encoding="utf-8")
    outside = tmp_path / "outside.sarif"
    outside.write_text("keep", encoding="utf-8")
    destination = tmp_path / "report.sarif"
    destination.symlink_to(outside)

    with pytest.raises(OSError, match="replace symlink"):
        atomic_copy_file(source, destination)
    assert outside.read_text(encoding="utf-8") == "keep"

    destination.unlink()
    with pytest.raises(OSError, match="artifact copy limit"):
        atomic_copy_file(source, destination, max_bytes=3)
    assert not destination.exists()

    atomic_copy_file(source, destination)
    assert destination.read_bytes() == source.read_bytes()


def test_malformed_mcp_on_pr_worktree_fails_safe(tmp_path):
    root = _repo(
        tmp_path,
        """
        on: pull_request_target
        permissions: {contents: write}
        jobs:
          agent:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@0123456789012345678901234567890123456789
                with:
                  ref: refs/pull/${{ github.event.pull_request.number }}/head
              - uses: openai/codex-action@0123456789012345678901234567890123456789
        """,
        {".mcp.json": "{/* unterminated"},
    )
    finding = next(
        finding
        for finding in analyze(root).findings
        if finding.rule_id == "tridelphi/agent-config-ingress"
    )
    assert any(hit.kind == "agent-mcp-ingress" for hit in finding.hits)


def test_case_insensitive_asset_directory_is_scanned(tmp_path):
    root = tmp_path / "repo"
    bundle = root / "Dist" / "main.js"
    bundle.parent.mkdir(parents=True)
    bundle.write_text('const key = "AKIAIOSFODNN7EXAMPLE";', encoding="utf-8")
    result = analyze_exposure(root, run_semgrep=False)
    assert any(f.rule == "client-secret" and f.severity == "critical" for f in result.findings)


def test_exposure_cap_is_machine_readable_and_never_prints_green(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.txt").write_text("a", encoding="utf-8")
    (root / "b.txt").write_text("b", encoding="utf-8")
    result = analyze_exposure(root, run_semgrep=False, limits=ExposureLimits(max_files=1))
    assert not result.coverage.complete
    coverage = result.sarif["runs"][0]["properties"]["tridelphiCoverage"]
    assert coverage["complete"] is False
    assert coverage["incompleteReasons"]

    monkeypatch.setattr("tridelphi.expose_cmd.analyze_exposure", lambda *_a, **_kw: result)
    out = io.StringIO()
    assert run_expose(str(root), out=out, err=io.StringIO()) == 2
    report = out.getvalue()
    assert "PARTIAL" in report
    assert "Nothing in your committed code or config looks exposed" not in report


def test_exposure_entry_cap_bounds_directory_bombs(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    for index in range(4):
        (root / f"empty-{index}").mkdir()

    result = analyze_exposure(
        root,
        run_semgrep=False,
        limits=ExposureLimits(max_entries=2),
    )

    assert not result.coverage.complete
    assert result.coverage.entries_seen == 3
    coverage = result.sarif["runs"][0]["properties"]["tridelphiCoverage"]
    assert coverage["entriesSeen"] == 3
    assert any("entry count" in reason for reason in coverage["incompleteReasons"])


def _external_doc(tool: str) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": tool}},
                "results": [
                    {
                        "ruleId": "x/rule",
                        "level": "error",
                        "partialFingerprints": {"tridelphiExternal/v1": "abc123"},
                    }
                ],
            }
        ],
    }


def test_external_baseline_ratchets_findings_but_never_waives_gitleaks(tmp_path):
    semgrep = _external_doc("semgrep")
    fp = external_fingerprint(semgrep["runs"][0]["results"][0])
    gating, seen = annotate_external_baseline([semgrep], {fp})
    assert gating == [] and seen == {fp}
    assert semgrep["runs"][0]["results"][0]["baselineState"] == "unchanged"

    gitleaks = _external_doc("gitleaks")
    gating, _seen = annotate_external_baseline([gitleaks], {fp})
    assert gating == ["critical"]
    assert gitleaks["runs"][0]["results"][0]["baselineState"] == "new"

    baseline = tmp_path / "baseline.json"
    assert write_baseline(baseline, [], "0", [semgrep, semgrep]) == 1
    assert len(json.loads(baseline.read_text())["fingerprints"]) == 1
