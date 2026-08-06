"""The HTML report is self-contained, escaped, and reflects the findings."""

from __future__ import annotations

import json

import pytest

from conftest import run_cli
from tridelphi import __version__
from tridelphi.api import analyze
from tridelphi.html_report import render_html


def test_report_is_self_contained_and_valid_shell():
    result = analyze("tests/fixtures/malicious/comment-and-control")
    page = render_html(result, repo_label="demo")
    assert page.startswith("<!doctype html>")
    assert page.rstrip().endswith("</html>")
    # No external assets: nothing to fetch, works offline / as a CI artifact.
    for needle in ("http://", "https://", "src=", "<script"):
        assert needle not in page, f"report should be inert and asset-free, found {needle!r}"


def test_report_shows_the_finding_and_its_fix():
    result = analyze("tests/fixtures/malicious/comment-and-control")
    page = render_html(result, repo_label="demo")
    assert "Critical" in page
    assert "agent-prompt-injection" in page
    assert "Cheapest fix" in page
    assert "author_association" in page  # the specific remediation text


def test_report_escapes_content(tmp_path):
    """Finding text is data, not markup — a crafted job name must not inject HTML."""
    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "w.yml").write_text(
        "on:\n  issues:\n"
        "jobs:\n"
        '  "<script>evil</script>":\n'
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n      contents: write\n"
        "    steps:\n"
        "      - uses: anthropics/claude-code-action@v1\n"
        "        with:\n          prompt: ${{ github.event.issue.body }}\n"
        "        env:\n          K: ${{ secrets.X }}\n",
        encoding="utf-8",
    )
    page = render_html(analyze(tmp_path), repo_label="demo")
    assert "<script>evil</script>" not in page
    assert "&lt;script&gt;" in page


def test_clean_repo_reports_compliant():
    result = analyze("tests/fixtures/clean/vanilla-ci")
    page = render_html(result, repo_label="clean")
    assert "No findings" in page or "compliant" in page.lower()


def test_html_format_via_cli(repo_root):
    result = run_cli(["tests/fixtures/malicious/comment-and-control", "--format", "html"], cwd=repo_root)
    assert result.returncode == 1
    assert result.stdout.startswith("<!doctype html>")


def test_html_file_written_alongside_text(repo_root, tmp_path):
    out = tmp_path / "report.html"
    result = run_cli(
        ["tests/fixtures/malicious/comment-and-control", "--format", "text", "--html-file", str(out)],
        cwd=repo_root,
    )
    assert result.returncode == 1
    assert "CRITICAL" in result.stdout
    assert out.read_text().startswith("<!doctype html>")
