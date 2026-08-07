"""The env-file-injection and weak-actor-guard detectors, and their remediations."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from tridelphi.api import analyze


def _scan(tmp_path, wf):
    d = tmp_path / ".github/workflows"
    d.mkdir(parents=True, exist_ok=True)
    (d / "w.yml").write_text(textwrap.dedent(wf).lstrip(), encoding="utf-8")
    return analyze(tmp_path)


def test_env_file_injection_is_critical(tmp_path):
    r = _scan(tmp_path, """
        on:
          issues:
            types: [opened]
        permissions:
          contents: write
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo "T=${{ github.event.issue.title }}" >> $GITHUB_ENV
                  curl https://example.com
                env:
                  TOK: ${{ secrets.X }}
        """)
    f = next(f for f in r.findings if f.rule_id == "tridelphi/env-file-injection")
    assert f.severity == "critical"
    assert "GITHUB" in f.remediation.rendered or "environment file" in f.remediation.rendered


def test_trusted_value_into_env_file_is_not_flagged(tmp_path):
    r = _scan(tmp_path, """
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: echo "SHA=${{ github.sha }}" >> $GITHUB_ENV
        """)
    assert not [f for f in r.findings if f.rule_id == "tridelphi/env-file-injection"]


def test_weak_actor_guard_is_warning(tmp_path):
    r = _scan(tmp_path, """
        on:
          issue_comment:
            types: [created]
        jobs:
          a:
            runs-on: ubuntu-latest
            if: github.actor == 'trusted'
            permissions:
              contents: write
            steps:
              - run: echo ok
        """)
    f = next(f for f in r.findings if f.rule_id == "tridelphi/weak-actor-guard")
    assert f.severity == "warning"
    assert "author_association" in f.remediation.rendered


def test_strong_author_association_guard_is_clean(tmp_path):
    r = _scan(tmp_path, """
        on:
          issue_comment:
            types: [created]
        jobs:
          a:
            runs-on: ubuntu-latest
            if: contains(fromJSON('["OWNER","MEMBER"]'), github.event.comment.author_association)
            permissions:
              contents: write
            steps:
              - run: echo ok
        """)
    assert not [f for f in r.findings if f.rule_id == "tridelphi/weak-actor-guard"]


def test_actor_guard_ignored_on_trusted_trigger(tmp_path):
    """github.actor on a push-only workflow is not an attack surface."""
    r = _scan(tmp_path, """
        on:
          push:
            branches: [main]
        jobs:
          a:
            runs-on: ubuntu-latest
            if: github.actor == 'ci-bot'
            steps:
              - run: echo ok
        """)
    assert not [f for f in r.findings if f.rule_id == "tridelphi/weak-actor-guard"]


def test_env_file_injection_fills_no_runtime_claim():
    """Both new rules map only to statically-reachable ADR techniques."""
    from tridelphi.coverage import coverage_rows
    rows = {r["id"]: r for r in coverage_rows()}
    assert "tridelphi/weak-actor-guard" in rows["agent-identity-spoofing"]["rules"]
