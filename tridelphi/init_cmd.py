"""`tridelphi init` — drop a ready-to-run guard workflow into a repo.

The whole point is that a non-expert can protect their repo in one command. It
writes `.github/workflows/tridelphi.yml`, a workflow that scans on every pull
request, uploads results to the Security tab, posts a plain-language sticky
comment on the PR — and *fails the build* when a critical exists, with the
ordered fix plan in the run's Summary tab. Explain first, then block: the
comment and the SARIF always land before the gate fires.

Idempotent: it refuses to clobber an existing file unless `--force` is given,
and it prints exactly what to do next.
"""

from __future__ import annotations

import sys
from pathlib import Path

__all__ = ["WORKFLOW", "run_init"]

# The workflow is itself Rule-of-Two clean: it runs on pull_request (where fork
# tokens are read-only), interpolates no github.event data into a shell, and the
# only privileged action is posting a comment via first-party github-script.
WORKFLOW = """\
# Added by `tridelphi init`. Scans your GitHub Actions for the jobs where a
# prompt injection or pwn-request would run attacker code with your secrets.
# Docs: https://girnarholdings.github.io/TriDelPhi/
name: TriDelPhi

on:
  pull_request:
  push:
    branches: [main, master]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write
  pull-requests: write

concurrency:
  group: tridelphi-${{ github.ref }}
  cancel-in-progress: true

jobs:
  scan:
    name: Agents Rule of Two
    runs-on: ubuntu-latest
    steps:
      # Egress telemetry for this job itself (step-security/harden-runner,
      # Apache-2.0). Audit mode only observes; tighten to block once you have
      # a baseline of expected endpoints.
      - uses: step-security/harden-runner@5c7944e73c4c2a096b17a9cb74d65b6c2bbafbde # v2.9.1
        with:
          egress-policy: audit

      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4

      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5
        with:
          python-version: '3.12'

      - name: Install TriDelPhi
        run: pipx install tridelphi

      - name: Scan
        id: scan
        # Don't fail *this* step; the SARIF upload and the PR comment must run
        # regardless. The exit code is captured and enforced by the Gate step
        # at the end, so a critical still fails the build — loudly, and after
        # the explanation has already been posted.
        # `--format checklist` is the plain-language report: a first-time reader
        # gets pass/fail and what to do, not exit codes and rule ids. SARIF still
        # carries the full detail to the Security tab.
        run: |
          code=0
          tridelphi . --format checklist --sarif-file tridelphi.sarif > report.txt 2>&1 || code=$?
          echo "code=$code" >> "$GITHUB_OUTPUT"
          {
            echo 'text<<TRIDELPHI_EOF'
            cat report.txt
            echo TRIDELPHI_EOF
          } >> "$GITHUB_OUTPUT"

      - name: Upload to code scanning
        uses: github/codeql-action/upload-sarif@c4dd10e44af883a891fe31ced449bcb4a6728b9b # v3
        if: always()
        with:
          sarif_file: tridelphi.sarif

      - name: Comment on the pull request
        if: github.event_name == 'pull_request'
        uses: actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b # v7
        env:
          REPORT: ${{ steps.scan.outputs.text }}
        with:
          script: |
            const report = process.env.REPORT || 'TriDelPhi produced no output.';
            const body = [
              '<!-- tridelphi -->',
              '### 🔺 TriDelPhi — Agents Rule of Two',
              '',
              '```',
              report.slice(0, 60000),
              '```',
              '',
              '_Static scan of your GitHub Actions. ' +
              '[What this means](https://girnarholdings.github.io/TriDelPhi/)._',
            ].join('\\n');

            const { data: comments } = await github.rest.issues.listComments({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
            });
            const existing = comments.find(c => c.body && c.body.includes('<!-- tridelphi -->'));
            if (existing) {
              await github.rest.issues.updateComment({
                owner: context.repo.owner, repo: context.repo.repo,
                comment_id: existing.id, body,
              });
            } else {
              await github.rest.issues.createComment({
                owner: context.repo.owner, repo: context.repo.repo,
                issue_number: context.issue.number, body,
              });
            }

      - name: Gate
        # The guard's teeth: after the report is uploaded and the comment is
        # posted, a critical fails the build — with the exact solution one
        # click away in the run's Summary tab, ordered easiest-first.
        if: steps.scan.outputs.code != '0'
        run: |
          {
            echo '## 🔺 TriDelPhi found something a stranger could exploit'
            echo
            tridelphi fix --markdown || true
            echo
            echo 'Fix it from your terminal, interactively: `pipx install tridelphi && tridelphi guard`'
          } >> "$GITHUB_STEP_SUMMARY"
          echo "TriDelPhi: critical finding — see the job Summary for the fix plan." >&2
          exit 1
"""

_NEXT_STEPS = """\
Done. TriDelPhi now guards this repo: every pull request is scanned, a
plain-English comment explains what it found, and a critical FAILS the build —
with the fix plan in the run's Summary tab.

Next:
  1. Commit and push this file:
       git add .github/workflows/tridelphi.yml
       git commit -m "Add TriDelPhi security scan"
       git push
  2. Open a pull request — you'll get a comment within a minute.
  3. If it ever goes red, run `tridelphi guard` here in your terminal: it shows
     each problem with its exact solution and asks before fixing anything.
  4. (Optional) Turn on GitHub code scanning to see findings in the Security tab:
       Settings -> Code security -> Code scanning -> set up.

Nothing else to configure. It reads only files on disk and makes no network calls.
"""


def run_init(target: str = ".", *, force: bool = False, out=None, err=None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    root = Path(target)
    if not root.is_dir():
        print(f"tridelphi: {root} is not a directory", file=err)
        return 2

    workflow_dir = root / ".github" / "workflows"
    workflow_path = workflow_dir / "tridelphi.yml"

    if workflow_path.exists() and not force:
        print(
            f"tridelphi: {workflow_path} already exists. Re-run with --force to "
            "overwrite, or edit it by hand.",
            file=err,
        )
        return 1

    workflow_dir.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(WORKFLOW, encoding="utf-8", newline="\n")
    print(f"wrote {workflow_path}", file=out)
    print(file=out)
    print(_NEXT_STEPS, file=out)
    return 0
