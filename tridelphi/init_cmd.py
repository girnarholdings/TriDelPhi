"""`tridelphi init` — drop a ready-to-run workflow into a repo.

The whole point is that a non-expert can protect their repo in one command. It
writes `.github/workflows/tridelphi.yml`, a workflow that scans on every pull
request, uploads results to the Security tab, and posts a plain-language sticky
comment on the PR. No flags to learn, no config to write.

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
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install TriDelPhi
        run: pipx install tridelphi

      - name: Scan
        id: scan
        # Never fail the job here; we want the SARIF upload and the PR comment to
        # run regardless. The gate is code scanning + branch protection, not this
        # step's exit code.
        run: |
          tridelphi . --format text --sarif-file tridelphi.sarif > report.txt 2>&1 || true
          {
            echo 'text<<TRIDELPHI_EOF'
            cat report.txt
            echo TRIDELPHI_EOF
          } >> "$GITHUB_OUTPUT"

      - name: Upload to code scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: tridelphi.sarif

      - name: Comment on the pull request
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
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
"""

_NEXT_STEPS = """\
Done. TriDelPhi will now scan every pull request and post a sticky comment.

Next:
  1. Commit and push this file:
       git add .github/workflows/tridelphi.yml
       git commit -m "Add TriDelPhi security scan"
       git push
  2. Open a pull request — you'll get a comment within a minute.
  3. (Optional) Turn on GitHub code scanning to see findings in the Security tab:
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
