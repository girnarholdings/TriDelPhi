"""`tridelphi init` — drop a ready-to-run guard workflow into a repo.

The whole point is that a non-expert can protect their repo in one command. It
writes `.github/workflows/tridelphi.yml`, a workflow that scans on every pull
request, uploads results to the Security tab, posts a plain-language sticky
comment on the PR — and *fails the build* when a critical exists, with the
ordered fix plan in the run's Summary tab. Explain first, then block: the
comment and the SARIF always land before the gate fires.

Three shapes, because "protect my repo" means different things to different
people and guessing wrong wastes the one command they were willing to run:

``tridelphi init``
    The short composite-Action workflow — a dozen readable lines that a
    first-time user will actually commit. The default.
``tridelphi init --app``
    For someone who shipped a web app and has no CI to speak of: build, then
    `expose` — what your *product* leaks. No ladder, no Rule-of-Two vocabulary.
``tridelphi init --from-source``
    The long transparent workflow that installs the CLI and runs every step in
    the open. Auditable line by line; the right choice if you want to read
    exactly what runs, and the wrong first impression for everyone else.
``tridelphi init --local``
    No CI at all. Installs a git pre-push hook that runs the same scans on
    this machine — for repos that never see GitHub Actions, private mirrors,
    or people who simply want the guard where they work.

Idempotent: it refuses to clobber an existing file unless `--force` is given,
and it prints exactly what to do next.
"""

from __future__ import annotations

import sys
from pathlib import Path

from .fsutil import atomic_write_text
from .release import ACTION_REF, install_command

__all__ = [
    "APP_WORKFLOW",
    "FIX_WORKFLOW",
    "LOCAL_HOOK",
    "WORKFLOW",
    "render_action_workflow",
    "run_init",
]

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
      - uses: step-security/harden-runner@e14015d583714f6e62063499dc959a02595150a1 # v2.21.1
        with:
          egress-policy: audit

      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: '3.12'

      - name: Install TriDelPhi
        run: __TRIDELPHI_INSTALL__

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
          REPORT_TEXT="$RUNNER_TEMP/tridelphi-report.txt"
          REPORT_MD="$RUNNER_TEMP/tridelphi-report.md"
          SARIF_FILE="$RUNNER_TEMP/tridelphi.sarif"
          EXIT_MARKER="$RUNNER_TEMP/tridelphi-exit-code"
          rm -f -- "$REPORT_TEXT" "$REPORT_MD" "$SARIF_FILE" "$EXIT_MARKER"
          tridelphi . --format checklist --sarif-file "$SARIF_FILE" \
            --checklist-md-file "$REPORT_MD" > "$REPORT_TEXT" 2>&1 || code=$?
          printf '%s\\n' "$code" > "$EXIT_MARKER"
          if [ -s "$SARIF_FILE" ]; then
            echo "sarif_ready=true" >> "$GITHUB_OUTPUT"
          else
            echo "sarif_ready=false" >> "$GITHUB_OUTPUT"
          fi
          if [ -f "$REPORT_MD" ]; then
            cat "$REPORT_MD" >> "$GITHUB_STEP_SUMMARY"
          else
            echo "TriDelPhi could not produce the readable report; the final gate will fail." \
              >> "$GITHUB_STEP_SUMMARY"
          fi
          echo "TriDelPhi finished. Open the job Summary for the plain-language report."

      # Uploads on push only, on purpose: uploading on a pull request makes
      # github-advanced-security[bot] echo these same findings back as inline
      # review comments, duplicating the sticky comment below. One voice on the
      # PR; the Security tab tracks the default branch.
      - name: Upload to code scanning
        uses: github/codeql-action/upload-sarif@b96794f015dfd88f77b49b1c93e0fa7110f94c63 # v4.38.0
        if: always() && steps.scan.outputs.sarif_ready == 'true' && github.event_name != 'pull_request'
        with:
          sarif_file: ${{ runner.temp }}/tridelphi.sarif
          category: tridelphi

      # Optional: also audit your *shipped* product — built JS, DB/config — for
      # what it leaks (source maps, client secrets, weak hashing, open database).
      # It is advisory (--fail-on none) and sees only build output present in the
      # checkout, so build first or it finds nothing. Uncomment to enable:
      #
      #   - name: Build
      #     run: npm ci && npm run build          # produces ./dist
      #   - name: Audit shipped output
      #     run: tridelphi expose ./dist --sarif-file expose.sarif --fail-on none
      #   - name: Upload exposure audit
      #     uses: github/codeql-action/upload-sarif@b96794f015dfd88f77b49b1c93e0fa7110f94c63 # v4.38.0
      #     if: always() && github.event_name != 'pull_request'
      #     with:
      #       sarif_file: expose.sarif
      #       category: tridelphi-expose

      - name: Comment on the pull request
        # Fork pull_request tokens are read-only and cannot comment. Those runs
        # still scan and gate; their readable report is in the job Summary.
        if: github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository
        uses: actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3 # v9.0.0
        env:
          REPORT_FILE: ${{ runner.temp }}/tridelphi-report.md
        with:
          script: |
            // The comment is what the notification email renders — real
            // Markdown, not a monospace dump.
            const fs = require('fs');
            function readBounded(path, limit = 60000) {
              if (!path) return '';
              let fd;
              try {
                fd = fs.openSync(path, 'r');
                const buffer = Buffer.alloc(limit);
                const count = fs.readSync(fd, buffer, 0, limit, 0);
                return buffer.subarray(0, count).toString('utf8');
              } catch (_error) {
                return '';
              } finally {
                if (fd !== undefined) fs.closeSync(fd);
              }
            }
            const report = (readBounded(process.env.REPORT_FILE) ||
              'TriDelPhi produced no readable report.').replaceAll('@', '&#64;');
            const body = [
              '<!-- tridelphi -->',
              report.slice(0, 60000),
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
        run: |
          code=2
          if [ -f "$RUNNER_TEMP/tridelphi-exit-code" ]; then
            IFS= read -r code < "$RUNNER_TEMP/tridelphi-exit-code"
          fi
          case "$code" in
            0) exit 0 ;;
            1)
              {
                echo '## 🔺 TriDelPhi found something a stranger could exploit'
                echo
                tridelphi fix --markdown || true
                echo
                echo 'Fix it from your terminal, interactively: `__TRIDELPHI_INSTALL_LOCAL__ && tridelphi guard`'
              } >> "$GITHUB_STEP_SUMMARY"
              echo "TriDelPhi: critical finding — see the job Summary for the fix plan." >&2
              exit 1
              ;;
            *)
              echo '## ⬜ TriDelPhi could not finish the scan' >> "$GITHUB_STEP_SUMMARY"
              echo 'Treat this as unknown, not safe. Open the Scan step, fix the error, and rerun.' \
                >> "$GITHUB_STEP_SUMMARY"
              echo "TriDelPhi could not finish; failing closed." >&2
              exit 2
              ;;
          esac
"""

# Reply-to-fix: a maintainer replies `tridelphi fix` on a pull request and this
# workflow applies the automatic fixes to the PR branch — each one verified by
# a re-scan or rolled back, exactly like `tridelphi fix --apply` locally.
#
# Built to pass the scanner that ships it. The Rule of Two audit of this file:
#   U   the comment body is read ONLY inside `if:` expressions, which GitHub
#       evaluates before any shell exists; no event text ever reaches a shell,
#       an env file, or a prompt. The PR number is numeric and env-quoted.
#   gate  OWNER / MEMBER / COLLABORATOR is the early event gate, followed by a
#       live API check that the sender currently has write/maintain/admin access.
#   scope fork pull requests are skipped before checkout: the bot only ever
#       scans and pushes branches of this repository, i.e. code written by
#       someone who already has write access. And because `issue_comment`
#       workflows always run the file from the DEFAULT branch, a PR cannot
#       modify the bot that will act on it.
#   fix   what gets applied is `tridelphi fix --apply`: the three mechanical
#       fixers only, every edit re-scanned and kept only if the finding
#       provably cleared — never a destructive action.
FIX_WORKFLOW = """\
# Added by `tridelphi init`. Reply `tridelphi fix` on a pull request and the
# bot applies TriDelPhi's automatic fixes to the PR branch — verified or
# rolled back. See the header of this file's twin, tridelphi.yml.
name: TriDelPhi fix

on:
  issue_comment:
    types: [created, edited]

permissions:
  contents: write
  pull-requests: write

concurrency:
  group: tridelphi-fix-${{ github.event.issue.number }}
  cancel-in-progress: false

jobs:
  fix:
    name: Apply verified fixes
    # Trust boundary. Two ways in, both restricted to people this repo trusts:
    #   · a comment that says `tridelphi fix`, gated on author_association; OR
    #   · the "Fix these for me" checkbox in TriDelPhi's own comment — a task-list
    #     box can only be TOGGLED (an `edited` event), and GitHub restricts
    #     toggling a box in someone else's comment to users with write access,
    #     which the Authorize step below re-verifies. The `edited`-only guard is
    #     load-bearing: without it a stranger could post a NEW comment merely
    #     containing the marker and `[x]` and — because Authorize trusts every
    #     `created` event — drive this write-scoped job. So `created` reaches the
    #     job only via the author_association branch. Both branches use positive
    #     `contains` only (never `!contains`/`!=`), so this stays the strong
    #     author_association gate our own detector recognises.
    if: >-
      github.event.issue.pull_request != null && (
        (contains(github.event.comment.body, 'tridelphi fix') &&
         contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association))
        ||
        (github.event.action == 'edited' &&
         contains(github.event.comment.body, '<!--tridelphi-fix-->') &&
         contains(github.event.comment.body, '[x]'))
      )
    runs-on: ubuntu-latest
    steps:
      # Re-verify current repository permission before doing anything. GitHub's
      # MEMBER/COLLABORATOR association is not the same as write permission, so
      # both the typed-comment and checkbox paths must pass this live API check.
      # We also never act on the bot's own periodic comment edits.
      - name: Authorize the requester
        id: auth
        uses: actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3 # v9.0.0
        with:
          script: |
            const p = context.payload;
            if (p.sender && p.sender.type === 'Bot') { core.setOutput('ok', 'false'); return; }
            if (!p.sender || typeof p.sender.login !== 'string') {
              core.setOutput('ok', 'false'); return;
            }
            const { data } = await github.rest.repos.getCollaboratorPermissionLevel({
              owner: context.repo.owner, repo: context.repo.repo, username: p.sender.login,
            });
            const ok = ['admin', 'maintain', 'write'].includes(data.permission);
            core.setOutput('ok', ok ? 'true' : 'false');
            if (!ok) core.notice(`${p.sender.login} lacks write access; ignoring.`);

      # Egress is BLOCKED, not audited: this is the one job where a write-capable
      # token and third-party code (pip's dependency tree) meet, so a compromised
      # package must have nowhere to send the credential. The allowlist is only
      # what the job needs — GitHub itself and PyPI. If a step fails on a blocked
      # connection, the harden-runner log names the endpoint to consider adding.
      - if: steps.auth.outputs.ok == 'true'
        uses: step-security/harden-runner@e14015d583714f6e62063499dc959a02595150a1 # v2.21.1
        with:
          egress-policy: block
          allowed-endpoints: >
            github.com:443
            api.github.com:443
            codeload.github.com:443
            objects.githubusercontent.com:443
            raw.githubusercontent.com:443
            pypi.org:443
            files.pythonhosted.org:443

      # Default-branch checkout; the credential stays so the verified commit
      # can be pushed at the end — pushing is this workflow's entire purpose.
      - if: steps.auth.outputs.ok == 'true'
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - if: steps.auth.outputs.ok == 'true'
        uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: '3.12'

      - name: Install TriDelPhi
        if: steps.auth.outputs.ok == 'true'
        run: __TRIDELPHI_INSTALL__

      - name: Switch to the pull request branch (open, same-repo only)
        id: pr
        if: steps.auth.outputs.ok == 'true'
        env:
          GH_TOKEN: ${{ github.token }}
          PR_NUMBER: ${{ github.event.issue.number }}
        run: |
          state=$(gh pr view "$PR_NUMBER" --json state -q .state)
          if [ "$state" != "OPEN" ]; then
            echo "skip=true" >> "$GITHUB_OUTPUT"
            echo "Pull request is $state — nothing to fix on a closed branch." >&2
            exit 0
          fi
          cross=$(gh pr view "$PR_NUMBER" --json isCrossRepository -q .isCrossRepository)
          if [ "$cross" = "true" ]; then
            echo "skip=true" >> "$GITHUB_OUTPUT"
            echo "Fork pull request — the fix bot only pushes to this repo's own branches." >&2
            exit 0
          fi
          echo "skip=false" >> "$GITHUB_OUTPUT"
          gh pr checkout "$PR_NUMBER"

      - name: Apply the automatic fixes (each verified or rolled back)
        if: steps.pr.outputs.skip == 'false'
        # The log lives OUTSIDE the working tree ($RUNNER_TEMP): a log inside it
        # made `git status` below report a change on every run, so the bot
        # committed its own log and reported "fixes applied" when nothing was.
        run: |
          tridelphi fix --apply > "$RUNNER_TEMP/fix-log.txt" 2>&1 || true

      # An intentional tool update (Dependabot, or a maintainer) trips the L7
      # trust-lock by design — the pawl cannot tell a wanted bump from a swap.
      # Ticking the box IS the human confirmation, so re-record the moved pins
      # here. `--relock` refuses an ambiguous remove-plus-add publisher change:
      # offline source inspection cannot prove that it is a routine replacement.
      - name: Re-lock tool pins the maintainer just approved
        if: steps.pr.outputs.skip == 'false'
        id: relock
        run: |
          if tridelphi verify . --relock > "$RUNNER_TEMP/relock.txt" 2>&1; then
            rm -f "$RUNNER_TEMP/relock-refused"
          else
            : > "$RUNNER_TEMP/relock-refused"
          fi

      - name: Push what verified
        if: steps.pr.outputs.skip == 'false'
        id: push
        run: |
          if [ -z "$(git status --porcelain)" ]; then
            rm -f "$RUNNER_TEMP/push-changed"
            echo "No files changed — nothing was auto-fixable, or nothing verified."
          else
            git config user.name "github-actions[bot]"
            git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
            git add -A
            git commit -m "tridelphi: apply verified automatic fixes"
            git push
            : > "$RUNNER_TEMP/push-changed"
          fi

      - name: Report back
        if: steps.pr.outputs.skip == 'false'
        uses: actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3 # v9.0.0
        with:
          script: |
            const fs = require('fs');
            const path = require('path');
            const temp = process.env.RUNNER_TEMP;
            const read = (name) => {
              let fd;
              try {
                fd = fs.openSync(path.join(temp, name), 'r');
                const buffer = Buffer.alloc(25000);
                const count = fs.readSync(fd, buffer, 0, buffer.length, 0);
                return buffer.subarray(0, count).toString('utf8');
              } catch { return ''; }
              finally { if (fd !== undefined) fs.closeSync(fd); }
            };
            const escape = (value) => value
              .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
              .replaceAll('@', '&#64;')
              .slice(0, 25000);
            const changed = fs.existsSync(path.join(temp, 'push-changed'));
            const refused = fs.existsSync(path.join(temp, 'relock-refused'));
            const log = escape(read('fix-log.txt'));
            const relock = escape(read('relock.txt'));
            // A refused re-lock is the one outcome that must not read as routine:
            // the source identities cannot be safely reconciled automatically.
            const headline = refused
              ? '🛑 **TriDelPhi stopped: your pinned tool identities need review.** A locked publisher was removed while another was introduced, or the lock disagrees with the source. TriDelPhi cannot resolve ownership offline, so nothing was re-locked. Review the change, then replace the lock deliberately with `tridelphi verify --write-trust-lock --yes`.'
              : changed
              ? '🔺 **TriDelPhi applied its verified fixes** — each change below was re-scanned before it was kept.'
              : '🔺 **TriDelPhi had nothing it could fix automatically** — the remaining items need a human decision (`tridelphi guard` locally walks you through them).';
            // GITHUB_TOKEN pushes do not trigger ordinary push/PR workflows.
            // Never imply that stale checks cover the new commit.
            const nextStep = changed
              ? "**One last step:** GitHub does not automatically start checks for a bot-token push. " +
                "Review the changes, then push a new commit yourself to this PR branch " +
                "to trigger fresh checks. Do not merge based on checks for the old commit."
              : null;
            const body = [
              headline, '',
              ...(relock.trim() ? ['**Tool pins**', '', '<pre>', relock, '</pre>', ''] : []),
              '<pre>', log || 'No automatic fix output.', '</pre>',
              ...(nextStep ? ['', nextStep] : []),
            ].join('\\n');
            await github.rest.issues.createComment({
              owner: context.repo.owner, repo: context.repo.repo,
              issue_number: context.issue.number, body,
            });
"""

# The workflow for someone whose fear is "did I just leak my app?", not "can a
# stranger's comment reach my secrets?". No ladder, no Rule-of-Two vocabulary, no
# gate: build the app, audit what the build actually ships, say so on the PR.
#
# Advisory on purpose (`--fail-on none`). `expose` reads static files and cannot
# see your live deployment, so a flagged database may already be firewalled — a
# static audit should not be the thing that blocks your merge until you have
# seen its false-positive rate on your own repo. When you trust it, drop the
# flag and it will fail the build on a shipped key.
APP_WORKFLOW = """\
# Added by `tridelphi init --app`. Builds your app, then audits what the build
# actually ships: keys inlined into browser bundles, source maps that hand over
# your repository, open database rules, credentials committed by accident.
# Docs: https://girnarholdings.github.io/TriDelPhi/
name: TriDelPhi app audit

on:
  pull_request:
  push:
    branches: [main, master]
  workflow_dispatch:

permissions:
  contents: read
  pull-requests: write

jobs:
  audit:
    name: What does this app leak?
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      # `expose` reads files on disk, so your built output has to exist before
      # it looks. Without this step it will still catch committed secrets and
      # open database rules, but it cannot see inside a bundle you never built.
      # Edit this line to match how you build. (ubuntu-latest already has Node;
      # add actions/setup-node if you need a specific version.)
      - name: Build
        run: npm ci && npm run build

      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: '3.12'
      - name: Install TriDelPhi
        run: __TRIDELPHI_INSTALL__

      - name: Audit what we ship
        run: |
          REPORT_TEXT="$RUNNER_TEMP/tridelphi-expose.txt"
          REPORT_MD="$RUNNER_TEMP/tridelphi-expose.md"
          rm -f -- "$REPORT_TEXT" "$REPORT_MD"
          tridelphi expose . --format checklist --checklist-md-file "$REPORT_MD" \
            --fail-on none > "$REPORT_TEXT" 2>&1 || true
          if [ -f "$REPORT_MD" ]; then
            cat "$REPORT_MD" >> "$GITHUB_STEP_SUMMARY"
          else
            echo "TriDelPhi could not produce the exposure report. Rerun the Audit step." \
              >> "$GITHUB_STEP_SUMMARY"
          fi
          echo "TriDelPhi finished. Open the job Summary for the plain-language report."

      - name: Comment on the pull request
        # Fork pull_request tokens are read-only and cannot comment. Those runs
        # still audit; their readable report is in the job Summary.
        if: github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository
        uses: actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3 # v9.0.0
        env:
          REPORT_FILE: ${{ runner.temp }}/tridelphi-expose.md
        with:
          script: |
            const fs = require('fs');
            function readBounded(path, limit = 60000) {
              if (!path) return '';
              let fd;
              try {
                fd = fs.openSync(path, 'r');
                const buffer = Buffer.alloc(limit);
                const count = fs.readSync(fd, buffer, 0, limit, 0);
                return buffer.subarray(0, count).toString('utf8');
              } catch (_error) {
                return '';
              } finally {
                if (fd !== undefined) fs.closeSync(fd);
              }
            }
            const report = (readBounded(process.env.REPORT_FILE) ||
              'TriDelPhi produced no readable report.').replaceAll('@', '&#64;');
            const body = ['<!-- tridelphi-expose -->', report.slice(0, 60000)].join('\\n');
            const { data: comments } = await github.rest.issues.listComments({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
            });
            const existing = comments.find(
              c => c.body && c.body.includes('<!-- tridelphi-expose -->'));
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

# The install line is written once, in `release.py`, and substituted into every
# template here. It used to be typed out in each one as `pipx install tridelphi`
# — a command that 404s, in the file we hand a first-time user, inside CI where
# they cannot debug it. A generated workflow must never contain an install that
# we have not checked resolves.
WORKFLOW = WORKFLOW.replace("__TRIDELPHI_INSTALL__", install_command(pinned=True))
# …except the one line that tells a *human* what to run on their own laptop.
WORKFLOW = WORKFLOW.replace("__TRIDELPHI_INSTALL_LOCAL__", install_command())
FIX_WORKFLOW = FIX_WORKFLOW.replace("__TRIDELPHI_INSTALL__", install_command(pinned=True))
APP_WORKFLOW = APP_WORKFLOW.replace("__TRIDELPHI_INSTALL__", install_command(pinned=True))


_NEXT_STEPS = """\
Done. TriDelPhi now guards this repo: every pull request is scanned, a
plain-English comment explains same-repo pull requests, and a critical FAILS
the build — with the report and fix plan in the run's Summary tab. GitHub gives
fork pull requests a read-only token, so those runs use the Summary instead of
failing while trying to post a comment.

Next:
  1. Commit and push both files:
       git add .github/workflows/tridelphi.yml .github/workflows/tridelphi-fix.yml
       git commit -m "Add TriDelPhi security scan + fix bot"
       git push
  2. Open a pull request — same-repo branches get a comment within a minute;
     fork pull requests get the same scan and gate in the job Summary.
  3. If it flags something minor, just reply `tridelphi fix` on the pull
     request: the bot applies the automatic fixes to the branch, re-scanning
     each one before it's kept. (Current write access required; forks excluded.)
  4. For anything bigger, run `tridelphi guard` in your terminal: it shows each
     problem with its exact solution and asks before fixing anything.
  5. (Optional) Turn on GitHub code scanning to see findings in the Security tab:
       Settings -> Code security -> Code scanning -> set up.

Nothing else to configure. The scan reads only files on disk.
"""

# The no-CI path. Everything TriDelPhi checks in a workflow it can check at a
# git hook instead: same commands, same exit codes, zero GitHub involvement.
# pre-push (not pre-commit) on purpose — a scan on every commit teaches people
# to bypass hooks; a scan before code leaves the machine is the actual boundary.
LOCAL_HOOK = """\
#!/bin/sh
# Added by `tridelphi init --local`. Runs TriDelPhi before every push — the
# same checks the CI workflow would run, entirely on this machine.
# Remove this file (or push with --no-verify) to bypass; edit it to tune.
set -e

echo "tridelphi: pre-push scan (local, offline)"
tridelphi . --fail-on critical
tridelphi expose . --fail-on critical
"""

_LOCAL_NEXT_STEPS = """\
Done. TriDelPhi now guards this repo with no CI at all: every `git push` first
runs the Rule-of-Two scan and the exposure audit on this machine, and a
critical blocks the push.

Notes:
  1. Everything runs locally and offline. Nothing is uploaded anywhere.
  2. Add rungs by editing .git/hooks/pre-push (e.g. `tridelphi . --level 3`).
  3. Bypass once with `git push --no-verify`; remove the hook to uninstall.
  4. Hooks don't travel with the repo — each collaborator runs
     `tridelphi init --local` once. (That is a git property, not a choice:
     a repo that could install hooks on clone would itself be an attack.)
  5. Scanning something BEFORE you install it needs no setup at all:
       tridelphi scan <dir | archive | npm:pkg | pypi:pkg>
"""

_APP_NEXT_STEPS = """\
Done. Every pull request now builds your app and reports what the build ships —
inlined keys, source maps, open database rules, committed credentials — as a
plain-English comment.

Next:
  1. Check the Build step matches how you build:
       .github/workflows/tridelphi-app.yml  (it assumes `npm ci && npm run build`)
  2. Commit and push:
       git add .github/workflows/tridelphi-app.yml
       git commit -m "Add TriDelPhi app exposure audit"
       git push
  3. Run it locally any time, without waiting for CI:
       tridelphi expose .

This audit is advisory — it reports, it never fails your build. It reads static
files, so it cannot see your live deployment; verify anything network-facing
against the real thing.
"""


# ---------------------------------------------------------------------------
# the one-click / wizard path — a composite-action workflow with chosen inputs
# ---------------------------------------------------------------------------

_CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"


def render_action_workflow(
    *, level: int = 3, fail_on: str = "critical", comment: bool = True, expose: bool = False,
) -> str:
    """The short composite-action workflow: one `uses:` line with the chosen
    inputs, so the whole selected ladder (plus optional `expose`) runs and merges
    into one code-scanning upload.

    This is what plain ``tridelphi init``, ``init --wizard`` and the Setup Studio
    all emit — a dozen readable lines someone will actually commit. The long
    transparent workflow that installs the CLI and runs each step in the open is
    ``init --from-source``.

    The pin comes from :mod:`tridelphi.release`, never a literal: it is a commit
    SHA with the version named in a comment, so it resolves today and cannot
    silently start meaning something else."""
    lines = [
        "# Added by the TriDelPhi Setup Studio / `tridelphi init --wizard`. One line runs",
        "# the whole chosen ladder and merges every result into one code-scanning upload.",
        "# Docs: https://girnarholdings.github.io/TriDelPhi/",
        "name: TriDelPhi",
        "",
        "on:",
        "  pull_request:",
        "  push:",
        "    branches: [main, master]",
        "  workflow_dispatch:",
        "",
        "permissions:",
        "  contents: read",
        "  security-events: write",
    ]
    if comment:
        lines.append("  pull-requests: write")
    if level >= 6:
        lines.extend(("  id-token: write", "  attestations: write"))
    lines += [
        "",
        "concurrency:",
        "  group: tridelphi-${{ github.ref }}",
        "  cancel-in-progress: true",
        "",
        "jobs:",
        "  harden:",
        "    name: TriDelPhi",
        "    runs-on: ubuntu-latest",
        "    steps:",
        f"      - uses: {_CHECKOUT}",
        "        with:",
        "          persist-credentials: false",
        f"      - uses: {ACTION_REF}",
        "        with:",
        f"          level: '{level}'",
        f"          fail-on: {fail_on}",
        f"          comment: '{str(comment).lower()}'",
    ]
    if expose:
        lines.append("          expose: 'true'")
    return "\n".join(lines) + "\n"


_WIZARD_INTRO = """\
TriDelPhi setup — a few questions, then I write your workflow.
Press Enter to accept the [default] each time.
"""


def _ask(stream, out, prompt: str, default: str) -> str:
    print(prompt, end="", file=out, flush=True)
    line = stream.readline()
    if line == "":  # EOF / closed stdin → take defaults
        print(file=out)
        return default
    return line.strip() or default


def _ask_wizard(stream, out) -> dict:
    print(_WIZARD_INTRO, file=out)
    raw = _ask(stream, out, "  Ladder level (0 core only · 1 +secrets · 3 +workflow lint · "
               "5 +code SAST · 7 +trust-lock) [3]: ", "3")
    try:
        level = max(0, min(7, int(raw)))
    except ValueError:
        level = 3
    expose = _ask(stream, out, "  Also audit your shipped product (secrets, open DB, leaked "
                  "source) with `expose`? advisory [y/N]: ", "n").lower().startswith("y")
    fo = _ask(stream, out, "  Fail the build on which severity? critical / warning / none "
              "[critical]: ", "critical").lower()
    fail_on = fo if fo in ("critical", "warning", "none") else "critical"
    comment = not _ask(stream, out, "  Post a plain-language PR comment with the report? "
                       "[Y/n]: ", "y").lower().startswith("n")
    fix_bot = not _ask(stream, out, "  Add the reply-to-fix bot (comment `tridelphi fix` on a "
                       "PR applies verified fixes)? [Y/n]: ", "y").lower().startswith("n")
    return {"level": level, "expose": expose, "fail_on": fail_on,
            "comment": comment, "fix_bot": fix_bot}


def run_init(
    target: str = ".", *, force: bool = False, wizard: bool = False,
    app: bool = False, from_source: bool = False, local: bool = False,
    input_stream=None, out=None, err=None,
) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    root = Path(target)
    if root.is_symlink() or not root.is_dir():
        print(f"tridelphi: {root} is not a directory", file=err)
        return 2

    if local:
        # The no-CI path writes into .git/hooks, which only exists in a real
        # repository — and must never clobber a hook someone already wrote.
        hooks_dir = root / ".git" / "hooks"
        if (root / ".git").is_symlink() or not (root / ".git").is_dir():
            print(f"tridelphi: {root} is not a git repository (no .git); "
                  "--local installs a git hook, so it needs one", file=err)
            return 2
        hook = hooks_dir / "pre-push"
        if hook.exists() and not force:
            print(f"tridelphi: {hook} already exists. Re-run with --force to "
                  "overwrite, or add the two tridelphi lines to it by hand.",
                  file=err)
            return 1
        try:
            atomic_write_text(hook, LOCAL_HOOK, create_parent=True, mode=0o755)
        except OSError as exc:
            print(f"tridelphi: could not write pre-push hook: {exc}", file=err)
            return 2
        print(f"wrote {hook}", file=out)
        print(file=out)
        print(_LOCAL_NEXT_STEPS, file=out)
        return 0

    workflow_dir = root / ".github" / "workflows"
    next_steps = _NEXT_STEPS
    if app:
        # The exposure audit stands alone: no fix bot, because nothing `expose`
        # reports is a workflow edit the bot could make.
        targets: tuple[tuple[Path, str], ...] = (
            (workflow_dir / "tridelphi-app.yml", APP_WORKFLOW),
        )
        next_steps = _APP_NEXT_STEPS
    elif wizard:
        opts = _ask_wizard(input_stream or sys.stdin, out)
        fix_bot = opts.pop("fix_bot")
        targets = ((workflow_dir / "tridelphi.yml", render_action_workflow(**opts)),)
        if fix_bot:
            targets += ((workflow_dir / "tridelphi-fix.yml", FIX_WORKFLOW),)
    else:
        # Default: the short composite-Action file. `--from-source` opts into the
        # long transparent one — same scan, every step in the open, and a far
        # worse first thing to hand someone who has never read a workflow.
        scan = WORKFLOW if from_source else render_action_workflow()
        targets = (
            (workflow_dir / "tridelphi.yml", scan),
            (workflow_dir / "tridelphi-fix.yml", FIX_WORKFLOW),
        )

    existing = [path for path, _content in targets if path.exists()]
    if existing and not force:
        print(
            f"tridelphi: {existing[0]} already exists. Re-run with --force to "
            "overwrite, or edit it by hand.",
            file=err,
        )
        return 1

    try:
        if (root / ".github").is_symlink() or workflow_dir.is_symlink():
            raise OSError("refusing to write workflows through a symlinked directory")
        workflow_dir.mkdir(parents=True, exist_ok=True)
        for path, content in targets:
            atomic_write_text(path, content, mode=0o644)
            print(f"wrote {path}", file=out)
    except OSError as exc:
        print(f"tridelphi: could not write workflow: {exc}", file=err)
        return 2
    print(file=out)
    print(next_steps, file=out)
    return 0
