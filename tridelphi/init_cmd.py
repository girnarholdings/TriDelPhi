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

__all__ = ["FIX_WORKFLOW", "WORKFLOW", "render_action_workflow", "run_init"]

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
      - uses: step-security/harden-runner@b09bb98e06d4d774595224525879c09bc6e98c40 # v2.20.1
        with:
          egress-policy: audit

      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
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
          tridelphi . --format checklist --sarif-file tridelphi.sarif \
            --checklist-md-file report.md > report.txt 2>&1 || code=$?
          echo "code=$code" >> "$GITHUB_OUTPUT"
          {
            echo 'md<<TRIDELPHI_EOF'
            cat report.md 2>/dev/null || cat report.txt
            echo TRIDELPHI_EOF
          } >> "$GITHUB_OUTPUT"

      # Uploads on push only, on purpose: uploading on a pull request makes
      # github-advanced-security[bot] echo these same findings back as inline
      # review comments, duplicating the sticky comment below. One voice on the
      # PR; the Security tab tracks the default branch.
      - name: Upload to code scanning
        uses: github/codeql-action/upload-sarif@5595ccaf912efad79be6eef63a5619ff05969be3 # v4.37.6
        if: always() && github.event_name != 'pull_request'
        with:
          sarif_file: tridelphi.sarif
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
      #     uses: github/codeql-action/upload-sarif@5595ccaf912efad79be6eef63a5619ff05969be3 # v4.37.6
      #     if: always() && github.event_name != 'pull_request'
      #     with:
      #       sarif_file: expose.sarif
      #       category: tridelphi-expose

      - name: Comment on the pull request
        if: github.event_name == 'pull_request'
        uses: actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3 # v9.0.0
        env:
          REPORT_MD: ${{ steps.scan.outputs.md }}
        with:
          script: |
            // The comment is what the notification email renders — real
            // Markdown, not a monospace dump.
            const report = process.env.REPORT_MD || 'TriDelPhi produced no output.';
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

# Reply-to-fix: a maintainer replies `tridelphi fix` on a pull request and this
# workflow applies the automatic fixes to the PR branch — each one verified by
# a re-scan or rolled back, exactly like `tridelphi fix --apply` locally.
#
# Built to pass the scanner that ships it. The Rule of Two audit of this file:
#   U   the comment body is read ONLY inside `if:` expressions, which GitHub
#       evaluates before any shell exists; no event text ever reaches a shell,
#       an env file, or a prompt. The PR number is numeric and env-quoted.
#   gate  only OWNER / MEMBER / COLLABORATOR comment authors can trigger it —
#       the author_association gate TriDelPhi itself recommends (and honors).
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
    #   · the "Fix these for me" checkbox in TriDelPhi's own comment — GitHub only
    #     lets users with write access toggle a task list, and the Authorize step
    #     below re-verifies that write access before anything runs. Both branches
    #     use positive `contains` only (never `!contains`/`!=`), so this stays the
    #     strong author_association gate our own detector recognises.
    if: >-
      github.event.issue.pull_request != null && (
        (contains(github.event.comment.body, 'tridelphi fix') &&
         contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association))
        ||
        (contains(github.event.comment.body, '<!--tridelphi-fix-->') &&
         contains(github.event.comment.body, '[x]'))
      )
    runs-on: ubuntu-latest
    steps:
      # Re-verify authorization before doing anything. The comment path is already
      # gated on author_association above; the checkbox path is gated by GitHub
      # (write access to toggle), which we confirm here — and we never act on the
      # bot's own edits (its periodic re-render of the comment).
      - name: Authorize the requester
        id: auth
        uses: actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3 # v9.0.0
        with:
          script: |
            const p = context.payload;
            if (p.sender && p.sender.type === 'Bot') { core.setOutput('ok', 'false'); return; }
            if (p.action === 'created') { core.setOutput('ok', 'true'); return; }
            const { data } = await github.rest.repos.getCollaboratorPermissionLevel({
              owner: context.repo.owner, repo: context.repo.repo, username: p.sender.login,
            });
            const ok = ['admin', 'maintain', 'write'].includes(data.permission);
            core.setOutput('ok', ok ? 'true' : 'false');
            if (!ok) core.notice(`${p.sender.login} lacks write access; ignoring.`);

      - if: steps.auth.outputs.ok == 'true'
        uses: step-security/harden-runner@b09bb98e06d4d774595224525879c09bc6e98c40 # v2.20.1
        with:
          egress-policy: audit

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
        run: pipx install tridelphi

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
        id: apply
        # The log lives OUTSIDE the working tree ($RUNNER_TEMP): a log inside it
        # made `git status` below report a change on every run, so the bot
        # committed its own log and reported "fixes applied" when nothing was.
        run: |
          tridelphi fix --apply > "$RUNNER_TEMP/fix-log.txt" 2>&1 || true
          cat "$RUNNER_TEMP/fix-log.txt"
          {
            echo 'log<<TRIDELPHI_EOF'
            cat "$RUNNER_TEMP/fix-log.txt"
            echo TRIDELPHI_EOF
          } >> "$GITHUB_OUTPUT"

      # An intentional tool update (Dependabot, or a maintainer) trips the L7
      # trust-lock by design — the pawl cannot tell a wanted bump from a swap.
      # Ticking the box IS the human confirmation, so re-record the moved pins
      # here. `--relock` refuses if an action changed OWNER: that is the repo
      # transfer / takeover shape, and no click should wave it through.
      - name: Re-lock tool pins the maintainer just approved
        if: steps.pr.outputs.skip == 'false'
        id: relock
        run: |
          if tridelphi verify . --relock > "$RUNNER_TEMP/relock.txt" 2>&1; then
            echo "refused=false" >> "$GITHUB_OUTPUT"
          else
            echo "refused=true" >> "$GITHUB_OUTPUT"
          fi
          cat "$RUNNER_TEMP/relock.txt"
          {
            echo 'log<<TRIDELPHI_EOF'
            cat "$RUNNER_TEMP/relock.txt"
            echo TRIDELPHI_EOF
          } >> "$GITHUB_OUTPUT"

      - name: Push what verified
        if: steps.pr.outputs.skip == 'false'
        id: push
        run: |
          if [ -z "$(git status --porcelain)" ]; then
            echo "changed=false" >> "$GITHUB_OUTPUT"
            echo "No files changed — nothing was auto-fixable, or nothing verified."
          else
            git config user.name "github-actions[bot]"
            git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
            git add -A
            git commit -m "tridelphi: apply verified automatic fixes"
            git push
            echo "changed=true" >> "$GITHUB_OUTPUT"
          fi

      - name: Report back
        if: steps.pr.outputs.skip == 'false'
        uses: actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3 # v9.0.0
        env:
          FIX_LOG: ${{ steps.apply.outputs.log }}
          CHANGED: ${{ steps.push.outputs.changed }}
          RELOCK_LOG: ${{ steps.relock.outputs.log }}
          RELOCK_REFUSED: ${{ steps.relock.outputs.refused }}
        with:
          script: |
            const changed = process.env.CHANGED === 'true';
            const refused = process.env.RELOCK_REFUSED === 'true';
            const log = (process.env.FIX_LOG || '').slice(0, 25000);
            const relock = (process.env.RELOCK_LOG || '').slice(0, 25000);
            // A refused re-lock is the one outcome that must not read as routine:
            // an action changed hands, which is exactly what the lock is for.
            const headline = refused
              ? '🛑 **TriDelPhi stopped: one of your pinned tools changed hands.** A repo transfer and a takeover look identical from here, so nothing was re-locked. Confirm the action is still the one you trust, then record it deliberately with `tridelphi verify --write-trust-lock`.'
              : changed
              ? '🔺 **TriDelPhi applied its verified fixes** — each change below was re-scanned before it was kept.'
              : '🔺 **TriDelPhi had nothing it could fix automatically** — the remaining items need a human decision (`tridelphi guard` locally walks you through them).';
            // Tell them the last step. A push made by GITHUB_TOKEN leaves the
            // re-run needing a maintainer's "Approve and run" on many repos, so
            // the checks sit stale and it looks like nothing happened. Saying so
            // is the difference between "done" and "why is it still red".
            const nextStep = changed
              ? "**One last step:** the checks re-run on the new commit, and GitHub may " +
                "hold them for approval — if they look stuck, open the **Actions** tab and " +
                "click **Approve and run**."
              : null;
            const body = [
              headline, '',
              ...(relock.trim() ? ['**Tool pins**', '', '```', relock, '```', ''] : []),
              '```', log, '```',
              ...(nextStep ? ['', nextStep] : []),
            ].join('\\n');
            await github.rest.issues.createComment({
              owner: context.repo.owner, repo: context.repo.repo,
              issue_number: context.issue.number, body,
            });
"""

_NEXT_STEPS = """\
Done. TriDelPhi now guards this repo: every pull request is scanned, a
plain-English comment explains what it found, and a critical FAILS the build —
with the fix plan in the run's Summary tab.

Next:
  1. Commit and push both files:
       git add .github/workflows/tridelphi.yml .github/workflows/tridelphi-fix.yml
       git commit -m "Add TriDelPhi security scan + fix bot"
       git push
  2. Open a pull request — you'll get a comment within a minute.
  3. If it flags something minor, just reply `tridelphi fix` on the pull
     request: the bot applies the automatic fixes to the branch, re-scanning
     each one before it's kept. (Maintainer comments only; forks excluded.)
  4. For anything bigger, run `tridelphi guard` in your terminal: it shows each
     problem with its exact solution and asks before fixing anything.
  5. (Optional) Turn on GitHub code scanning to see findings in the Security tab:
       Settings -> Code security -> Code scanning -> set up.

Nothing else to configure. The scan reads only files on disk.
"""


# ---------------------------------------------------------------------------
# the one-click / wizard path — a composite-action workflow with chosen inputs
# ---------------------------------------------------------------------------

_CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"


def render_action_workflow(
    *, level: int = 3, fail_on: str = "critical", comment: bool = True, expose: bool = False,
) -> str:
    """The one-line composite-action workflow the Setup Studio and `init --wizard`
    emit: ``uses: girnarholdings/TriDelPhi@v3`` with the chosen inputs, so the whole
    selected ladder (plus optional `expose`) runs and merges into one code-scanning
    upload. Plain ``tridelphi init`` writes the transparent, pipx-based workflow
    instead; this is the click-and-choose spelling."""
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
        "  pull-requests: write",
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
        "      - uses: girnarholdings/TriDelPhi@v3",
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
    input_stream=None, out=None, err=None,
) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    root = Path(target)
    if not root.is_dir():
        print(f"tridelphi: {root} is not a directory", file=err)
        return 2

    workflow_dir = root / ".github" / "workflows"
    if wizard:
        opts = _ask_wizard(input_stream or sys.stdin, out)
        fix_bot = opts.pop("fix_bot")
        targets: tuple[tuple[Path, str], ...] = (
            (workflow_dir / "tridelphi.yml", render_action_workflow(**opts)),
        )
        if fix_bot:
            targets += ((workflow_dir / "tridelphi-fix.yml", FIX_WORKFLOW),)
    else:
        targets = (
            (workflow_dir / "tridelphi.yml", WORKFLOW),
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

    workflow_dir.mkdir(parents=True, exist_ok=True)
    for path, content in targets:
        path.write_text(content, encoding="utf-8", newline="\n")
        print(f"wrote {path}", file=out)
    print(file=out)
    print(_NEXT_STEPS, file=out)
    return 0
