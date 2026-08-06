# Issue to write-token

Mirrors the Claude Code Action issue-to-write-credential chain (CVSS 7.8).

An attacker-authored issue body reaches a shell command in a job that holds a
personal access token and pushes to the repository.

- **U** `github.event.issue.body` and `.title` interpolated into `run:`.
- **P** `secrets.RELEASE_PAT`, plus workflow-level `contents: write`.
- **E** `git push`.

Expected: one CRITICAL under `tridelphi/expression-injection-privileged`, and
the cheapest fix should be env-indirection, because that is the one-line change
that breaks nothing.
