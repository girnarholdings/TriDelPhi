# Self-hosted runner takeover

A fork pull request executes `make all` on a non-ephemeral self-hosted runner.

There are no secrets and the token is read-only, so a model that equates
privilege with credentials sees nothing here. But the runner itself is the
privileged asset: it persists between jobs, and attacker code on it reaches
other jobs' caches, credentials and network position.

- **U** checkout of the pull request merge ref.
- **P** the self-hosted runner — the one privilege class that survives the
  fork-`pull_request` platform cap, because the fork's code runs on the machine
  regardless of what the token may do.
- **E** `run: make all`.

Expected: CRITICAL. This fixture also pins the platform-cap carve-out: if
`self-hosted-runner` were filtered alongside token privilege, this becomes a
false negative on one of the highest-severity real Actions findings.
