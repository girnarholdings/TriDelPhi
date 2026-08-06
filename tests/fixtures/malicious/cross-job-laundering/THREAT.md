# Cross-job output laundering

The composition finding — the one per-file analysis structurally cannot reach.

Read alone, neither job is dangerous. `meta` takes attacker input but holds no
credentials. `publish` holds a token and runs a shell, but references only
`needs.meta.outputs.title`, which appears in no untrusted-context table.

Joined, the PR title reaches a privileged shell.

Expected: `publish` yields a CRITICAL under
`tridelphi/cross-job-untrusted-flow`. A scanner without `needs:` edges reports
at most two unrelated warnings here.
