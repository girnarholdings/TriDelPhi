# The official mitigation must not be flagged

GitHub's documented remediation for expression injection is to route the value
through the environment and quote it in the shell. This fixture does exactly
that.

A detector that scans `run:` and `with:` and `env:` undifferentiated flags the
correct code. Flagging the official fix is worse than missing the bug: it
teaches users their remediation did not work, and the next thing they do is
disable the rule.

`env:` is a U hit only when the run body re-expands the variable unsafely —
`eval`, command substitution, or writing it to `$GITHUB_ENV`.
