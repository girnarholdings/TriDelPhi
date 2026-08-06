# The hardened agent pattern

Identical in shape to `malicious/agent-config-poisoning`, with one difference:
`actions/checkout` has no `ref:`.

Under `pull_request_target`, a bare checkout resolves to the **base** branch —
that is the entire reason the trigger exists. The agent therefore reads
base-branch `CLAUDE.md`, which no PR author can edit.

A detector keyed on "agent step + CLAUDE.md exists + fork-reachable trigger"
fires here. That is a false positive on the officially recommended
configuration, and it is indistinguishable in its message from the real exploit
one directory over. Getting the ref direction right is the difference between a
tool people trust and one they mute.
