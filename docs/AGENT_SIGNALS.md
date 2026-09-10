# Maintaining AI-agent restore semantics

TriDelPhi reports an agent action as `unknown` until its working-tree and
configuration behavior has been reviewed. This is intentional: a newly named AI
action must not become a silent pass just because it is absent from a table.

To add or update an entry in `tridelphi/data/agent_signals.yml`:

1. Pin the action version or commit you reviewed.
2. Read the vendor action definition and security documentation. Record the
   source in `evidence`; do not infer restoration from marketing language.
3. Set `restore_state` to `known` only when the action actively replaces named
   paths with base-branch content. Use `none` when no restore exists and
   `unknown` when evidence is incomplete.
4. List exact paths or narrow globs in `restores_from_base`. A broad directory
   must not erase a pull-request-controlled file the action still reads.
5. Record `reviewed_versions` and today in `reviewed_at`.
6. Add a fixture proving restored paths are clean, residual paths still flag,
   and a future unrecognized version/action stays visible as unknown.

The monthly `Review AI-agent security models` workflow fails when evidence is
missing or older than 120 days. It has read-only repository permissions and
does not create issues or modify the table automatically; changing a security
model always requires a reviewed pull request.
