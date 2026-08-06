# Agent-config poisoning — the differentiator

The workflow runs on `pull_request_target` (so repository secrets are present)
and then *explicitly* checks out `github.event.pull_request.head.sha` — the
attacker's code. The agent then reads instruction files from that tree.

The subtlety, and the reason a filename grep gets this wrong in both directions:

`anthropics/claude-code-action` restores `CLAUDE.md`, `.claude/`, `.mcp.json`
and five other paths from the **base branch** before the agent starts. So a
finding that says "attacker controls CLAUDE.md" against this action is a **false
positive**.

`AGENTS.md` is *not* in that restore list. It comes from the PR head and is read
as authoritative direction. That is the true finding, and stating it correctly
requires modelling what this specific action version restores.

- **U** agent over an attacker-controlled working tree, plus `AGENTS.md` ingress.
- **P** `secrets.ANTHROPIC_API_KEY` and `pull-requests: write`.
- **E** the agent's network-capable tools.

Expected: CRITICAL under `tridelphi/agent-config-ingress`, and the message must
name `AGENTS.md` and must **not** claim `CLAUDE.md` is attacker-controlled.
