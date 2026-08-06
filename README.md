# TriDelPhi

A static **Agents Rule of Two** checker for CI.

[Meta's Agents Rule of Two](https://ai.meta.com/blog/practical-ai-agent-security/)
says an agent should hold at most two of three properties: it processes
untrusted input, it holds sensitive credentials, or it can change state and
communicate externally. Hold all three and prompt injection becomes remote code
execution with your secrets.

A GitHub Actions job is an agent by that definition. `tridelphi core` reads a
repo, models every job as an **execution context**, and flags the ones that hold
all three:

- **U — untrusted ingress**: fork-reachable triggers, attacker-controlled
  `github.event.*` interpolation, and — the part no other scanner does — an AI
  agent step reading a `CLAUDE.md` / `AGENTS.md` / `.cursor/rules` file that an
  untrusted PR can edit.
- **P — privilege**: `secrets.*`, effective `write` permissions, `id-token:
  write`, write-capable MCP tools.
- **E — egress / state change**: any `run:` step, publish/deploy actions,
  network commands, agent steps with `Bash`/`WebFetch`.

`U ∩ P ∩ E` → CRITICAL. Exactly two → WARNING, naming the single cheapest
capability to strip. Output is SARIF 2.1.0, so it lands in GitHub code scanning
with no UI of ours.

Offline by design: no network calls, no account, no API token.

## Status

**Pre-implementation.** The repo currently holds the build brief and the
research prewalk. No code yet.

| Doc | What it is |
|---|---|
| [`docs/BRIEF.md`](docs/BRIEF.md) | The full v1 spec — scope, domain model, frozen interfaces, definition of done |
| [`docs/OSS_LANDSCAPE.md`](docs/OSS_LANDSCAPE.md) | Prior-art scan: what exists, what we harvest, what's genuinely ours |
| [`docs/KICKOFF.md`](docs/KICKOFF.md) | Phase checkpoints and the subagent handoff plan |
| [`.claude/agents/`](.claude/agents/) | Four walled subagent definitions for the build |

`tridelphi core` is one component of a larger hardening ladder (L0→L6). The
ladder, the merge gate, and the attestation plane are separate briefs — `core`
is the only piece that does not already exist in open source, so it goes first.
