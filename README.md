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

`U ∩ P ∩ E` → CRITICAL, naming the single cheapest capability to strip. Exactly
two is *compliant* with the rule, so it warns only when the third capability is
one small edit away. Output is SARIF 2.1.0, so it lands in GitHub code scanning
with no UI of ours.

The part that is hard to copy is not "detect an agent" — it is knowing what each
agent action **restores from the base branch**. `anthropics/claude-code-action`
replaces `CLAUDE.md`, `.claude/`, `.mcp.json` and five other paths with base
content before the agent starts, so a finding against those is a false positive.
`AGENTS.md` and `.cursor/rules` are outside that set and stay attacker-
controlled. TriDelPhi models the difference per action, per version.

Offline by design: no network calls, no account, no API token.

## Install and run

```console
$ pip install -e .
$ tridelphi core .
tridelphi 0.1.0 · Agents Rule of Two · 6 workflows, 20 jobs, 0.2s, offline

START HERE ────────────────────────────────────────────────────────────
CRITICAL .github/workflows/assist.yml:19   job "assist"
  tridelphi/agent-prompt-injection

  U  `${{ github.event.comment.body }}` is interpolated into Claude
     Code Action's `prompt` input; the agent treats that text as
     instructions, so anyone who can write it can redirect the agent
     .github/workflows/assist.yml:19
  P  `secrets.ANTHROPIC_API_KEY` is available to this job
     .github/workflows/assist.yml:22
  E  Claude Code Action can use Bash, WebFetch, which reach the
     shell or the network
     .github/workflows/assist.yml:14

  Cheapest fix: strip U
  ...gate the job on the commenter's association so only trusted
  accounts can reach it. Escaping does not help — the injection is
  semantic, not syntactic.
```

Text is the default because SARIF is unreadable at a terminal. Both come out at
once when you need them:

```console
$ tridelphi core . --format text --sarif-file tridelphi.sarif
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | no findings at or above `--fail-on` (default `critical`) |
| `1` | findings at or above `--fail-on` |
| `2` | execution error — bad path, bad arguments, or `--strict-parse` with an unparseable workflow |

`--min-severity` (what you see) and `--fail-on` (what breaks the build) are
separate axes. Both default to `critical`, so warnings inform without turning
day one red.

### The ratchet

```console
$ tridelphi core . --write-baseline    # freeze today's findings
$ tridelphi core .                     # only new ones count from here
```

Fingerprints exclude line numbers, so inserting a step above a job does not
invalidate its baseline entry.

## Honest calibration

Egress is true for roughly nine jobs in ten — any `run:` step is unrestricted
network access on a hosted runner. That is stated rather than hidden: the
discriminating join is untrusted-input ∩ privilege, and egress exists to catch
the rare genuinely contained job and to rank what is left. Narrowing its
detection would only produce false negatives, since `run: node build.js` where
the script fetches is invisible to any pattern.

Holding exactly two capabilities is *compliant* with the Rule of Two, so it is
never critical. Warnings signal **proximity** — a third capability one small,
hard-to-review edit away — not presence.

## Docs

| Doc | What it is |
|---|---|
| [`docs/RULES.md`](docs/RULES.md) | Every rule, what it means, and why it fires |
| [`docs/DECISIONS.md`](docs/DECISIONS.md) | What four adversarial reviews changed, and what was defended |
| [`docs/OSS_LANDSCAPE.md`](docs/OSS_LANDSCAPE.md) | Prior-art scan: zizmor, poutine, Raven, octoscan, TaintAWI |
| [`docs/BRIEF.md`](docs/BRIEF.md) | The original v1 spec (superseded in part by `DECISIONS.md`) |

`tridelphi core` is one component of a larger hardening ladder (L0→L6). The
ladder, the merge gate, and the attestation plane are separate briefs.
