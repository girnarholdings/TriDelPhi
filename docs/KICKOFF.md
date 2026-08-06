# How to run this session

## Setup (before you start Claude Code)

1. Create the project directory and drop the brief in:
   ```
   mkdir tridelphi && cd tridelphi
   git init
   mkdir -p .claude/agents
   cp /path/to/CLAUDE_CODE_BRIEF.md ./CLAUDE_CODE_BRIEF.md
   cp /path/to/.claude/agents/*.md ./.claude/agents/
   ```
2. Start Claude Code on Opus for coordination/judgment; the subagents default to
   Sonnet via their frontmatter:
   ```
   claude --model claude-opus-4-6
   ```

## The kickoff message (paste this verbatim as your first message)

> Read `CLAUDE_CODE_BRIEF.md` in full before doing anything, then read all four
> files in `.claude/agents/`. Confirm back to me, in under ten lines: (a) the v1
> scope in one sentence, (b) what is explicitly out of scope, (c) the five-phase
> build order, and (d) the acceptance test that defines done. Do not write any
> code yet.
>
> Once I approve your summary, execute Phase A yourself (the SARIF contract skeleton
> via the `sarif-contract` subagent) and prove the round-trip against the vendored
> OASIS schema with a dummy finding. Stop after Phase A is green and show me the
> validating SARIF before continuing.

## Why gate on the summary first

You're spending Opus tokens on coordination. A ten-line readback costs almost
nothing and catches the two failure modes early: scope creep (it starts
scaffolding the gate or a wrapper) and contract drift (it misunderstands the
SARIF-first ordering). If the readback is wrong, correct it before a single
detector is written — mistakes in Phase A propagate through all four workstreams.

## Phase handoffs — what you approve at each checkpoint

- **After A:** valid SARIF from a dummy finding. Sink is proven. → release
  `graph-modeler` and `fixture-adversary` to run in parallel.
- **After B:** `model.py` interface frozen + `parse.py` enumerates jobs with
  correct line numbers. → release `capability-detective` against the frozen
  interface.
- **After C:** three detectors green on their own unit tests. → wire the rule +
  SARIF in Phase D (main thread).
- **After D:** real findings emit as valid SARIF end-to-end.
- **After E:** `test_thesis.py` green — 3/3 malicious critical, two_cap warnings
  correct, clean is zero. **This is done. Stop here.**

## Token-budget note

Subagent-heavy sessions can run ~7x the tokens of a single thread because each
subagent holds its own context. That's the correct trade here — parallel isolated
workstreams with frozen interfaces beat one thread thrashing between SARIF,
parsing, detection, and adversarial fixtures. But don't spawn subagents for
trivial edits; use them for the four walled workstreams and do the wiring
yourself in the main thread.

## The one thing to watch

The `agent-config-poisoning` fixture and its corresponding U detector (agent-
config ingress) are the moat. Every other capability check exists in some form in
zizmor or the linters. If you're short on time, cut fixture variants and polish,
but never cut that path — it's the reason the product isn't a weekend fork.
