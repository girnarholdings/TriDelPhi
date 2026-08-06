# TriDelPhi

**Find the CI job that turns a comment into remote code execution — before an attacker does.**

TriDelPhi scans your GitHub Actions workflows and flags the jobs where a
prompt-injection or pwn-request attack would actually work. It reads only files
on disk, makes no network calls, needs no account, and prints the one line you
should change.

```console
$ pipx install tridelphi     # or: pip install tridelphi
$ tridelphi .
```

```
tridelphi 0.1.0 · Agents Rule of Two · 6 workflows, 20 jobs, 0.2s, offline

START HERE ────────────────────────────────────────────────────────────
CRITICAL .github/workflows/assist.yml:19   job "assist"
  tridelphi/agent-prompt-injection

  U  ${{ github.event.comment.body }} is interpolated into Claude Code
     Action's prompt input; the agent treats that text as instructions
     .github/workflows/assist.yml:19
  P  secrets.ANTHROPIC_API_KEY is available to this job
     .github/workflows/assist.yml:22
  E  Claude Code Action can use Bash, WebFetch
     .github/workflows/assist.yml:14

  Cheapest fix: strip U — gate the job on the commenter's association so
  only trusted accounts can reach it. Escaping does not help; the
  injection is semantic, not syntactic.

  1 critical · 0 warning · 0 note
```

---

## Why this exists

In 2026 the dangerous CI jobs stopped looking dangerous. An AI agent that reviews
pull requests, a workflow that triages issues with an LLM, a `pull_request_target`
that checks out a fork — each is one crafted comment away from running attacker
code *with your repository's secrets*. Line-level linters miss it because no
single line is wrong. The danger is in the **combination**.

[Meta's **Agents Rule of Two**](https://ai.meta.com/blog/practical-ai-agent-security/)
names the combination: an agent should hold **at most two** of these three, never
all three.

| | Capability | In a GitHub Actions job |
|---|---|---|
| **U** | processes untrusted input | fork-reachable trigger + a real ingress path — an injected `${{ github.event.* }}`, a checkout of PR code, or an AI agent reading files the PR can edit |
| **P** | holds sensitive data | `secrets.*`, a write-scoped token, `id-token: write`, a self-hosted runner |
| **E** | changes state / talks to the network | any `run:` step, a publish/deploy action, an agent with `Bash`/`WebFetch` |

Hold all three in one job and prompt injection becomes code execution with your
credentials. **TriDelPhi finds those jobs, and only those** — it stays quiet on
the ordinary CI that holds at most two.

## What you get

- **`CRITICAL`** — a job holds U ∩ P ∩ E. Fix it now; the report tells you which
  single capability is cheapest to remove and what that breaks.
- **`WARNING`** — a job holds two, and the third is one small, easy-to-miss edit
  away. Proximity, not alarm.
- **Silence** on the compliant majority. A deploy job with a secret and a shell
  is *supposed* to exist; TriDelPhi does not cry wolf on it.

The differentiator is the **agent-config** class no other scanner has: it knows
what each AI agent action restores from the base branch. `claude-code-action`
replaces `CLAUDE.md` and seven other paths with base content before the agent
runs — so a `CLAUDE.md` finding against it is a false positive, while `AGENTS.md`
(*not* restored) is a real one. TriDelPhi models that difference per action.

## Install

```console
pipx install tridelphi          # recommended — isolated
pip install tridelphi           # or into your environment
uvx tridelphi .                 # or run without installing
```

Python 3.11+. The only runtime dependency is `ruamel.yaml`.

## Use it

```console
tridelphi .                     # scan the current repo, human-readable
tridelphi . --format html --html-file report.html    # a page you can share
tridelphi . --format sarif --sarif-file out.sarif     # for GitHub code scanning
tridelphi --explain agent-config-ingress              # what a rule means and why
tridelphi --list-rules                                # every rule at a glance
```

### See it in your terminal, ship it to code scanning

```console
tridelphi . --format text --sarif-file tridelphi.sarif
```

Text goes to the log where a human reads it; the SARIF goes to GitHub's Security
tab. You need both, so they combine.

### The ratchet — stop the count from rising

On an existing repo you cannot fix everything today. Freeze what is there and
only block what is *new*:

```console
tridelphi . --write-baseline    # once: record today's findings
tridelphi .                     # from now on, only new findings count
```

Fingerprints ignore line numbers, so adding a step above a job does not
re-flag it.

### Add zizmor's line-level checks

TriDelPhi finds the capability-graph combination; [zizmor](https://github.com/zizmorcore/zizmor)
finds the commodity problems — unpinned actions, mutable tags, template
injection at the line. They are complementary, so you can run both and get one
merged SARIF:

```console
pipx install zizmor
tridelphi . --with-zizmor --format sarif --sarif-file out.sarif
```

zizmor's findings land as a second SARIF run alongside TriDelPhi's. If zizmor
isn't installed, `--with-zizmor` prints a note and TriDelPhi's own findings are
unaffected — it never fails the scan over a missing optional tool. This stays
offline unless you add `--zizmor-online`.

## Put it in CI

```yaml
name: tridelphi
on:
  pull_request:
  push: { branches: [main] }
permissions:
  contents: read
  security-events: write
jobs:
  rule-of-two:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pipx install tridelphi
      - run: tridelphi . --format text --sarif-file tridelphi.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()          # the scan exits non-zero on findings; upload anyway
        with: { sarif_file: tridelphi.sarif }
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | no findings at or above `--fail-on` (default `critical`) |
| `1` | findings at or above `--fail-on` |
| `2` | execution error — bad path, bad arguments, or `--strict-parse` on unparseable YAML |

`--min-severity` controls what you *see*; `--fail-on` controls what *breaks the
build*. They are independent, and both default to `critical`, so warnings inform
without turning day one red.

## Honest calibration

Egress is true for ~9 jobs in 10 — a `run:` step is unrestricted network access
on a hosted runner. TriDelPhi does not hide that: the discriminating join is
U ∩ P, and E exists to rank findings and catch the rare genuinely-contained job.
Narrowing E's detection would only produce false negatives, since `run: node
build.js` where the script fetches is invisible to any pattern.

## Docs

| Doc | What it is |
|---|---|
| [`site/index.html`](site/index.html) | The landing page — what it is and the U/P/E idea, interactive |
| [`docs/RULES.md`](docs/RULES.md) | Every rule, what it means, why it fires |
| [`docs/DECISIONS.md`](docs/DECISIONS.md) | What four adversarial reviews changed before a line was written |
| [`docs/OSS_LANDSCAPE.md`](docs/OSS_LANDSCAPE.md) | Prior art: zizmor, poutine, Raven, octoscan, TaintAWI |

TriDelPhi is one rung of a larger hardening ladder (L0→L6). The merge gate and
attestation plane are separate work; the capability-graph core is the piece that
does not already exist in open source, so it came first.
