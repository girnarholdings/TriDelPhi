<div align="center">

# 🔺 TriDelPhi

### Find the CI job that turns a comment into remote code execution — before an attacker does.

[![CI](https://github.com/girnarholdings/TriDelPhi/actions/workflows/ci.yml/badge.svg)](https://github.com/girnarholdings/TriDelPhi/actions/workflows/ci.yml)
[![Site](https://img.shields.io/badge/site-girnarholdings.github.io%2FTriDelPhi-22d3ee)](https://girnarholdings.github.io/TriDelPhi/)
[![Python](https://img.shields.io/badge/python-3.11%20|%203.12%20|%203.13-3776ab)](https://pypi.org/project/tridelphi/)
[![License](https://img.shields.io/badge/license-Apache--2.0-3ddc97)](LICENSE)
[![Offline](https://img.shields.io/badge/network%20calls-zero-ff4d6d)](#-offline-by-design)

**[🌐 Website](https://girnarholdings.github.io/TriDelPhi/)** ·
**[📖 Rules](docs/RULES.md)** ·
**[🧭 Decisions](docs/DECISIONS.md)** ·
**[⚙️ Setup](docs/REPO_SETUP.md)**

</div>

---

```console
$ pipx install tridelphi
$ tridelphi .
```

```
tridelphi 0.1.0 · Agents Rule of Two · 6 workflows, 20 jobs, 0.2s, offline

START HERE ────────────────────────────────────────────────────────────
CRITICAL .github/workflows/assist.yml:19   job "assist"
  tridelphi/agent-prompt-injection

  U  ${{ github.event.comment.body }} is interpolated into Claude Code
     Action's prompt input; the agent treats that text as instructions
  P  secrets.ANTHROPIC_API_KEY is available to this job
  E  Claude Code Action can use Bash, WebFetch

  Cheapest fix: strip U — gate the job on the commenter's association
  so only trusted accounts reach it. Escaping does not help; the
  injection is semantic, not syntactic.

  1 critical · 0 warning · 0 note
```

## 🚀 Protect your repo in one command

Not sure where to start? You don't need to learn the flags. Run this in your repo:

```console
$ pipx install tridelphi
$ tridelphi init
wrote .github/workflows/tridelphi.yml
```

Commit that file and push. From now on TriDelPhi scans every pull request, posts
a plain-language sticky comment, and (if you turn on code scanning) files
findings in the Security tab. That's the whole setup — it's the **bot**, and
GitHub Actions is what runs it.

Prefer a one-liner in an existing workflow? This runs the **whole hardening
ladder** — secrets (gitleaks), supply chain (osv-scanner), workflow lint
(zizmor) and TriDelPhi's own capability scan — merged into one report:

```yaml
- uses: girnarholdings/TriDelPhi@v1      # full L1-L3 ladder + PR comment
```

Running a hosted bot across many repos? There's a Cloudflare Worker webhook front
door in [`bot/`](bot/), testable locally with `wrangler dev` — see
[`bot/README.md`](bot/README.md).

---

## 🎯 The problem

In 2026 the dangerous CI jobs stopped *looking* dangerous. An AI agent that
reviews pull requests, a workflow that triages issues with an LLM, a
`pull_request_target` that checks out a fork — each is one crafted comment away
from running attacker code **with your repository's secrets**.

Line-level linters miss it because no single line is wrong. **The danger is the
combination.**

```mermaid
flowchart LR
    A["💬 Attacker comments<br/>on any public issue"] --> B
    subgraph JOB ["⚙️ One GitHub Actions job"]
        direction LR
        B["🔓 <b>U</b>&nbsp; Untrusted input<br/><i>reaches the agent prompt</i>"]
        C["🔑 <b>P</b>&nbsp; Privilege<br/><i>secrets · write token</i>"]
        D["🌐 <b>E</b>&nbsp; Egress<br/><i>Bash · WebFetch · push</i>"]
        B --> C --> D
    end
    D --> E["💥 Attacker code runs<br/>with your credentials"]

    style A fill:#2a1520,stroke:#ff4d6d,color:#ffd7de
    style B fill:#2a1520,stroke:#ff4d6d,color:#ffd7de
    style C fill:#2a2115,stroke:#ffb020,color:#ffe9c2
    style D fill:#132a30,stroke:#22d3ee,color:#c7f3fb
    style E fill:#2a1520,stroke:#ff4d6d,color:#ffd7de
```

## ⚖️ The rule: two is fine, three is an exploit

[Meta's **Agents Rule of Two**](https://ai.meta.com/blog/practical-ai-agent-security/)
says an agent should hold **at most two** of three properties. A GitHub Actions
job is an agent by that definition.

| | Capability | What TriDelPhi looks for |
|:--:|---|---|
| 🔓 | **U** — untrusted input | Fork-reachable trigger **plus a real ingress path**: an injected `${{ github.event.* }}`, a checkout of PR code, or an agent reading files the PR can edit |
| 🔑 | **P** — privilege | `secrets.*`, a write-scoped token, `id-token: write`, or a self-hosted runner |
| 🌐 | **E** — egress | Any `run:` step, a publish/deploy action, or an agent with `Bash`/`WebFetch` |

```mermaid
flowchart TD
    S(["🔍 Scan every job"]) --> Q1{"Holds all<br/>three?"}
    Q1 -->|Yes| CRIT["🔴 <b>CRITICAL</b><br/>fix now — names the one<br/>capability cheapest to remove"]
    Q1 -->|No| Q2{"Holds two, and the<br/>third is one edit away?"}
    Q2 -->|Yes| WARN["🟡 <b>WARNING</b><br/>proximity, not alarm"]
    Q2 -->|No| OK["🟢 <b>SILENT</b><br/>Rule-of-Two compliant —<br/>your deploy job is fine"]

    style S fill:#171e30,stroke:#28304a,color:#e8ecf5
    style Q1 fill:#171e30,stroke:#28304a,color:#e8ecf5
    style Q2 fill:#171e30,stroke:#28304a,color:#e8ecf5
    style CRIT fill:#2a1520,stroke:#ff4d6d,color:#ffd7de
    style WARN fill:#2a2115,stroke:#ffb020,color:#ffe9c2
    style OK fill:#13291f,stroke:#3ddc97,color:#c8f5e2
```

> **It stays quiet on the compliant majority.** A deploy job with a secret and a
> shell is *supposed* to exist. TriDelPhi does not cry wolf on it — that is the
> difference between a tool people keep and one they mute.

## 🛡️ The part no other scanner does

TriDelPhi knows **what each AI agent action restores from the base branch**.

```mermaid
flowchart LR
    PR["📥 Pull request head<br/><i>attacker-controlled</i>"] --> ACT["🤖 claude-code-action<br/><i>restores 8 paths from base</i>"]
    ACT --> SAFE["✅ <b>CLAUDE.md</b><br/>.claude/ · .mcp.json<br/><i>swapped back to base — safe</i>"]
    ACT --> BAD["🔴 <b>AGENTS.md</b><br/>.cursor/rules · package.json<br/><i>stays at PR head — exploitable</i>"]

    style PR fill:#2a1520,stroke:#ff4d6d,color:#ffd7de
    style ACT fill:#171e30,stroke:#8493b0,color:#e8ecf5
    style SAFE fill:#13291f,stroke:#3ddc97,color:#c8f5e2
    style BAD fill:#2a1520,stroke:#ff4d6d,color:#ffd7de
```

A filename-matching scanner gets this **wrong in both directions**: it flags
`CLAUDE.md` (a false positive on the hardened, recommended setup) and it has
nothing to say about `AGENTS.md` (the real finding). Getting that distinction
right requires a per-action, per-version model of restore behaviour — which is
the part that has to be maintained, and the part nobody else maintains.

## 🧭 Coverage against a published taxonomy

`tridelphi --coverage` maps every rule onto [Uber's **ADR**](https://github.com/uber/ADR)
17 agent threat techniques (MLSys 2026, arXiv:2605.17380) — and says plainly
where static analysis **cannot** reach:

```
[x] Agentic Control-Flow Hijacking             detected
[x] Indirect Prompt Injection                  detected
[x] Exploitation of Excessive Tool Permissions detected
[x] Agent Identity Spoofing                    partial
[ ] Tool Shadowing                             gap — statically reachable, no rule yet
[-] Long-Term Goal Hijacking                   runtime-only
...
9 of 11 statically reachable techniques have a rule; 6 of 17 are runtime-only.
```

**ADR is the runtime half; TriDelPhi is the static half.** ADR observes agent
sessions and detects hijacking as it happens. TriDelPhi finds the jobs where
those attacks would land, before anything runs. Roughly a third of the taxonomy
is runtime-only by nature — no repository content distinguishes a benign session
from a hijacked one — and the report says so rather than claiming coverage it
does not have.

## 📦 Install

```console
pipx install tridelphi          # recommended — isolated
pip install tridelphi           # or into your environment
uvx tridelphi .                 # or run without installing
```

Python 3.11+. One runtime dependency: `ruamel.yaml`.

## 🚀 Use it

```console
tridelphi .                                    # scan, human-readable
tridelphi . --format html --html-file out.html # a page you can share
tridelphi . --format sarif --sarif-file s.json # for GitHub code scanning
tridelphi --explain agent-config-ingress       # what a rule means and why
tridelphi --coverage                           # ADR taxonomy coverage
tridelphi --list-rules                         # every rule at a glance
```

### 🔁 The ratchet — stop the count from rising

You cannot fix everything today. Freeze what exists, block only what is new:

```console
tridelphi . --write-baseline   # once: record today's findings
tridelphi .                    # from now on, only new findings count
```

Fingerprints ignore line numbers, so adding a step above a job does not re-flag it.

### 🪜 Climb the ladder — the full bundle in one flag

TriDelPhi core finds the **combination** no per-rule linter sees. The rungs
below it are commodity checks that best-of-breed open-source tools already do
superbly — so instead of reimplementing them, `--level` runs them and merges
everything into **one SARIF document, one Security tab, one gate**:

| Rung | Tool | License | Catches |
|:--:|---|:--:|---|
| **L1** | [gitleaks](https://github.com/gitleaks/gitleaks) | MIT | credentials committed to the tree |
| **L2** | [osv-scanner](https://github.com/google/osv-scanner) | Apache-2.0 | known-vulnerable packages in your lockfiles¹ |
| **L3** | [zizmor](https://github.com/zizmorcore/zizmor) | MIT | unpinned actions, template injection, workflow lint |
| **L3** | **tridelphi core** | Apache-2.0 | the U∩P∩E capability intersection — always runs |
| **L4** | [scorecard](https://github.com/ossf/scorecard) | Apache-2.0 | OSSF repo posture: security policy, token permissions, pinning¹ |
| **L5** | [semgrep](https://github.com/semgrep/semgrep) | LGPL-2.1 | rule-based SAST of the application code itself¹ |
| **L6** | **tridelphi attest / gate** | Apache-2.0 | native: emit signed evidence + enforce policy as its own step |
| **L7** | **tridelphi verify** + [gh](https://github.com/cli/cli) | Apache-2.0 / MIT | native trust-lock pawl (offline) + upstream provenance verification |

```console
tridelphi . --level 3      # lean default: secrets + supply chain + workflow lint + core
tridelphi . --level 6      # the whole ladder, then write the evidence statement
tridelphi . --level 7      # + verify consumed actions against the trust-lock
tridelphi . --level 1      # just secrets + core
tridelphi --credits        # who built what — the wrapped tools, with licenses
```

Rungs are cumulative. **Level 3 is the recommended default** — fast, and it
stays off the heavier dependency trees; opt into 5+ when you want code SAST.
Missing a tool? That rung is skipped with an install hint — a missing optional
scanner **never** fails the scan or hides TriDelPhi's own findings. A gitleaks
hit is escalated to error severity: a live secret in the tree is never just a
warning. ¹ osv-scanner, scorecard and semgrep reach the network (a vuln
database or a ruleset registry); pass `--offline` to skip those rungs.
`--with-zizmor` remains as the single-tool spelling of L3's linter.

### 🔏 L6 — attest & gate, the spec's two closing processes

Scanning and enforcing are deliberately separate steps, so evidence can be
uploaded before a gate fails the build and a policy change can re-gate an old
scan without re-scanning:

```console
tridelphi . --level 6 --sarif-file out.sarif   # scan every rung, then attest
tridelphi gate out.sarif                        # enforce --fail-on as its own process
tridelphi attest out.sarif                      # write the in-toto evidence statement
```

`attest` emits an **unsigned** in-toto Statement (the SARIF's digest as
subject, the tools and their counts as predicate). Signing is sigstore's job:
the composite action feeds the evidence to `actions/attest-build-provenance`,
which signs it with the workflow's OIDC identity. The generated `init`
workflow also drops in [step-security/harden-runner](https://github.com/step-security/harden-runner)
(Apache-2.0) to audit the scan job's own egress.

### 🔑 L7 — trust: the pawl SHA-pinning can't provide

L6 *produces* signed evidence; L7 is the **consumer** half nothing below it
provides — it asks the one question the content rungs don't: *is what I consume
still pinned to who it claims to be?*

```console
tridelphi verify --write-trust-lock   # once: record each action's owner + pinned SHA
git add .tridelphi/trust.lock          # commit the pawl
tridelphi verify .                     # from now on, a changed signer fails the build
```

The **trust-lock** records the owner and pinned SHA of every third-party
`uses:` in your workflows. On a later run, an action whose SHA changed *under
the same ref*, or whose owner changed (a repo transfer), is an **error** that
fails the gate. This is the case SHA-pinning cannot see: pinning defeats tag
*mutation*, but a hijacked or transferred upstream repo — the tj-actions class —
looks like a legitimate new SHA. The lock catches it. The whole pawl is
**offline and deterministic**: no network, no crypto, just the diff between
what you locked and what the workflow says now.

Where the [gh CLI](https://github.com/cli/cli) is present and online, L7 also
verifies upstream SLSA build provenance — reported honestly at `note` level,
because in 2026 most actions publish none, and a finding you can't act on
should never break your build. See [`docs/L7_PROPOSAL.md`](docs/L7_PROPOSAL.md)
for the full design and its honest limits.

## ⚡ Put it in CI — one line

The composite action installs everything (version-pinned, checksum-verified),
climbs the ladder, uploads the merged SARIF, and posts a sticky PR comment:

```yaml
name: tridelphi
on:
  pull_request:
  push: { branches: [main] }
permissions:
  contents: read
  security-events: write
  pull-requests: write
jobs:
  harden:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: girnarholdings/TriDelPhi@v1   # the whole ladder, one line
        with: { level: '3' }
```

Or hand-roll it — the CLI is a normal exit-code-honest scanner:

```yaml
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pipx install tridelphi
      - run: tridelphi . --format text --sarif-file tridelphi.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()          # the scan exits non-zero on findings; upload anyway
        with: { sarif_file: tridelphi.sarif }
```

### 🚦 Exit codes

| Code | Meaning |
|:--:|---|
| `0` | no findings at or above `--fail-on` (default `critical`) |
| `1` | findings at or above `--fail-on` |
| `2` | execution error — bad path, bad arguments, or `--strict-parse` on unparseable YAML |

`--min-severity` controls what you **see**; `--fail-on` controls what **breaks
the build**. Independent axes, both defaulting to `critical`, so warnings inform
without turning day one red.

## 🔒 Offline by design

No network calls, no account, no API token. By default it reads files on disk
and nothing else — air-gap safe and auditable in one sitting. Subprocesses are
spawned only when you explicitly ask for the ladder (`--level`, `--with-zizmor`),
and the only rung that touches the network is osv-scanner's osv.dev lookup —
which `--offline` skips, and which the credit line labels honestly.

## 🙏 Standing on the shoulders

The ladder exists because these projects do the commodity layers superbly;
TriDelPhi orchestrates them and adds the capability-graph join they don't do.
Each keeps its own name, rule metadata, and provenance as a separate run in the
merged SARIF — attribution is structural, not a footnote:
[gitleaks](https://github.com/gitleaks/gitleaks) (MIT) ·
[osv-scanner](https://github.com/google/osv-scanner) (Apache-2.0) ·
[zizmor](https://github.com/zizmorcore/zizmor) (MIT) ·
[scorecard](https://github.com/ossf/scorecard) (Apache-2.0) ·
[semgrep](https://github.com/semgrep/semgrep) (LGPL-2.1) ·
[step-security/harden-runner](https://github.com/step-security/harden-runner) (Apache-2.0) ·
[actions/attest-build-provenance](https://github.com/actions/attest-build-provenance) (MIT) ·
[gh CLI](https://github.com/cli/cli) (MIT, L7 provenance).
Run `tridelphi --credits` for the same table from the CLI.

## 📊 Honest calibration

Egress is true for **~9 jobs in 10** — a `run:` step is unrestricted network
access on a hosted runner. TriDelPhi publishes that rather than hiding it: the
discriminating join is **U ∩ P**, and E exists to rank findings and catch the
rare genuinely-contained job. Narrowing E's detection would only produce false
negatives, since `run: node build.js` where the script fetches is invisible to
any pattern.

## 🧪 Developing

```console
pip install -e ".[dev]"
pytest -q                       # 253 tests
ruff check tridelphi/ tests/    # lint
python -m build --wheel         # packaging
```

```mermaid
flowchart LR
    L["🧹 lint<br/><i>ruff</i>"] --> OK
    T["🧪 test<br/><i>3.11 · 3.12 · 3.13</i>"] --> OK
    W["📦 wheel<br/><i>clean-venv install</i>"] --> OK
    S["🔺 self-scan<br/><i>dogfood + SARIF</i>"] --> OK["✅ <b>ci-ok</b><br/><i>the single required check</i>"]

    style L fill:#171e30,stroke:#8493b0,color:#e8ecf5
    style T fill:#171e30,stroke:#8493b0,color:#e8ecf5
    style W fill:#171e30,stroke:#8493b0,color:#e8ecf5
    style S fill:#171e30,stroke:#8493b0,color:#e8ecf5
    style OK fill:#13291f,stroke:#3ddc97,color:#c8f5e2
```

The **wheel** job is the one worth explaining: `pip install -e .` leaves the repo
on disk, so a missing `package-data` entry stays invisible until a real user
installs. It builds a wheel, installs it into a clean venv, and runs the console
script from *outside* the checkout.

**`ci-ok`** aggregates the rest and asserts each result is `success` — a
cancelled or skipped job is not success, which is the failure mode that lets
untested merges through. A test asserts it depends on every job, so adding one
without wiring it in fails CI rather than silently widening what can merge.

> ⚙️ Two repository settings a workflow cannot flip — serving the site and
> requiring `ci-ok` — are in [`docs/REPO_SETUP.md`](docs/REPO_SETUP.md).

## 📚 Docs

| Doc | What it is |
|---|---|
| 🌐 [**Website**](https://girnarholdings.github.io/TriDelPhi/) | The landing page, deployed from [`site/`](site/) |
| 📖 [`docs/RULES.md`](docs/RULES.md) | Every rule, its ADR technique, why it fires |
| 🧭 [`docs/DECISIONS.md`](docs/DECISIONS.md) | What four adversarial reviews changed before a line was written |
| 🗺️ [`docs/OSS_LANDSCAPE.md`](docs/OSS_LANDSCAPE.md) | Prior art: zizmor, poutine, Raven, octoscan, TaintAWI |
| ⚙️ [`docs/REPO_SETUP.md`](docs/REPO_SETUP.md) | The two settings that gate merges and serve the site |
| 🤖 [`bot/`](bot/) | Cloudflare Worker webhook front door for a hosted bot |
| ▶️ [`action.yml`](action.yml) | The one-line `uses:` composite action |

---

<div align="center">
<sub>TriDelPhi is one rung of a larger CI hardening ladder. The merge gate and
attestation plane are separate work — the capability-graph core came first
because it is the piece that does not already exist in open source.</sub>
</div>
