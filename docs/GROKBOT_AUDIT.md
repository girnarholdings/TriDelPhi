# GrokBot product audit — TriDelPhi vibe-coder fit

**Date:** 2026-08-14  
**Auditor:** TriDelPhi (Grok Bot)  
**Repo:** [girnarholdings/TriDelPhi](https://github.com/girnarholdings/TriDelPhi)  
**Site:** [girnarholdings.github.io/TriDelPhi](https://girnarholdings.github.io/TriDelPhi/)  
**Base:** `main` @ `d5c0138`  
**Method:** product map of the public repo and site, a product-manager review, and a first-run as a new vibe coder (install + `tridelphi .` + `expose` on a fake Next.js app). No clone of this repo. No code changes in this document — observations and proposed fixes only.

---

## Verdict

New vibe coders would benefit from `tridelphi expose`. They would not benefit from TriDelPhi as it ships today.

The first-run dies at the front door. `pipx` is not on a typical vibe-coder machine, `tridelphi` is not on PyPI, and the command the README tells them to run (`tridelphi .`) looks at GitHub Actions they do not have, then says **YOU'RE GOOD** while a Stripe key sits in `.env`. That is the most dangerous sentence in the product.

You built two products under one name. The site talks to vibe coders. The README, CLI default, and `init` talk to a platform engineer who just wired Claude Code Action. That second person is still the real wedge: nobody else does the per-job U∩P∩E join plus the restore-semantics table. `expose` is unusually honest. It is the on-ramp, not the company.

**Fix the door this week. Do not rebuild the house to look like secretlint.**

---

## 1. What it actually is

A Python 3.11+ offline-first CLI (`tridelphi = tridelphi.cli:main`) plus a composite GitHub Action. The novel core is a static per-job capability graph over `.github/workflows/*.yml`: parse with ruamel → detect Untrusted / Privilege / Egress → join in `rule.py` → flag jobs that hold all three (Meta's Agents Rule of Two). Sixteen native rules (`docs/RULES.md`), including AI-agent restore semantics, cross-job taint, and cheapest-fix remediation.

Around that core, `--level 1–7` shells out to gitleaks / osv-scanner / zizmor / Scorecard / semgrep, then native attest + a committed trust-lock. Sibling commands `expose` and `privatize` audit/obfuscate shipped JS, not CI. One runtime dep: `ruamel.yaml`.

It is not a SaaS, not a pentest, not a secret-hiding tool, and not yet a published PyPI package.

| Channel | Version / pin | Status |
|---|---|---|
| `pyproject.toml` / `__init__.py` | **0.2.0** | Source of truth for CLI / SARIF driver |
| PyPI `tridelphi` | — | **Unpublished (404)** |
| Git tags | `v3.1.0`, `v3.0.0-beta` | No `v3`, `v2`, or `v1` |
| GitHub Release | **v3.1.0** “Exposure Audit + Honest Privatize” (2026-08-09) | Latest; notes empty |
| Action `uses:` in docs/site | `@v3` | **Does not resolve** |
| Action that would work | `@v3.1.0` or a commit SHA | Unadvertised |
| Marketplace | — | **0 listings**; `docs/MARKETPLACE.md` still open |
| Classifier | `Development Status :: 3 - Alpha` | Contradicts site “one line, never think about it again” |
| Social proof | 0 stars, 0 forks, 0 topics, no repo description, no homepage field | Created 2026-08-06 |

---

## 2. Implied users (two products, one binary)

| ICP | Where they appear | What they are sold |
|---|---|---|
| **Vibe-coder / AI-app builder** | `site/index.html`, Setup Studio, `expose` / `privatize`, checklist copy | One-line smoke detector; leaked keys / source maps / open DBs |
| **Solo OSS maintainer with public PRs + AI review bots** | README problem statement, `agent-prompt-injection`, Claude/Gemini/Codex tables | Flag the comment→agent→secrets job before it ships |
| **AppSec / CI security engineer** | `docs/RULES.md`, `DECISIONS.md`, SARIF, `--fail-on`, baseline ratchet | Capability-graph join zizmor cannot do |
| **Platform / DevSecOps (many repos)** | `bot/` Cloudflare Worker, `action.yml` one-liner, Marketplace copy | Hosted dispatch + one `uses:` line |
| **Compliance / release engineer** | L6 attest, L7 trust-lock | Signed receipt + “did this action change hands?” |
| **Security researcher / contributor** | `SECURITY.md`, red-team corpus, “Harden it further” | Attack the scanner; add restore-table rows |

The **site speaks to ICP 1**. The **README and `docs/` speak to ICPs 2–5**. Those are two products sharing one binary.

`docs/RELEASES.md` is explicit: *“`expose` and `privatize` are additive sibling commands (not new ladder rungs).”* `docs/BRIEF.md` is equally explicit the other way: the wrappers are “linear work with a competitor-copyable ceiling. Build the convex thing first.”

**Wedge user (keep this):** a developer or platform engineer who just wired an AI agent into GitHub Actions. Their job is *“can a stranger's comment steal my keys?”* Nobody else names that job. That is still the only un-copyable wedge (`docs/OSS_LANDSCAPE.md` §2, `docs/DECISIONS.md` §2).

**Expansion user (do not make this the identity):** a vibe coder who shipped a Next/Vite app and is scared their OpenAI key, Firebase rules, or source maps are public. Their job is *“did I just leak my app?”* `expose` actually does this job. The ladder, Rule of Two, SARIF, in-toto, and OIDC do not.

Do not collapse them. Do not lead the GitHub surface with the expansion user.

---

## 3. First-run paths and completeness

### A. CLI (`pipx install tridelphi && tridelphi .`)

**Code: complete. Distribution: broken.**

- Default scan is **core only** (no `--level`). Help text: *“Omit --level to run the core Rule-of-Two scan only… the CLI has no default rung; the GitHub Action defaults to level 3.”*
- `tridelphi . --format checklist`, `fix`, `guard`, `expose`, `privatize`, `init`, `verify`, `gate`, `attest` are all wired in `cli.py`.
- **PyPI `tridelphi` is 404.** `docs/RELEASES.md` admits this: *“until the package exists on PyPI those instructions are aspirational.”*
- Trusted Publishing workflow exists; first publish not done.
- CLI default `--format` is `text` (U/P/E), not the checklist the site promises.

### B. Composite Action (`uses: girnarholdings/TriDelPhi@v3`)

**Implementation: complete. Pin users are told to use: broken.**

`action.yml` is a real composite: setup-python → `pip install $GITHUB_ACTION_PATH` (installs **this ref**, not PyPI) → `scripts/install-ladder.sh` → scan → optional expose → SARIF upload → sticky PR comment → gate last.

Inputs: `path`, `level` (default **3**), `fail-on` (critical), `comment`, `expose` (false, advisory), `pr-annotations` (false), plus SARIF / evidence / trust-lock files.

**Tags that exist:** `v3.1.0`, `v3.0.0-beta`. **`v3` does not exist.** Marketplace search: 0 results. Every advertised `uses: …@v3` (README, Setup Studio, `init --wizard`) fails to resolve. `@v3.1.0` would work.

### C. Setup Studio (`site/setup.html`)

**UX: complete and polished. Output: the broken `@v3` pin.**

Static page: L0–L7 pills (default L3), expose toggle, fail-on, PR comment, `owner/name` → “Create this file on GitHub.” Choices never leave the browser. Does **not** write the fix-bot workflow (terminal wizard can).

First control is *“Hardening ladder level.”* Expose is “Extras,” advisory, never fails the build. A vibe coder who asked “is my app leaking?” gets a CI bill of materials.

### D. `tridelphi expose`

**Complete as a static auditor.** Categories A–G (`expose.py`): source maps + client secrets (incl. AI keys, `NEXT_PUBLIC_` / `VITE_`), password hashing, PII/localStorage, open DBs, minification note, committed creds, Firebase `if true` / public buckets. Honest scope line every run.

Action path is **advisory** (`--fail-on none`) and only sees build output already in the checkout. Default `init` workflow comments the expose block out.

### E. Related on-ramps

| Path | Completeness |
|---|---|
| `tridelphi init` (no wizard) | Writes a **~140-line transparent pipx workflow** + `tridelphi-fix.yml`. Scan is **core-only**. Both `pipx install tridelphi` → fail until PyPI exists. |
| `tridelphi init --wizard` | Writes `@v3` action workflow (broken pin) + optional fix-bot (still pipx). Four questions still say “trust-lock,” “SAST,” “severity.” |
| `tridelphi fix` / `guard` | Complete. 3 auto-fixers only (`env-indirect`, `drop-untrusted-ref`, `narrow-trigger`); snapshot → re-scan → rollback. Ladder findings are print-only. |
| `tridelphi privatize` | Complete locally. Consent-gated, refuses `--yes`, refuses if expose finds a shipped secret, verify-or-revert. **Not in the Action.** Wheel does not ship `scripts/`. |
| Cloudflare Worker `bot/` | Real, allowlist-fail-closed, no code read. Power-user only. |

**Gap:** a vibe-coder who follows the site's three steps hits a PyPI 404 or an unresolved `@v3`. The engineer who clones and `pip install -e .` gets a serious tool. The marketing path and the working path are different people.

---

## 4. First-run as a new vibe coder (what actually happened)

Persona: just shipped a Next.js app with Cursor/Claude. Friend said “run TriDelPhi, it tells you if you leaked stuff.” Does not know SARIF, in-toto, OIDC, Agents Rule of Two, or pwn-request. Barely knows GitHub Actions.

### 60-second impression

- **Website: stay.** “Stop strangers from tricking your robots into stealing your keys.” Smoke-detector metaphor. Three pictures. Free, nothing leaves the machine.
- **GitHub README: bounce.** Opens with *“A static Agents Rule of Two analyzer for GitHub Actions.”* Then mermaid graphs, U ∩ P ∩ E, SARIF 2.1.0, “per-job capability graph,” “restore-semantics moat.” The install box is the only part a vibe coder understood.

If a friend sends the **site**, they stay. If they send the **repo**, they close the tab.

### Install attempt (exact order)

| Command | Result |
|---|---|
| `pipx install tridelphi` | `pipx: command not found` |
| `uvx tridelphi --help` | `tridelphi was not found in the package registry` |
| `pip install tridelphi` | `externally-managed-environment` (PEP 668) |
| `python3 -m venv … && pip install tridelphi` | `No matching distribution found for tridelphi` |
| `curl` to `pypi.org/pypi/tridelphi/json` | **HTTP 404** |

The website, README, and Setup Studio all say `pipx install tridelphi`. The package is not on PyPI. The v3.1.0 GitHub release has **zero downloadable files**.

The only working install (not documented) was:

```console
pip install git+https://github.com/girnarholdings/TriDelPhi.git
```

That installed `tridelphi 0.2.0`. A normal person hits the 404 and quits. Call it minute 8.

### First command

`tridelphi --help` is a wall: `--sarif-file`, `--write-baseline`, `--level {1..7}`, `--evidence-file`, `--trust-lock`, `--relock`, `--with-zizmor`, `--coverage` (Uber ADR).

`tridelphi .` on a fake Next app with one dummy workflow:

```
tridelphi 0.2.0 · Agents Rule of Two · 1 workflow, 1 job, 0.0s, offline
  0 critical · 0 warning · 0 note
  no findings — every job holds at most two of three capabilities
```

“At most two of three capabilities” is not a sentence a vibe coder can act on.

Then the friendly format:

```
tridelphi . --format checklist
```

```
✅  Can a stranger trick a robot into leaking your keys?      all clear
⬜  Any passwords left sitting in your files?                 not run — add --level 1
⬜  Any known-broken building blocks in use?                  not run — add --level 2
…
Result:  ✅  YOU'RE GOOD — every check passed.
```

The fake app had a Stripe key in `.env` with `NEXT_PUBLIC_`, open Firestore rules (`allow read, write: if true`), and `postgres`/`postgres` on port 5432. The checklist said they were good because it never looked at the app. Empty boxes are easy to ignore when the banner is green.

### `expose` on the fake app

This is the part that delivered. Exit code 1. Output felt like a friend:

- **NEXT_PUBLIC_ keys** — named the file and line, said the prefix *puts the key in the browser*, told them to drop the prefix, read it on the server, and rotate it.
- **Source map** — “anyone who loads your site can reconstruct your repository,” plus the exact Next/Vite knobs to turn maps off.
- **Open Postgres** — bind to `127.0.0.1` or drop `ports:`, don't use the default password.
- **Firestore `if true`** — “anyone, authenticated or not, can read and write your database,” with a starter condition.

Two nits:

1. It flagged `NEXT_PUBLIC_FIREBASE_API_KEY` the same way as the Stripe secret. The *website* said Firebase web keys are supposed to be public and would be left alone. Contradiction.
2. “Are your keys or cloud config committed to the repo? all clear” — while `.env` is sitting right there. The keys were caught under a different heading, but that checkbox is a lie to the eye.

### Setup Studio / `init`

- **Setup Studio as a page:** the onboarding a vibe coder actually wanted. Click, tick “Audit what I ship,” paste `owner/repo`, hit Create. They could commit it without understanding Actions. The generated file is short — and pinned to the broken `@v3`.
- **`tridelphi init` (no wizard):** wrote two files and a nice “commit and push” checklist. The workflow is ~140 lines of `pipx install tridelphi`, SARIF upload, harden-runner, “pwn-request,” “egress telemetry.” That `pipx` line **fails in GitHub Actions** because the package isn't on PyPI.
- **`tridelphi init --wizard`:** much better. Four questions, writes the short `@v3` action file. Still cannot run the wizard if they cannot install the CLI.

### Emotional arc

curious → confused → pissed → briefly delighted → false-safe → overwhelmed → quit (keep `expose` if install ever works)

Would they add this to the next vibe-coded project?

- **Yes** to running `tridelphi expose` before pushing a Next app. That output earned it.
- **No** to the advertised install, because it does not work.
- **No** to default `tridelphi .` / the green “YOU'RE GOOD,” because it would have given false confidence.
- **Maybe** to Setup Studio's one-line Action, if a friend sat with them. They would not have gotten there alone.

---

## 5. Strengths that are real

1. **The join is the product.** Per-job U∩P∩E, not per-line lint. `rule.py` + `docs/OSS_LANDSCAPE.md` §2: zizmor / poutine / octoscan do not do this. Cross-job `needs:` + artifact taint is the class per-file tools miss.

2. **Restore-semantics moat.** `data/agent_signals.yml` + `detect_agent_ingress.py`. Claude Code Action restores `.claude/`, `CLAUDE.md`; `AGENTS.md` / `.cursor/rules` stay attacker-controlled. Filename scanners get this wrong both ways (`DECISIONS.md` §2).

3. **Noise discipline is designed, not hoped.** Fork-PR token is read-only (`DECISIONS.md` §0.1). Assumed privilege never becomes CRITICAL. P∩E on a trusted trigger is silent. E is graded, not the gate.

4. **Cheapest-fix + verified auto-fix.** `rule.py` picks which of U/P/E to strip. `apply.py`: snapshot → transform → re-analyze → rollback. Three mechanical fixers only; will not leave a file changed *and* still vulnerable.

5. **Honesty as a product feature.** `expose` says a clean result is not a pentest. Firebase web key / Supabase anon = note; `service_role` = critical. `privatize` refuses to hide a secret. L7 proposal records what L4/L6 do *not* do.

6. **Real-world regressions.** `docs/REAL_WORLD.md` + `tests/test_realworld.py`: pwn-request (MITRE / Splunk / spotipy shape) and tj-actions SHA-swap via trust-lock.

7. **Output contract.** SARIF 2.1.0, line-independent fingerprints, `--min-severity` ⊥ `--fail-on`, checklist for humans / SARIF for the Security tab.

8. **They attack their own tool.** Last ~15 commits (Aug 11–14) are audit remediations: fix-bot auth bypass, detection FNs, secret-safety + comment injection, privatize hardening. That is a live security-engineering culture, not brochureware.

9. **`expose` voice.** The “Do this:” lines are the best writing in the product. A vibe coder knew what to do next. That is rare.

---

## 6. Friction, incompleteness, contradictions

### Distribution (fatal for advertised first run)

- Site, README, Setup Studio, default `init` all say `pipx install tridelphi`. **PyPI 404.** `docs/RELEASES.md` knows this; the site does not.
- Everyone says `uses: girnarholdings/TriDelPhi@v3`. **No `v3` tag.** Only `v3.1.0` and `v3.0.0-beta`.
- Two version namespaces, undocumented to users: package `0.2.0` vs Action `v3.1.0`.
- This repo's dogfood workflows install from checkout; users get the registry path that does not exist.

### Default-path contradictions

- README ladder: *“Level 3 is the default.”* CLI: no `--level` ⇒ core only. Action: level 3. `init` (no wizard): core only via pipx. `init --wizard` / Studio: Action @v3 level 3.
- `docs/REPO_SETUP.md` still documents `@v1` / `v1.0.0`. README / Studio use `@v3`.
- Site L3 is both “the Rule-of-Two check” *and* “zizmor workflow lint.” Internally L3 = zizmor + core always-on.
- CLI default format is `text`. Site demo is the checklist.

### `init` vs Action quality

- Default `init` workflow: `pipx install` (broken), **no `--level`**, harden-runner in **audit**. Fix-bot template: `pipx` + PyPI allowlist (also broken until publish).
- Wizard / Studio: `@v3` (broken pin) but otherwise the better path (checksum-pinned ladder, no PyPI).

### Ladder honesty gaps (their own L7 audit, still true)

- L4 Scorecard maxes at `warning` ⇒ **never gates** under default `--fail-on critical` (`docs/L7_PROPOSAL.md` §1.2).
- External findings **cannot be baselined** (`cli.py`) — L2/L5 day-one red on a messy repo.
- L6 attest is write-only / self-asserted env (`GITHUB_SHA`); L7 verifies *consumed actions*, not the L6 statement itself.
- Missing scanner reports “not run” (⬜), which reads like a clean skip next to a green banner.

### Product scope vs original brief

- `docs/BRIEF.md` §0: do **not** build gate / attest / init / ladder / frontend. All of that shipped. Brief is now historical and still in `docs/` as if current.
- `OSS_LANDSCAPE.md` §4 still says “one flat list of contexts with no edges”; `DECISIONS.md` §3 and D3 added edges. Stale.

### Auto-fix coverage is narrow

- Only 3 rule kinds. Cross-job taint, agent-config-ingress, env-file-injection, L1–L5: human or `guard` print-only. The site implies “or just say yes and it's fixed.”

### `expose` limits they disclose but users will miss

- Needs `dist/` / `build/` / `out` / `public` / `.next` **in the checkout**. Action says “build first or it finds nothing.”
- Static only; open-DB finding may already be firewalled.
- Semgrep rung optional; without it, categories B/C shrink.
- Firebase web-key handling contradicts the site copy (see first-run).

### `privatize`

- Not in Action (correct). Extra npm toolchain. Wheel does not ship `scripts/`.
- Honest engineering, wrong acquisition. Vibe coders will hear “hide my code/keys.”

### Docs / site gaps a new user hits

1. No working install on the homepage. Three-step block is a 404.
2. No “if PyPI isn't up, do this” (`pip install git+https://…@v3.1.0` or Action `@v3.1.0`). `RELEASES.md` has the truth; it is not linked from the site.
3. No Getting Started that matches a working pin. README jumps problem → architecture mermaid → ladder → expose.
4. `docs/` is builder/internal, not user docs: `BRIEF.md` (obsolete scope), `DECISIONS.md`, `KICKOFF.md`, `L7_PROPOSAL.md`, `MARKETPLACE.md` (unpublished), `REPO_SETUP.md` (stale `@v1`).
5. No CONTRIBUTING.md / changelog. v3.1.0 release body is empty.
6. Two languages, no bridge. Site is ELI5; README is capability-graph / ADR / SARIF. A vibe-coder who clicks GitHub from the site lands in a 43 KB engineer README.
7. Setup Studio “Create on GitHub” assumes `main` and does not mention code-scanning enablement.
8. L numbering on the site will not match `--level` / `--credits`.
9. Zero social proof. Site claims MITRE / Splunk / spotipy *shape* (true as fixtures), which a skim reads as “we scanned those orgs.”
10. `SECURITY.md` is good and easy to miss; site does not link it.

### Jargon a vibe coder quoted, not paraphrased

Agents Rule of Two · U ∩ P ∩ E · pwn-request · SARIF 2.1.0 · per-job capability graph · restore-semantics moat · in-toto evidence statement · trust-lock / the pawl · OIDC identity · author_association gate · hardening ladder / rung · Uber ADR's 17 agent threat techniques · egress-policy: audit · github-advanced-security[bot] · “every job holds at most two of three capabilities”

The site has “Scary words, decoded.” It is not on the README. `--help` does not point at it.

---

## 7. Competitive set — unique vs commodity

| Layer | Commodity (they wrap / compete with) | Unique to TriDelPhi |
|---|---|---|
| L1 secrets | gitleaks, GitHub secret scanning, TruffleHog, Snyk | None (they escalate gitleaks to error) |
| L2 deps | osv-scanner, Dependabot, Snyk | None |
| L3 workflow lint | **zizmor**, actionlint, octoscan, poutine | **U∩P∩E join + cheapest-fix + platform-truth P** |
| Agent CI | zizmor `#1605` (unassigned), Trail of Bits skill | **Per-action restore-semantics table** |
| Cross-job | CodeQL Actions pack; Raven (Neo4j, needs network) | Offline in-process edges + artifact channel |
| L4 posture | OSSF Scorecard | Wrapper only; decorative for gating |
| L5 SAST | semgrep, CodeQL, Snyk Code | Wrapper only |
| L6 attest | in-toto, `attest-build-provenance` | Split scan/gate; evidence is weak (self-asserted) |
| L7 trust | pinact, Dependabot SHA pins, SLSA | **Committed trust-lock pawl** (tj-actions class) |
| Shipped app | Snyk, Semgrep, secretlint, git-secrets | **`expose` honesty** + **honest obfuscator** |
| UX | SARIF in Security tab | Checklist / sticky comment / Setup Studio / vibe-coder English |

**Positioning that holds:** “mechanize Meta's Rule of Two on a GHA job” + restore table + offline join.

**Positioning that does not:** “a whole security team, 6+ tools, one command” — that is a wrapper. zizmor + gitleaks + osv + Scorecard + semgrep already exist, and GitHub code scanning already merges SARIF.

Closest peers: **zizmor** (highest overlap, no join), **octoscan** (offline, no agents), **Raven** (graph, needs Neo4j), **gato-x** (offensive, needs token).

### What a vibe coder already uses or ignores

| Habit | Why they bounce off you |
|---|---|
| `create-next-app` / Vite already gitignores `.env*` | “I already don't commit `.env`.” `expose` still wins on `NEXT_PUBLIC_` and committed non-template `.env` — you don't say that on the first screen. |
| GitHub secret scanning / push protection | Free, zero install, blocks `sk-` on push. You are a *second* secret scanner (L1 = gitleaks) plus a YAML tool. |
| Vercel / Netlify env UI | “Secrets live in the dashboard.” Does not catch `NEXT_PUBLIC_OPENAI_KEY` or source maps. You do. Not the default path. |
| Cursor / Claude (“don't commit secrets”) | The agent that wrote the leak is also their security reviewer. Circular. `expose` as a Cursor skill would beat a Python CLI. |
| Firebase / Supabase dashboard warnings | They trust the host. You catch `allow if true` and `service_role` in the bundle — complementary, undiscoverable. |

What they would `npx` and never leave Node for: `npx secretlint`, `trufflehog filesystem .`, `gitleaks detect`, `git-secrets`.

For the vibe job-to-be-done, you are a better-honest `secretlint` + Firebase / Supabase / source-map linter. That is a feature, not a company, unless it is the on-ramp to Product A when they later add an agent workflow. For Product A, the join + restore table is still unclaimed. That is the business.

---

## 8. Would new vibe coders benefit today?

**No — not as packaged. Conditional yes for `expose` only, and only after they survive install.**

Conditions that currently fail:

1. **The advertised install does not work.** Site, README, and the workflow `init` writes all say `pipx install tridelphi`. PyPI is 404. First command is a lie.
2. **The default command is the wrong product.** `tridelphi .` scans `.github/workflows`. No workflows → *“no .github/workflows found — nothing to scan”* and exit 0. A typical Vercel / Firebase app has zero Actions. The command they need is a sibling they have to already know.
3. **Runtime is Python 3.11+ / pipx.** Vibe stack is Node. There is no `npx` path.
4. **`expose` in CI is opt-in, advisory, and blind unless you built first.** `action.yml`: default `expose: "false"`; *“never fails the build”*; *“run your build step first or it finds nothing.”*
5. **CLI default format is `text` (U/P/E), not the checklist the site promises.**

The job `expose` actually does (and it is real):

- Committed `.env` with `OPENAI_API_KEY=sk-…` (literally called “the classic vibe-coder mistake”)
- `NEXT_PUBLIC_` / `VITE_` / `REACT_APP_` prefix shipping a real key
- Source maps with `sourcesContent`
- Firebase `allow … : if true`; Supabase `service_role` in the bundle
- Compose DB on a public port with password `postgres`
- Private keys, SA JSON, AWS creds in tree

A vibe coder with no Actions, no Python, and a Vercel deploy gets: broken `pipx`, empty core scan, and a feature they never find. Benefit today ≈ 0.

A vibe coder who already has Python, runs `tridelphi expose` in a repo with a committed `.env` or `firestore.rules`: **yes, immediately useful.** That person is rare if they arrived via the homepage CTA.

---

## 9. Top 5 drop-off reasons

Ranked by how fast they bounce.

1. **Install is broken and alien.** `pipx install tridelphi` is step 1 on the site. Package is not on PyPI. Even if it were: vibe coders do not have `pipx`. No `npx`, no binary, no Cursor one-click. Fatal.

2. **README is a 43 KB security-engineer paper.** H1: *“A static Agents Rule of Two analyzer for GitHub Actions.”* First GitHub impression. They will not scroll to the “vibe-code” paragraph.

3. **Default command audits CI they do not have.** Empty “nothing to scan” / green “YOU'RE GOOD” on a Next app. The fear they brought (leaked key / open Firebase) is a checkbox named `expose` on a page titled “Hardening ladder level.”

4. **L1–L7 + Setup Studio is a purchasing decision, not onboarding.** First control is ladder level. They asked “is my app leaking?” and got a CI bill of materials.

5. **“Agents Rule of Two” is not their language, and the site's translation still dumps them into it.** Homepage does the helper-robots metaphor well. Then: `pipx`, workflow file, Security tab, SARIF, “one uses: line.” The metaphor sells Product A. They came for Product B.

Honorable mention: Action YAML + permissions + “turn on code scanning.” Many vibe apps never open `.github/`. Also: package `0.2.0` vs Action `v3.1.0` vs site “v3.1.0” — looks unfinished. 0 stars, no description, no topics: no social proof.

---

## 10. Proposed fixes

### P0 — this week (docs / UX / positioning, no big build)

#### P0-1. Make the advertised install true

- **Problem:** `pipx install tridelphi` 404s; generated fix-bot cannot install itself (`RELEASES.md`). `uses: …@v3` does not resolve.
- **Change:** Publish to PyPI via the Trusted Publishing flow already written, **or** change every CTA to `pipx install git+https://github.com/girnarholdings/TriDelPhi.git` until it is live. Create / move a `v3` tag to current `main` (or change every pin to `@v3.1.0`). Set repo `description`, `homepage`, topics (`security`, `github-actions`, `secret-scanning`).
- **Why:** First command cannot be a 404.
- **Effort:** S (git URL + tag) / M (real PyPI).

#### P0-2. Two-door homepage and README

- **Problem:** Site sells robots; README sells Rule of Two; vibe job is buried.
- **Change:** README top 40 lines: (1) one-sentence what, (2) **two doors** — “I shipped an app” → `expose`; “I have GitHub Actions / AI bots” → `tridelphi .` + `init`. Move U/P/E, ladder, SARIF, L7 below a fold. Site hero: keep the robots line *or* the leak line — not both as one product.
- **Why:** Current first impression is for the user you do not have.
- **Effort:** S.

#### P0-3. If there are no workflows, do not say “nothing to scan” / “YOU'RE GOOD”

- **Problem:** Default command fails the vibe job silently (exit 0) or prints a green banner after only checking robots. Checklist with five empty “not run” boxes and a green banner is how someone ships a leaked Stripe key.
- **Change:** No `.github/workflows` → print: “No GitHub Actions found. Your app may still be leaking. Run: `tridelphi expose`” and optionally run it. If workflows exist but expose / L1 did not run, the banner must say “we only checked your GitHub robots; run `tridelphi expose` for the app.” Never print YOU'RE GOOD when you didn't look.
- **Why:** This is the entire first-run for a Next app.
- **Effort:** S.

#### P0-4. Default local format = checklist

- **Problem:** Site promises plain English; CLI default is U/P/E text (`cli.py`).
- **Change:** `--format checklist` as default for TTY; keep SARIF for `--sarif-file` / CI.
- **Why:** `DECISIONS.md` §5 already made this call for SARIF-vs-text. Finish it.
- **Effort:** S.

#### P0-5. Setup Studio: two paths, expose not a footnote

- **Problem:** First control is L0–L7. Expose is “Extras.”
- **Change:** Path A “Check what I ship” → generate a short workflow that only runs `expose` (and say it is advisory). Path B “Harden my GitHub robots” → current ladder. Default Path A if they came from the vibe headline. Pin the generated `uses:` to a tag that exists (`@v3.1.0` or a real `v3`).
- **Why:** Studio is the one-click you already built; it currently teaches the ladder.
- **Effort:** S–M.

#### P0-6. Make `init` write the short Action file

- **Problem:** Default `init` writes a ~140-line `pipx` workflow that is unreadable and currently broken. Wizard / Studio file is something a vibe coder would actually commit.
- **Change:** `init` (no wizard) writes the same short composite-action file as Studio / `--wizard`, pinned to a resolving tag. Keep the long transparent workflow behind an explicit flag (`--transparent` / `--from-source`).
- **Why:** “One command, never think about it again” currently installs a broken robot.
- **Effort:** S.

#### P0-7. Stop leading with `privatize`

- **Problem:** Honest obfuscator is correct engineering and wrong acquisition.
- **Change:** Keep it, bury it. Never pair it with the hero.
- **Why:** You already refuse to hide secrets; don't put the temptation in the first scroll.
- **Effort:** S.

#### P0-8. Fix expose contradictions the first-run hit

- **Problem:** Firebase web key flagged like a Stripe secret; “keys committed?” checkbox all-clear while `.env` is in the tree.
- **Change:** Align Firebase / Supabase public-by-design keys with the site copy (note, not critical). If a key was caught under another heading, do not mark the committed-keys row all-clear — point at the other finding.
- **Why:** The “Do this:” voice is the best writing in the product. Contradictions burn that trust.
- **Effort:** S.

### P1 — next month (unlock vibe adoption)

#### P1-1. Node-native entry

- **Problem:** Python is a hard stop.
- **Change:** `npx tridelphi` wrapper (download/run the wheel, or a small JS driver that shells the same CLI). Cursor rule / Claude skill: “before you commit, run this.”
- **Why:** Meets them in the toolchain they already trust.
- **Effort:** M.

#### P1-2. Expose-first local default + optional fail on criticals

- **Problem:** The useful command is hidden; CI expose never fails.
- **Change:** `tridelphi` with no args in a JS app repo → expose (plus core if workflows exist). Local expose keeps `--fail-on critical`. CI can stay advisory *if you say why* (static ≠ live). Offer `--fail-on critical` for expose as an explicit Studio toggle, default off, labeled “I want the build red if a key is in the bundle.”
- **Why:** A tool that never fails is a report they ignore.
- **Effort:** M.

#### P1-3. Framework-specific first report

- **Problem:** Generic 7-category checklist still feels like a scanner.
- **Change:** Detect `next.config` / `vite.config` / `firebase.json` / `supabase` and lead with *their* risks: `NEXT_PUBLIC_`, source maps, RLS / `if true`, `service_role`. One paragraph, then the rest.
- **Why:** “This is about *your* Next app” beats “Category A–G.”
- **Effort:** M.

#### P1-4. Marketplace listing with two taglines, security-engineer primary

- **Problem:** 0 Marketplace results; listing will render the 43 KB README.
- **Change:** Publish after P0-2. Tagline can mention the ship-audit; README top must not drown a platform buyer.
- **Why:** `uses: girnarholdings/TriDelPhi@v3` is how Product A distributes.
- **Effort:** S (process) after P0.

#### P1-5. One “vibe CI” workflow, no ladder

- **Problem:** `init` writes harden-runner + pipx + SARIF upload + fix-bot + commented expose.
- **Change:** `tridelphi init --app` writes: checkout → build → `expose` → sticky comment. No L4–L7. Fix-bot optional.
- **Why:** Current init is a platform gift-basket.
- **Effort:** M.

### P2 — later (moat / platform)

#### P2-1. Keep and publish the restore-semantics table

Precision number on a real corpus (`DECISIONS.md` §8). Comment on zizmor #1605. This is the moat. Effort: L.

#### P2-2. Do not become “6 tools in one command”

The site already pitches “a whole security team.” That is Semgrep + Snyk + Scorecard's market. You will lose. Ladder as *optional depth* for the wedge user is fine. Effort: discipline, not build.

#### P2-3. GitHub App / hosted bot only after local + Action work

`bot/` already exists. Vibe users who never open Actions might click an App. Only if expose-first is proven. Effort: L.

#### P2-4. Agent-session / MCP scanning is a different product again

Do not add a third identity this quarter.

---

## 11. Messaging

**Primary on the site (acquisition): vibe coder.** That is who the live homepage is already performing for. Do not make it primary on GitHub / Marketplace / CLI — that is where the paying / serious wedge user shows up.

**Vibe (site primary)**

- **Headline:** See if the app you just shipped is leaking its keys, its database, or its source.
- **Subhead:** One command, on your machine. It reads your repo and tells you in plain English — rotate this, move that server-side, lock that Firebase rule. It will not pretend obfuscation is security.

**Security / platform (README + Marketplace + `action.yml` primary)**

- **Headline:** Find the GitHub Actions job where a stranger's comment becomes RCE.
- **Subhead:** Static Agents Rule of Two: the one job that reads untrusted input, holds secrets, and can reach the network. Offline, SARIF, cheapest fix named. Optional ladder around it.

If you invert this (vibe-primary on GitHub), you compete with `npx secretlint` and look unserious to the only user who cannot get this join anywhere else.

---

## 12. Packaging advice

**Keep one CLI. Ship two entry points. Make first-run expose-first when that is the repo.**

| Option | Verdict |
|---|---|
| One CLI, one default (`tridelphi .` = Rule of Two) | What you have. Vibe bounce. |
| Two products / two names | Premature. `expose` is not a company yet. |
| **One CLI, two doors, smart default** | Right. No workflows + JS app → expose path. Workflows / `--init` → Rule of Two path. Studio mirrors the doors. |
| Expose-only onboarding, hide the core | Wrong. Throws away the moat. |

Do **not** make `privatize` an entry point. Consent-gated, verify-or-revert is correct; it is not onboarding.

Action stays one `uses:` line for Product A. Add a documented `expose: 'true'` recipe, not a second action, until usage proves a split.

---

## 13. What not to do

- **Do not dumb down the core.** Restore-semantics, platform-true privilege, cheapest-fix, quiet on compliant P∩E deploy jobs — that is why a security engineer keeps it. Translate the *door*, not the detector.
- **Do not hide honesty about obfuscation or static limits.** `privatize` “is not security” and expose “is not a pentest” are load-bearing. The naïve version of this feature *makes people less safe*. Keep saying rotate + move server-side.
- **Do not claim “one line to turn on” while PyPI is empty and init writes two workflows plus a commented expose.**
- **Do not teach L1–L7 to people who asked if their key is in the repo.** The ladder is a power-user depth control, not a first impression.
- **Do not make vibe-coder the company identity.** You will become a nicer secretlint and zizmor will eventually grow an agent rule. The join is the business; expose is the on-ramp / adjacent utility.
- **Do not wrap more scanners to look complete.** `BRIEF.md` already forbade this instinct. The site's “6+ tools → 1 command” is the opposite of the brief.
- **Do not auto-fail vibe CI on expose until you have FP data.** Advisory-by-default is correct for a static DB / Firebase read. Just don't hide the command.
- **Do not ship `privatize` as “protect my IP” marketing.** OOPSLA 2026 OBsmith finding is already in the README; respect it in the hero.

---

## 14. Suggested implementation order

If you only do five things:

1. Publish to PyPI **or** change every CTA to a working git install. Create the `v3` tag (or retarget every pin to `@v3.1.0`).
2. Two doors at the top of the README and site.
3. Never print YOU'RE GOOD when you didn't look at the app.
4. Default the local TTY format to the checklist.
5. Make Setup Studio default to “check what I ship,” and make `init` write that short Action file pinned to a tag that exists.

Everything else can wait. The product already knows how to talk to a vibe coder. That's `expose`, the website, and Setup Studio. Everything else is still talking to a security engineer, and the front door is locked.
