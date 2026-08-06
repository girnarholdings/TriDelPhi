# Decision record — post-review plan refinement

Four hostile reviewers attacked the plan on non-overlapping surfaces: threat
model, strategy/moat, code architecture, adoption/noise. Every load-bearing
factual claim below was independently verified by the main thread before being
accepted. This document records what changed, what I defended, and why.

**Status: the brief's scope, phase order, and offline constraint survive. The
detection model, the §7 interfaces, and the acceptance bar do not.**

---

## 0. The three things that were fatal

Each of these would have shipped. Each was caught by a different reviewer.

### 0.1 The tool flagged the most common job on GitHub as CRITICAL

Brief §3 says the repo default permission is treated as **write-all unless told
otherwise**, and that fork-reachable `pull_request` confers U, and that any
`run:` step confers E. Compose them:

```yaml
on: [push, pull_request]
jobs:
  test:
    steps: [{uses: actions/checkout@v4}, {run: npm ci && npm test}]
```

U ∧ P ∧ E ⇒ **CRITICAL**, on a job with no secrets and a read-only token.

**Verified:** for `pull_request` from a fork, `GITHUB_TOKEN` is read-only and
repository secrets are not passed — *regardless of repo settings*. The write-all
assumption is not merely conservative, it is **wrong for exactly this case**.

An honest count on a median unhardened repo (6 workflows / 20 jobs) put **12
criticals and 5 warnings** on the board, including GitHub's own recommended
CodeQL workflow. zizmor on the same repo emits 3–8 low-severity findings. That
is the comparison a user actually makes, and we lose it 4× on volume and 10× on
alarm.

**Fixed by:** the platform-truth rule (fork `pull_request` ⇒ P is impossible
from the token), and the observed-vs-assumed split (§1.2).

### 0.2 The acceptance test was unsatisfiable by construction

Brief §3 lists `workflow_run` as a dangerous trigger. `fixture-adversary.md`
mandates a `clean/` fixture that is *the officially recommended hardening
pattern* — privileged work split into a `workflow_run` job — and requires it to
produce **zero findings**. That fixture is U(trigger) + P(secrets) + E(run) ⇒
CRITICAL. `test_thesis.py`, the definition of done, could never go green.

The predictable fix — drop `workflow_run` from the trigger table — opens the
real artifact-poisoning chain. Both settings of the only available knob are
wrong, which means the knob was the wrong shape.

**Fixed by:** `workflow_run` confers U **only if the job consumes upstream
state** (§1.1).

### 0.3 The moat detector fired on the hardened configuration

The agent-config ingress detector — the one KICKOFF.md says never to cut — was
specified as: agent step + instruction file exists in repo + trigger is
fork-reachable.

**Verified two independent breakages:**

1. **Ref direction.** `actions/checkout` with no `ref:` on `pull_request_target`
   checks out **base**, not PR head. That is the *recommended safe pattern*, and
   the detector as specified fires on it and cannot distinguish it in its
   message from the exploitable variant.
2. **`claude-code-action` already mitigates.** It restores `.claude/`,
   `.mcp.json`, `.claude.json`, `CLAUDE.md`, `CLAUDE.local.md`, `.gitmodules`,
   `.ripgreprc`, `.husky/` **from the base branch**, deletes paths absent on
   base, and parks PR versions in `.claude-pr/` as reference-only. Our flagship
   fixture reproduces a configuration that is already safe.

**Fixed by:** restating the moat as **reachability**, with per-action restore
semantics (§2).

---

## 1. Detection model changes

### 1.1 U becomes precondition + mechanism

A dangerous trigger is now a **precondition**, not a source. U fires only when
attacker-controlled bytes have an actual path into the job:

| Mechanism | Fires U |
|---|---|
| Untrusted expression interpolated into an **interpreter sink** | yes |
| `actions/checkout` resolving to an untrusted ref | yes |
| Agent step operating over an untrusted working tree | yes (§2) |
| `workflow_run` job consuming upstream artifacts / `head_sha` | yes |
| `needs.<job>.outputs.*` where the upstream job is U-tainted | yes (§3) |
| Dangerous trigger with none of the above | **no** — precondition only |

### 1.2 Observed vs assumed privilege

Every `CapabilityHit` now carries `observed: bool`. A hit is *observed* when the
evidence is written in the file (a `secrets.X` token, an explicit `write` scope,
a self-hosted runner label). It is *assumed* when we are guessing at repo
defaults.

**An assumed hit can never produce a CRITICAL.** U(observed) ∧ P(assumed) ∧
E(observed) downgrades to a warning under its own rule ID, whose message hands
the user a one-line `permissions: contents: read` diff that both fixes the
ambiguity and hardens the repo. Noise converted into a nudge.

Platform truths override assumptions outright: fork `pull_request` ⇒ no secrets,
read-only token, full stop.

### 1.3 E is graded, never the gate

The prosecution: `run:`-implies-E is true for ~90–95% of real jobs, so U∩P∩E
collapses to U∩P and the third axis is decorative. The defense (brief §9):
narrowing E by grepping `curl` is trivially evaded — `run: node build.js` where
`build.js` fetches is invisible — and on a hosted runner, shell *is* egress.

**The defense is right about detection and wrong about product semantics.** So:
detection stays broad; the *use* changes.

- `E2` — observed egress primitive (`curl`/`wget`/`nc`, `git push`, publish
  actions, `upload-artifact`, agent with `Bash`/`WebFetch`)
- `E1` — generic shell
- `E0` — no shell, only known-read-only `uses:`

Tier ranks criticals; it does not admit them. And the README states the
prevalence out loud. With this audience, publishing the base rate buys
credibility; concealing it is what would make the triad framing dishonest.

### 1.4 Warnings signal proximity, not presence

The sharpest single catch of the review: we positioned on mechanizing Meta's
Rule of Two — *at most two of three* — and then emitted a WARNING for holding
exactly two. **We were flagging the framework's compliant state.** Anyone who
knows the framework, which is precisely our target audience, spots that in
thirty seconds.

| Shape | Emit |
|---|---|
| U ∧ P ∧ E, all observed | CRITICAL |
| U ∧ P, no E — one `run:` line away | WARNING |
| U ∧ E with a secret reachable in scope | WARNING, naming the secret |
| P ∧ E on a trusted trigger, in a file that *also* has a fork-reachable trigger | WARNING |
| **P ∧ E on a wholly trusted trigger** | **SILENT** (see §1.5) |
| U ∧ E, no secret anywhere in the file | note, off by default |

### 1.5 Ruling: P+E on a trusted trigger is SILENT

Both `fixture-adversary` and `capability-detective` were told to escalate this
to the main thread — a deadlock by construction, since each may assume the other
resolved it. Ruling, pre-decided:

**`push: [main]` + `secrets.DEPLOY_KEY` + `run:` emits nothing at default
verbosity.** It is the definition of a deploy job; warning on it means warning
every repo that ships software, for shipping software. It is Rule-of-Two
compliant. Every exploit in the threat model requires U. A finding whose
cheapest fix is "nothing" is not a finding.

Surfaced as `tridelphi/privileged-trusted-context` at `note` level, off by
default, never counted toward the exit code, with a summary rollup line.

### 1.6 Other detection corrections

| Change | Was |
|---|---|
| **Sink classification.** `${{ }}` into `env:` is the *documented mitigation* — never a U hit unless the body does `eval`/`$(…)`/`$GITHUB_ENV`. Interpolation into a data input (`actions/cache` `key:`) is a taint carrier, not injection. | Scanned `run:` and `with:` undifferentiated — flagged the official fix |
| **`secrets` as a context expression**: dot, bracket (`secrets['X']`, `secrets[matrix.k]`), and `secrets: inherit`. Plus workflow-level `env:`. | `secrets\.\w+` regex — missed all four |
| **Self-hosted runner ⇒ P** (observed). The runner is the privileged asset. | No slot in the model for the highest-severity uncovered class |
| **Local composite actions and local reusable workflows are resolved** — `uses: ./...` is inlined. | Files on disk went unread; a caller job with no `steps:` scored E=false, P=false |
| **`.claude/settings.json` hooks ⇒ own unconditional CRITICAL.** A fork PR adding a `PreToolUse` hook is direct shell execution with no LLM in the loop. | Not modelled |
| **Glob segments in the untrusted-expression matcher** (`github.event.*.body`, `commits.*.message`) | Flat string list |

---

## 2. The moat, restated

**Old:** agent step + known instruction filename exists + fork-reachable trigger.
Filename enumeration — the exact weakness we criticized in zizmor, and it fires
on the safe config.

**New:** *an agent-invoking step executes against a working tree derived from an
untrusted ref, after accounting for what that specific agent action restores
from base.*

This is strictly more general, immune to the filename arms race, and it catches
the dominant real attack — injection via a comment in a `.ts` file in the diff,
with zero `github.event.*` and zero agent-config files touched.

The per-action **restore-semantics table** is the thing that compounds. It is
versioned, it decays with every action release, and nobody else maintains one.
`claude-code-action` restores 8 fixed paths — so `AGENTS.md`, `.cursor/rules`,
`.github/copilot-instructions.md` are **not** covered, and `package.json` /
lockfiles / formatter config stay at PR head, meaning a base-branch
`settings.json` that shells out to a package-manager script re-inherits attacker
control. Gemini CLI, Codex, and `run: npx …` have no restore at all.

That is a smaller, sharper, more maintainable moat than the one we claimed. It
is also the only version that survives zizmor merging
[#1605 `agentic-actions`](https://github.com/zizmorcore/zizmor/issues/1605) —
open since Feb 2026, filed by Trail of Bits' CEO, still unassigned.

**Defensibility ordering, inverted** (was: format first):

1. The per-action restore-semantics table + reachability analysis
2. Measured precision on real repos
3. The output format — downstream of adoption, not upstream of it

A properties bag inside SARIF is not a format, it's a comment. Formats become
moats through adoption; we have zero users.

---

## 3. The graph gets edges

`OSS_LANDSCAPE.md` §4 said "one flat list of contexts with no edges." Two
reviewers independently identified that sentence as the weak point — the
strategy reviewer because cross-job composition is the only finding class
genuinely unreachable from per-file analysis (and therefore the only thing
CodeQL's Actions pack, which already tracks taint across steps and jobs, does
not already do), the threat reviewer because without edges "capability graph" is
a per-job boolean AND.

That was my call in the landscape doc and it was wrong. v1 ships:

- **`needs:` edges** with U-taint propagation across job outputs, carrying a
  cross-job reason string.
- **Local `workflow_call` inlining** — `uses: ./.github/workflows/x.yml` with
  `secrets: inherit`.
- **`workflow_run` upstream-consumption detection** (§1.1).
- Remote `uses: org/repo/...@ref` emits `tridelphi/unresolved-context` at note
  level. Silence in a security tool is the worst output; "I could not see inside
  this" is honest and is the natural hook for a future `--online` mode.

---

## 4. Interfaces (§7 replaced)

The old `ExecutionContext.raw: dict` **could not be implemented**. Verified
against ruamel 0.19.1:

- Scalars (`run:`, `uses:`) carry no `.lc` — only `CommentedMap`/`CommentedSeq`
  do. A detector handed a bare `LiteralScalarString` cannot produce
  `CapabilityHit.position`, and the agent briefs forbid it from re-parsing. Both
  agents follow their briefs correctly and deadlock.
- `.lc` is 0-indexed; SARIF `startLine` has `minimum: 1`. Every position off by
  one, and `startColumn: 0` is a schema violation.
- `frozen=True` + a `dict` field ⇒ `hash()` raises `TypeError`, and `__eq__`
  deep-compares YAML bodies so two structurally identical jobs compare equal.

Changes:

| Change | Reason |
|---|---|
| `raw: dict` → `body: YamlNode` | A cursor that returns positioned nodes on navigation. Intra-scalar line math verified **exact** for literal (`\|`) blocks — `cat CLAUDE.md` on content line 1 → source line 12. Folded (`>`) and plain multi-line degrade to the step line; documented contract, and `region.snippet` recovers the precision in GitHub's UI. |
| `field(compare=False, repr=False)` on `body`, `slots=True` everywhere | Restores hashability and identity semantics |
| `tuple[str, ...]` everywhere `frozenset` was proposed | `str`-set iteration is `PYTHONHASHSEED`-randomized. The DoD's "run twice, diff empty" runs in one process — **it can pass while the property is false.** Determinism test now runs two subprocesses with different seeds. |
| `cheapest_fix: str` → `Remediation` struct | Three agents owned one prose string. `fixture-adversary` now asserts `remediation.strip == "P"` — stable and immune to copy-editing. |
| `Finding.primary_position` added | SARIF needed `region.startLine` from a field that did not exist; the sort key was undefined |
| Sort key gains `job_id` | YAML anchors make two jobs share a body and resolve to the same line |
| ~12 fields added to `ExecutionContext` | `effective_permissions`, `permissions_source`, `workflow_env`, `fork_reachable`, `untrusted_worktree`, `needs`, `runs_on`, `is_reusable_call`, `secrets_inherit`, `job_if`, `repo: RepoInventory` … all required by detectors contractually forbidden from parsing files |
| `RepoInventory` type added | The moat detector had **no legal way to read its inputs** |
| `RULES` registry in `model.py` | Rule IDs minted in `rule.py`, rendered in `sarif.py`, asserted in tests — one namespace, no registry, guaranteed drift |
| `api.py` with `analyze()` | `fixture-adversary` is nominally day-one parallel and was blocked on an interface nobody owned |
| Schema moves into `tridelphi/data/` | At repo root it is not in the wheel; `to_sarif` would raise `FileNotFoundError` for every non-editable install. The DoD only tested `pip install -e .` and was structurally incapable of catching it. |
| **PyYAML banned entirely** | It parses `on:` as `True` and `no`/`off` as `False`. ruamel already parses everything; this removes a dependency, which §2.3 says to prefer. |

Split rule IDs (was two catch-alls). The rule ID is the alert name users filter
and dismiss by, so `tridelphi/agent-config-ingress` appearing in a code-scanning
tab is the product's billboard — and it was invisible under a generic
`u-p-e-intersection` label.

---

## 5. Output and adoption

| Change | Reason |
|---|---|
| **Default output is text, not SARIF** | 17 findings × 40 lines of `sort_keys=True` JSON puts `level` and `ruleId` near the *bottom* of each block. The format buries the payload. SARIF is the right contract and the wrong default; those are separable decisions and the brief conflated them. |
| `--sarif-file` combines with `--format text` | CI needs both: text in the job log where findings are actually read, SARIF for upload |
| `--min-severity` and `--fail-on` are orthogonal, both default `critical` | Conflating "what do I see" with "what breaks the build" is the classic linter mistake |
| Baseline + `--write-baseline` | Without it, run 2 shows the same 12 criticals and the answer to "does anyone run this twice" is no. ~60 lines on top of fingerprints we already emit. |
| Fingerprints exclude line numbers | `hash(file, job_id, rule_id, sorted(hit kinds))`. Include the line and inserting a step above invalidates every entry, and the ratchet fires spuriously — trust gone in a week. |
| Parse errors become findings, not crashes | Exit 2 on the whole run kills the scan; silent skip is a **bypass**, since anyone who can choke our parser becomes invisible |
| Diagnostics to stderr | Otherwise `--format sarif > out.sarif` is corrupted by the banner |
| No workflows found ⇒ exit 0; bad path ⇒ exit 2 | Fresh repos and monorepo subdirs are legitimate; a typo must not silently pass |

---

## 6. The acceptance bar changed

The old bar was circular: fixtures authored from our threat model, asserted
against detectors built from the same threat model. 3/3 malicious → CRITICAL
proves our matcher matches our fixture. **It cannot detect the failure in §0.1**,
because the `clean/` fixtures are hardened repos and real repos are not.

Added to the definition of done:

- [ ] **A false-positive budget on realistic (not hardened) repos.** ≤1 critical
      per 20 jobs, ≤15% of jobs carrying any finding. This is the only check that
      would have caught §0.1, and it turns "is it too noisy?" from an argument
      into a build status.
- [ ] **Dogfood: `tridelphi core .` on this repo — including the README's own CI
      snippet — exits 0.** The snippet is `security-events: write` (P) + `run:`
      (E) on `pull_request` (U): under the old spec **the tool flagged its own
      recommended integration as CRITICAL.** If we can't pass our own README, we
      don't ship.
- [ ] Exit-code matrix across {no findings, warnings only, criticals} ×
      {`--fail-on critical|warning|none`} × {missing path, no workflows,
      malformed YAML}
- [ ] Remediation specificity lint: every rendered fix must contain a
      `file:line` and a verbatim source token, and must not contain `secrets.*`,
      `the minimum required`, or `consider`
- [ ] Baseline round-trip, fingerprint stability under a 10-line insertion
- [ ] Determinism across two subprocesses with different `PYTHONHASHSEED`
- [ ] stdout/stderr separation

---

## 7. Where I did not take the advice

**"Stop and do a 300-repo corpus measurement before building."** Strategically
right, and I accept the underlying finding — the acceptance bar must be measured
precision on real code, not self-authored fixtures. But two things:

1. **Not executable here.** This session's GitHub access is scoped to
   `girnarholdings/tridelphi`. I cannot pull 300 public repos without going
   outside that scope, which I won't do unilaterally.
2. **The measurement needs the instrument.** The corpus run requires a working
   analyzer. Building the corrected version is roughly a day; it *is* the
   measuring device.

So: build the corrected tool, ship the FP-budget harness with a hand-authored
`realworld/` bucket of *typical unhardened* repos — which catches the §0.1
class, the fatal one — and ship `scripts/corpus.py` so the real 300-repo run is
one command once repo access exists. That is the corpus recommendation honored
at the level that matters, minus the part I can't run.

**"Trail of Bits shipped a skill rather than a zizmor audit, therefore they
concluded this doesn't fit a deterministic linter."** The plugin's own
description is pattern-matching rules over workflow YAML, not LLM judgment — a
skill *packaging* deterministic checks. The inference is weaker than presented.
Worth noting: all nine of its categories are syntactic flows into prompts; none
model restore semantics. The residual in §2 is genuinely unclaimed.

**"Drop `per-context join` from the positioning."** Partially rejected — instead
I put the edges in (§3), which is what makes the claim true rather than
abandoning it. The reviewer's own argument supports this: they said cross-workflow
composition is the one finding class per-file analysis cannot reach.

**Job stays the unit of analysis.** Both the threat reviewer and I agree steps
are too fine (no data-flow model in v1) and workflows too coarse. Matrix
expansion collapses to the job *definition* in v1 — documented, not accidental.

**E's detection stays broad.** Defended in §1.3.

---

## 8. Recommended next actions outside the code

1. **Comment on [zizmor #1605](https://github.com/zizmorcore/zizmor/issues/1605)**
   with the restore-semantics analysis. One hour. If a maintainer says "PR
   welcome," we learn this should be an upstream contribution rather than a
   tool. If it stays silent another six months, we've earned the right to say
   the space is unserved — a claim we currently cannot support.
2. **Run the real corpus** once repo access allows, and put the precision number
   in the README. That number is the pitch.
3. **Set a refresh cadence on the restore-semantics table.** The deepest finding
   of the review was not that a competitor might catch up — it was that our
   prewalk audited *scanners* and never audited *the thing being scanned*, so a
   vendor mitigation landed without us noticing. That is a process gap, not a
   code gap.
