# TriDelPhi `core` — Claude Code build brief

> **Read this whole file before writing any code.** It pre-walks the session so
> we don't spend the first hour relitigating scope. The decisions below are
> made. Where something is genuinely open, it says **OPEN** and tells you when
> to ask.

---

## 0. One-paragraph orientation

We are building `tridelphi core`: a CLI that reads a GitHub repository and emits a
**capability graph** for its CI/CD + agent-config surface, then flags any
execution context that simultaneously holds all three of {untrusted input,
privileged credentials, egress/state-change capability}. That intersection is
the shape behind every 2026 agentic-CI exploit (Comment-and-Control, the Claude
Code Action issue→write-token chain, GitLost). Output is **SARIF 2.1.0** so it
drops into GitHub code scanning with zero custom UI. This is the one component
of the larger TriDelPhi product that does not already exist in open source —
everything else in the roadmap orchestrates tools that do (Socket, zizmor,
pinact, harden-runner, Semgrep). We build the novel core first.

**What we are NOT building in this session** (explicitly out of scope — do not
start these, do not scaffold them, do not add config for them):
- The GitHub App / merge gate (`tridelphi gate`)
- The runtime attestation signer (`tridelphi attest`)
- The `tridelphi init` remediation state machine / ladder
- The consumer `tridelphi clone` detonation sandbox
- Any wrapping of Socket / Semgrep / osv-scanner / harden-runner
- Any web frontend, dashboard, or server

If you find yourself reaching for any of the above, stop — you've left scope.

---

## 1. Why this scope, so you don't try to "help" by widening it

The instinct will be to build the whole ladder because it's more impressive.
Resist it. Reasoning, in the terms that matter:

- **Convexity.** `tridelphi core` is the only piece with asymmetric upside: it's
  novel, so it can't be forked in a weekend, and it's the format we want the
  ecosystem to standardize on. The wrappers are linear work with a competitor-
  copyable ceiling. Build the convex thing first.
- **Falsifiability.** The entire product thesis rests on "the capability graph
  finds real problems that per-file scanners miss." If `core` doesn't surface
  the known 2026 exploit shapes on our test fixtures, the thesis is dead and we
  saved six months. Ship the test of the thesis before the scaffolding around
  it.
- **Distribution.** A single-purpose SARIF-emitting binary with zero account and
  zero network calls is installable in one command and auditable in one sitting.
  That's the adoption wedge. A framework is not.

---

## 2. Hard technical constraints (KISS — these are load-bearing)

1. **Language: Python 3.11+.** Rationale: the SARIF, YAML, and graph tooling is
   mature there, and the security-tooling audience already has Python. No
   Node/Go/Rust for v1. **OPEN** only if you hit a concrete blocker — ask.
2. **No network calls at runtime.** `tridelphi core` reads local files only. It does
   NOT call the GitHub API, does NOT resolve action SHAs over the wire, does NOT
   phone home. Everything is static analysis of files already on disk. This is a
   security tool; it must be trivially auditable and air-gap-safe. A future
   `--online` mode can resolve transitive reusable workflows, but not now.
3. **Dependency minimalism.** Standard library + `PyYAML` + `ruamel.yaml` (for
   position-preserving parse, needed for good SARIF line numbers) + `jsonschema`
   (to self-validate our SARIF output). That's the whole allowlist. Per the
   user's coding principles: vet each dep, pin it, and prefer stdlib. If you want
   a graph library, justify it against writing ~40 lines of adjacency-list code
   ourselves — default is we write it ourselves.
4. **SARIF 2.1.0 output is the contract.** It must validate against the official
   OASIS schema. We ship the schema in-repo and self-test against it. If our
   output doesn't validate, the build is red.
5. **Deterministic output.** Same repo in → byte-identical SARIF out (modulo an
   optional timestamp field). Sort findings by (file, line, ruleId). This makes
   it diffable in CI, which is the whole point of a gate later.
6. **Exit codes are an API.** `0` = no findings, `1` = findings at or above the
   `--fail-on` threshold, `2` = execution error (bad args, unreadable files).
   Never conflate "found a vuln" with "the tool crashed."
7. **Secrets hygiene.** If any API keys ever get added (they won't in v1), they
   go in `.env`, never in code. `.env` is gitignored from commit zero.

---

## 3. The domain model — what a "capability graph" actually is

This is the conceptual heart. Get this right and the code is mechanical.

We model the repo as a set of **execution contexts**. In v1 an execution context
is a **single GitHub Actions job** (one `job` in one workflow file). For each
context we compute three boolean capability flags by static inspection:

### U — Untrusted ingress
The job can be influenced by attacker-controlled text. Sources:
- Trigger is `pull_request_target`, `issue_comment`, `issues`,
  `discussion`, `discussion_comment`, `workflow_run`, or `fork`-reachable
  `pull_request` with `types` that fire on fork PRs.
- Any step interpolates a known-untrusted context expression into a `run:` block
  or an action input. The canonical dangerous set includes (non-exhaustive —
  put the full list in a data file, see agent brief):
  `github.event.issue.title`, `github.event.issue.body`,
  `github.event.pull_request.title`, `github.event.pull_request.body`,
  `github.event.comment.body`, `github.event.review.body`,
  `github.event.pull_request.head.ref`, `github.head_ref`,
  `github.event.*.head.label`, and pull-request-authored file contents.
- **Agent-config ingress (this is TriDelPhi's differentiator):** the job invokes an
  AI coding agent (Claude Code Action, an MCP-enabled step, a step that reads
  `CLAUDE.md` / `AGENTS.md` / `.cursor/rules` / `.github/copilot-instructions.md`),
  AND those instruction files are themselves modifiable by an untrusted PR. An
  agent that ingests attacker-editable instructions is an untrusted-ingress path
  that zizmor and every YAML linter completely miss. This is the finding class
  that justifies the whole product.

### P — Privilege
The job holds credentials or write scope. Sources:
- `secrets.*` referenced anywhere in the job (except the implicit
  `GITHUB_TOKEN`, which is handled by the next bullet's permission analysis).
- `permissions:` (job-level, falling back to workflow-level, falling back to the
  repo default which we treat as write-all unless told otherwise) grants any
  `write` scope, or `id-token: write`.
- An MCP server configured in an invoked agent step declares write-capable tools
  (`.mcp.json` with tools whose scope isn't read-only).

### E — Egress / state change
The job can exfiltrate or mutate outside state. Sources:
- Any `run:` step (shell = arbitrary network + fs by default). This is broad on
  purpose; refinement comes later.
- A step using an action known to push/publish/deploy (heuristic allow/deny list
  in a data file), or `actions/upload-artifact`, or any `curl`/`wget`/`nc`/
  `Invoke-WebRequest` token in a run block.
- An agent step with `Bash`/`WebFetch`/network-capable tools enabled.

### The rule
For each context: if `U && P && E`, emit a **CRITICAL** finding with the taint
path (which source triggered each of the three flags). If exactly two are set,
emit a **WARNING** naming the single capability that, if removed, breaks the
chain (the "cheapest fix"). One or zero → no finding.

This "which one capability to strip" output is the thing that makes it
actionable rather than just alarming. Prioritize implementing it.

---

## 4. Session plan — the order you build in

Do these in order. Each is a checkpoint; the build should be green at each.

**Phase A — skeleton + contract (do this first, it de-risks everything).**
Scaffold the CLI, the SARIF emitter, and the schema self-validation with a
single hardcoded dummy finding. Prove `tridelphi core ./fixtures/x | validate`
round-trips against the OASIS schema before writing a single detector. If the
contract is wrong, everything downstream is wrong.

**Phase B — the parser + graph model.** Walk `.github/workflows/*.{yml,yaml}`,
build the execution-context objects with position info. No detection yet — just
prove we can enumerate every job and every step with correct line numbers.

**Phase C — the three flag detectors.** Implement U, P, E as independent,
individually-tested pure functions over an execution context. Each ships with
its own fixture set. This is where the sub-agents parallelize (see §6).

**Phase D — the rule + the cheapest-fix logic + SARIF wiring.** Combine the
flags, compute the intersection, generate the "strip this capability" guidance,
emit real findings.

**Phase E — the fixture corpus + the thesis test.** Assemble fixtures that
reproduce the three named 2026 exploit shapes plus clean controls. The
acceptance bar: `core` flags all three malicious fixtures CRITICAL, flags the
two-capability fixtures WARNING, and produces ZERO findings on the clean
controls. **This test passing IS the definition of done for v1.**

Stop at E. Do not start Phase F (anything). Report back.

---

## 5. Repo layout to create

```
tridelphi/
  pyproject.toml            # deps pinned, entry point tridelphi = tridelphi.cli:main
  .gitignore                # .env, __pycache__, *.egg-info, .venv, dist
  README.md                 # what it is, install, one usage example, exit codes
  tridelphi/
    __init__.py
    cli.py                  # arg parsing, exit codes, orchestration only
    model.py                # ExecutionContext, Finding, Capability dataclasses
    parse.py                # workflow + agent-config file loading (ruamel)
    detect_untrusted.py     # U detector + its data tables
    detect_privilege.py     # P detector
    detect_egress.py        # E detector
    rule.py                 # intersection logic + cheapest-fix guidance
    sarif.py                # Finding[] -> SARIF 2.1.0 dict + schema validate
    data/
      untrusted_contexts.yml
      egress_actions.yml
      agent_signals.yml     # which actions/files indicate an AI agent step
  schema/
    sarif-2.1.0.json        # vendored OASIS schema, self-test against it
  tests/
    fixtures/
      malicious/            # the 3 named 2026 shapes, one dir each
      two_cap/              # exactly-two-capability repos
      clean/                # hardened controls that must produce zero findings
    test_untrusted.py
    test_privilege.py
    test_egress.py
    test_rule.py
    test_sarif_schema.py
    test_thesis.py          # the acceptance test from Phase E
```

---

## 6. Sub-agent strategy

Four subagent definition files ship in `.claude/agents/` of THIS brief package.
Copy them into the `tridelphi/.claude/agents/` directory at the start of the
session. Their scopes are deliberately non-overlapping (overlap is the #1
subagent failure mode). Summary — full definitions in the individual files:

| Subagent | Owns | Must NOT touch |
|---|---|---|
| `sarif-contract` | `sarif.py`, `schema/`, `test_sarif_schema.py` — the output contract and its validation | Any detector logic. It only cares that findings serialize correctly. |
| `graph-modeler` | `model.py`, `parse.py` — dataclasses + file→context enumeration with line numbers | Detection rules. It produces contexts; it does not judge them. |
| `capability-detective` | the three `detect_*.py` files + `rule.py` + their unit tests + the `data/*.yml` tables | SARIF serialization and CLI wiring. Pure logic over a context. |
| `fixture-adversary` | everything under `tests/fixtures/` + `test_thesis.py` | Production code. It writes ONLY malicious and clean repos and the acceptance test. It is the red team; keep it walled off from the code it's trying to catch. |

The main thread (you) owns `cli.py`, `pyproject.toml`, `README.md`, wiring the
pieces together, and adjudicating interface disagreements between subagents.

**Parallelization:** `sarif-contract` and `graph-modeler` and `fixture-adversary`
can run concurrently from the start — none depends on another's output.
`capability-detective` needs `graph-modeler`'s `model.py` interface frozen first,
so it starts once that interface is agreed (not once it's fully implemented — a
stub with the dataclass signatures is enough to unblock it).

---

## 7. Interface contracts between subagents (freeze these early)

To let the subagents work in parallel without merge chaos, these signatures are
fixed up front. Any change requires main-thread sign-off.

```python
# model.py — the frozen interface everyone codes against

@dataclass(frozen=True)
class Position:
    file: str
    line: int          # 1-indexed, points at the triggering token
    end_line: int | None = None

@dataclass(frozen=True)
class CapabilityHit:
    capability: str    # "U" | "P" | "E"
    reason: str        # human sentence: 'trigger pull_request_target'
    position: Position

@dataclass(frozen=True)
class ExecutionContext:
    workflow_file: str
    job_id: str
    position: Position          # the job: key
    raw: dict                   # the parsed job body, for detectors to inspect
    # detectors READ raw + return CapabilityHit list; they do not mutate context

@dataclass(frozen=True)
class Finding:
    severity: str               # "critical" | "warning"
    context: ExecutionContext
    hits: tuple[CapabilityHit, ...]
    cheapest_fix: str | None    # None for critical; the strip-target for warning
    rule_id: str                # "tridelphi/u-p-e-intersection" | "tridelphi/two-of-three"
```

```python
# each detector exposes exactly this shape:
def detect(context: ExecutionContext, tables: dict) -> list[CapabilityHit]: ...

# rule.py exposes:
def evaluate(context: ExecutionContext, tables: dict) -> Finding | None: ...

# sarif.py exposes:
def to_sarif(findings: list[Finding]) -> dict: ...   # validates internally
```

If a subagent wants to change one of these, it raises it to the main thread with
the reason; the main thread decides and broadcasts. Do not let a subagent
silently fork the interface.

---

## 8. Definition of done (v1)

- [ ] `pip install -e .` then `tridelphi tests/fixtures/malicious/comment-and-control`
      exits `1` and prints valid SARIF with one `critical` finding whose message
      names all three capability sources.
- [ ] Same command on `tests/fixtures/clean/*` exits `0` with an empty results
      array.
- [ ] `test_thesis.py` passes: 3/3 malicious → critical, all two_cap → warning
      with a correct cheapest-fix, 0 findings on clean.
- [ ] Every emitted SARIF document validates against the vendored OASIS schema
      (`test_sarif_schema.py`).
- [ ] Output is deterministic (run twice, diff is empty modulo timestamp).
- [ ] README shows install, one example, and the exit-code table.
- [ ] Zero runtime network calls (grep the source for `requests`, `urllib`,
      `http` — none in the execution path).

When all boxes are checked, STOP and report. Do not proceed to the ladder, the
gate, or any wrapper. Those are separate briefs.

---

## 9. Things that will tempt you off-course (pre-mortem)

- **"I should also wrap zizmor so it's more complete."** No. zizmor is a separate
  tool we orchestrate later. `core` finds what zizmor cannot; that's the point.
- **"I should resolve action SHAs over the network for accuracy."** No — that's
  the `--online` mode, explicitly deferred. v1 is air-gap-safe static analysis.
- **"The egress detector flags every `run:` step, that's too noisy."** It's
  supposed to be broad at the E layer — the intersection with U and P is what
  makes a finding, not E alone. Don't prematurely narrow E and miss real chains.
- **"Let me add a nice web dashboard for the findings."** SARIF renders in
  GitHub's UI for free. No frontend. Not in this brief.
- **"Let me make the model handle GitLab and Bitbucket too."** GitHub Actions
  only for v1. The model can be generalized later; doing it now triples the
  fixture burden and delays the thesis test.
