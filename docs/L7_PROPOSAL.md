# L7 proposal — capping the TriDelPhi hardening ladder

> **Status: implemented.** L7 · trust shipped as `tridelphi verify` (and
> `--level 7`) — the offline **trust-lock pawl** as the headline, with
> opportunistic `gh attestation verify` for upstream provenance at `note`
> level, exactly as this proposal recommended. See `tridelphi/verify_cmd.py`
> and `tests/test_verify_l7.py`. The audit findings in §1 that this rung does
> **not** close (scorecard gating, external-finding baselining) remain recorded
> here as honest known-limitations. This document is preserved as the design
> rationale.

**Author:** external supply-chain / CI security audit
**Scope:** a candid audit of L1–L6 as built, then one proposed L7 rung, the
alternatives rejected to get there, and the effort/risk to build it.
**Method:** grounded in the code as it stands — `tridelphi/ladder.py`,
`tridelphi/gate_cmd.py`, `tridelphi/orchestrate.py`, `tridelphi/cli.py`,
`action.yml`, `scripts/install-ladder.sh`, and the `docs/BRIEF.md` /
`docs/DECISIONS.md` framing. No praise; only what would change my sign-off.

---

## 1. Audit of L1–L6 — what I'd flag before shipping

### 1.1 The attestation is write-only evidence: there is no verifier, and its predicate is self-asserted

This is the load-bearing finding, and it is what motivates L7.

`run_attest` in `gate_cmd.py` builds an in-toto Statement whose **subject is the
SARIF file's sha256** and whose **predicate is the tool names/versions/counts**
plus a `source` block. Two problems:

- **The `source` is self-asserted, not bound.** `source.repository` and
  `source.commit` come straight from `os.environ.get("GITHUB_REPOSITORY")` /
  `GITHUB_SHA` (`gate_cmd.py:155–158`). Anyone who runs the process controls
  those strings. What `actions/attest-build-provenance` then signs with the
  workflow OIDC identity is "a blob with this digest existed" — it does **not**
  cryptographically bind the SARIF to the commit it claims to describe, nor to
  the scanner version that produced it. The predicate can say whatever the
  environment says.
- **The deliberate no-timestamp determinism (`gate_cmd.py:18–19`, DECISIONS is
  proud of it) makes the attestation replayable.** Two scans of the same SARIF
  are byte-identical, so a signed "clean" attestation from last week is
  indistinguishable from one produced today. Determinism is right for the SARIF
  *diff*, but an evidence statement that is reproducible from its inputs and
  carries no freshness signal is a replay primitive: cache one clean result and
  re-present it forever.
- **Nothing consumes it.** There is an `attest` verb and zero `verify` verb.
  `action.yml:112–116` signs the evidence and… stops. Attestation without a
  verifier is provenance theater — you have built the producer half of a trust
  system and none of the consumer half. The threat model the attestation
  implies ("a downstream party can verify what scanned this commit",
  `gate_cmd.py:14–17`) has no code path that lets that party actually verify
  anything.

The whole point of L6 is undermined by the absence of its mirror. That mirror is L7.

### 1.2 The scorecard score→severity mapping is defensible in direction but flattens risk, and can never gate

`_scorecard_to_sarif` (`ladder.py:366–445`) maps score 0–3 → `warning`, 4–7 →
`note`, 8–10 → nothing. The "don't be alarming" instinct is right, but:

- It **discards scorecard's own per-check risk weighting.** Scorecard treats
  `Dangerous-Workflow` and `Token-Permissions` as critical-risk and
  `CII-Best-Practices` as informational — yet here a `Dangerous-Workflow` score
  of 2 (an *active* template-injection / self-hosted finding, overlapping
  TriDelPhi core's own turf) lands as the same `warning` as a missing CII badge
  at score 2. The single-band collapse throws away exactly the signal that would
  let L4 corroborate L3.
- **L4 can never break the build under the default gate.** The max level this
  adapter emits is `warning`; the default `--fail-on` is `critical`. So every
  scorecard finding is, by construction, non-blocking on a default install.
  That's a legitimate choice — but it should be stated plainly: **under the
  shipped defaults, L4 is decorative for gating** and exists only to populate
  the Security tab.

### 1.3 The containment gate checks shape, not magnitude, and "unknown level → warning" is a silent severity channel

`sarif_shape_error` (`orchestrate.py:49–76`) is a good structural gate — it
rejects non-dict runs, missing `tool.driver`, malformed results/locations. But:

- **It bounds bytes, not cardinality.** `MAX_OUTPUT_BYTES` is 25 MB
  (`orchestrate.py:46`). A crafted repo that makes a wrapped tool emit tens of
  thousands of *valid* findings under 25 MB passes the gate, and all of it is
  merged, counted, and fed to the exit-code logic. The size cap stops a memory
  bomb; it does not stop a finding flood that turns the gate red on volume.
- **Attacker-influenced `level` strings drive gate severity, mitigated in
  exactly one place.** Both `ExternalRun.__init__` (`ladder.py:194–198`) and
  `_run_summaries` (`gate_cmd.py:72–76`) default any non-standard `level` to
  `"warning"`. The wrapped tools scan hostile repos, so those level strings are
  attacker-influenced. The only hardening against this is the per-`ToolSpec`
  `severity_override`, and it is used on **gitleaks alone** (`ladder.py:108`).
  For every other rung, a tool coerced into emitting an off-spec level has its
  findings silently normalized to `warning` — which slips the default
  `--fail-on critical` gate. The design correctly identified the risk for L1 and
  then applied the fix exactly once.

### 1.4 The wrapped rungs bypass the ratchet — the ladder violates its own adoption principle

`cli.py:322–328` gates on external findings but comments: *"External findings
are not baselined … a committed secret should never be waived."* Correct for
gitleaks. Wrong as a blanket rule for L2/L4/L5. The README's entire adoption
thesis (§"The ratchet", "You cannot fix everything today. Freeze what exists")
is that a team can baseline the backlog and gate only on *new* findings. A repo
that switches on osv-scanner at L2 with 40 pre-existing transitive vulns
**cannot baseline them** — day-one red on findings the team did not introduce.
DECISIONS §5 is explicit that this is the failure mode that makes people
uninstall ("does anyone run this twice? … no"). So the ratchet rule — "each rung
installs a regression-blocking pawl" — genuinely holds for core and gitleaks,
and **silently does not hold for L2/L4/L5**. That is a product gap dressed as a
security choice.

### 1.5 The pinning discipline is real, but it is a manual, drifting, dual-sourced supply chain of its own

`install-ladder.sh` + `semgrep-requirements.txt` (867 lines of fully-hashed
closure) is better than almost anyone ships. But an auditor has to note:

- **It is hand-maintained with no refresh automation in-repo**, and DECISIONS
  §8.3 already lists "set a refresh cadence" as an *unclosed* process gap. A
  stale pin is a known-CVE freeze; a hand-regenerated 867-line hash file is a
  recurring opportunity to paste one bad digest. The pinning that reduces
  upstream supply-chain risk introduces a local one.
- **Two sources of truth for the zizmor version.** `ZIZMOR_VERSION=1.29.0` is a
  shell variable in `install-ladder.sh:37`, but the actual pin that governs the
  install lives in `zizmor-requirements.txt`. The script's
  `echo "installed zizmor v${ZIZMOR_VERSION}"` can print a version different
  from the one `--require-hashes` actually resolved if the two drift.
- **"Runs fully offline" conflates scan-time and install-time.** The credit line
  and `ToolSpec.network=False` describe zizmor's *scan* (true — it always gets
  `--offline`). But zizmor is installed by pip fetching a wheel over the network
  (`install-ladder.sh:80`). The offline claim is about the scan; a careless
  reader hears "no network anywhere." Worth a footnote.

### 1.6 (minor) `_relativize` hardens the relative-path escape but waves through the absolute one

`_relativize` (`ladder.py:524–552`) rewrites a `../`-escaping *relative* URI to
an unambiguous `file://` (good, well-reasoned), but an absolute or `file://` URI
pointing *outside* the root is returned untouched (`None` → left verbatim). The
stated rationale — a naive consumer can't distinguish an escaping relative path
from an in-repo one — applies just as well to a consumer resolving
`file:///etc/passwd`. Low impact (code scanning won't annotate out-of-repo
paths), but it's an inconsistency in the containment layer's own threat model:
one out-of-root shape is neutralized, the other is trusted.

---

## 2. The L7 proposal

### L7 · trust — `tridelphi verify`

**One line:** verify the *trust roots* the repo depends on — that every
third-party `uses:`/image the workflows pull has valid, publisher-bound build
provenance, and that TriDelPhi's own L6 attestation round-trips — and ratchet a
**trust-lock** so a change of signer (repo transfer, account takeover, the
tj-actions class) fails the build.

Where L1–L5 ask *"is the content bad?"* and L6 *emits* evidence, L7 asks the one
question nothing below it asks: **"is what I consume — and what I emit — actually
signed by who it claims to be?"** It is the consumer half of L6 and the
authenticity layer the ladder has no rung for.

#### Why it belongs at the TOP (signal density descending; depends on everything below)

- **It literally consumes the rungs below.** It needs core's parsed `uses:`
  graph (every action + pinned SHA that L3/core already enumerate), and it needs
  L6's signed evidence to verify the self-chain. It cannot exist until L1–L6 do.
- **It is the lowest-raw-density, highest-order rung** — exactly where the
  "signal density descending" ordering rule puts a check. gitleaks (L1) fires
  often and is almost always a true positive: dense, bottom of the ladder. L7
  fires rarely (only on missing/mismatched/regressed provenance) but each hit is
  a statement about the *trust root of the whole supply chain*, not the contents
  of one file. Sparse, high-assurance, top of the ladder. It is the "verify the
  verifier" rung, and there is nothing above it to verify.
- **It closes 1.1.** The single strongest audit finding is "attest with no
  verify." L7 is the verify.

#### How it fits TriDelPhi's constraints — and where it fits them *better* than L2/L4/L5

- **Offline-by-default / graceful degradation — L7 is *more* air-gap-friendly
  than the network rungs below it.** The key insight: **cryptographic
  verification is offline; only fetching the bundle is online.** Once you hold
  the sigstore bundle (cert chain + Rekor inclusion proof + artifact digest),
  verifying it against a pinned Fulcio/Rekor root is pure crypto — no network.
  So L7 runs in two modes, mirroring the L2 pattern exactly:
  `tridelphi verify --bundle-dir ./.tridelphi/attestations` verifies vendored
  bundles fully offline; online, it fetches and caches them. No bundles +
  `--offline` = rung skipped with a diagnostic and an install hint, identical to
  osv-scanner's `_skip` path (`ladder.py:229–234`). Contrast L2, which *must*
  reach osv.dev to know a CVE even exists — L7 needs the network only to acquire
  an artifact it then verifies forever offline.
- **Deterministic:** crypto verification of a fixed bundle against a fixed digest
  is byte-identical run to run. The trust-lock is committed to the repo, so drift
  is a diff, not a wall-clock event.
- **SARIF-or-native:** emits its results as one more `run` in the merged
  document via the same `merge_runs` path. `note` for "no provenance available
  (not your fault, not yet fixable)"; `warning`/`error` for
  "provenance present but FAILS / signer identity mismatch / trust-lock
  regression."
- **Wrap the commodity, own the join.** It **wraps** cosign / sigstore-python
  (Apache-2.0) and `gh attestation verify` for the crypto — you must never
  hand-roll signature verification. It is **native** for the part that is the
  moat: the *expected-signer table* (which OIDC identity should sign
  `actions/checkout`, `docker/build-push-action`, …) and the **trust-lock
  pawl**. That table is the exact shape of the moat DECISIONS §2 already defends
  for core's restore-semantics table: versioned, decaying with every
  action/publisher change, valuable precisely because nobody else maintains it.
  Forking the orchestration ("we shell out to cosign") gets a competitor
  nothing; the join and the signer table are the asset.
- **Ratchet / regression-blocking pawl — the strongest kind.** `--write-trust-lock`
  records the observed signer identity + resolved digest for each consumed
  artifact (mirrors `--write-baseline` in `baseline.py`). A later run where an
  action's provenance signer changes — the repo was transferred, the publisher
  account was taken over, the tag now resolves to a different builder — **fails
  the gate.** This is the pawl that would actually have caught
  tj-actions/changed-files: SHA-pinning defeats *mutation*, not *initial
  upstream compromise*; a trust-lock on the signer identity defeats the transfer/
  takeover case that pinning cannot see.

#### CLI sketch (mirrors `gate`/`attest` exactly)

```console
# inline, as the top rung of the ladder
tridelphi . --level 7 --sarif-file out.sarif        # full ladder, then verify trust roots

# as its own process (the mirror of `tridelphi gate` / `tridelphi attest`)
tridelphi verify out.sarif                            # verify consumed-action provenance, gate on it
tridelphi verify --self out.sarif --evidence tridelphi-evidence.json
                                                      # round-trip OUR OWN L6 attestation (closes 1.1)
tridelphi verify --workflows .github/workflows \
                 --trust-lock .tridelphi/trust.lock   # verify against the committed pawl
tridelphi verify --write-trust-lock                   # once: record today's signer identities
tridelphi verify --bundle-dir ./.tridelphi/attestations --offline
                                                      # air-gapped: verify vendored bundles, no network
```

#### How it gates

Same exit-code contract as `run_gate` (`gate_cmd.py:90–125`): `0` pass, `1`
findings at/above `--fail-on`, `2` document unusable. Severity discipline follows
core's observed-vs-assumed split (DECISIONS §1.2):

- **`error` / critical** — actionable and alarming: provenance present but
  verification *fails*; signer identity does not match the expected-signer table;
  trust-lock regression (a previously-accepted artifact now signed by a
  different identity).
- **`note` — unactionable-by-you**, off the default gate: no provenance
  published upstream for this action at all. This is the base rate in 2026 and it
  is published honestly (as DECISIONS §1.3 does for E-prevalence) rather than
  inflated into a warning the user cannot resolve.

#### The honest "why this might be wrong / what it does NOT solve"

- **Provenance coverage is sparse in 2026.** Most popular actions do not yet ship
  `attest-build-provenance` for their tags. On a real repo today, L7's dominant
  raw output is "no verifiable provenance for 18 of 20 actions." That is *true*
  and worth publishing, but it is not *fixable by this user* — and a rung whose
  default output is unactionable is the exact failure DECISIONS spent its whole
  length avoiding. **Mitigation, and the reason the rung survives:** lead with the
  **trust-lock**, not with upstream provenance. Even against an ecosystem with
  zero published attestations, "this action's resolved digest/signer changed
  since you accepted it" is independently valuable and fully actionable. SLSA
  verification is the upside as coverage matures; the pawl is the value that
  exists on day one.
- **It proves origin, not safety.** A correctly-signed-by-the-real-publisher
  action can still be vulnerable or malicious. L7 is an *authenticity* check, not
  a behavior check — it raises the cost of impersonation and takeover, it does
  not vet what the action does. It must say so.
- **It reintroduces a trust root TriDelPhi must maintain.** Offline sigstore
  verification means vendoring and pinning the Fulcio/Rekor (TUF) roots. That is
  real maintenance surface and a potential single point of failure — the very
  kind of pinning-drift risk raised in 1.5, now inside TriDelPhi itself. Honest
  cost, not a dealbreaker, but named.
- **Dependency-provenance is a partial subset.** Verifying the SLSA provenance of
  a package osv-scanner flagged only works where the ecosystem publishes it (npm
  provenance, PyPI attestations — partial coverage). "Verify our deps' build
  provenance" is something L7 *can* do where attestations exist, not a universal
  guarantee.

---

## 3. Rejected alternatives

**A. Runtime egress enforcement — harden-runner block-mode as a verified gate.**
Rejected. It breaks the two properties the product is built on: it is *runtime,
not static* (kills determinism and the "read files on disk, nothing else"
air-gap model), and block-mode leans on step-security's SaaS allowlist
intelligence — gating the build on a third-party live policy service is a trust
handoff at the worst possible moment. It also does **not** depend on L1–L6; it is
orthogonal to them, so it has no claim to the *top* of the ladder — it belongs in
a different product. The generated `init` workflow already drops harden-runner in
**audit** mode (README §L6), which is the correct dose of runtime for a static
analyzer.

**B. VEX / exploitability filtering of osv-scanner output.** Rejected *as a
capstone* — it's a good idea in the wrong slot. It is a *refinement of L2*: it
makes L2 quieter, it does not cap anything, and it depends on nothing in L3–L6.
The ordering rule (signal density descending) puts a noise-*reducer* **beside**
the rung it de-noises, not above the whole ladder. Fold it into L2 as
`osv-scanner --vex`/a reachability filter; do not crown the ladder with a filter.

**C. Continuous monitoring / drift detection between scans.** Rejected. It is
inherently *stateful and time-based*, which breaks determinism ("same repo in,
byte-identical out") and the offline model, and it needs a persisted history
store plus a scheduler — i.e. a backend/SaaS, precisely what `BRIEF.md §0`
forbids. My L7 pick captures the *one* drift that matters — a change in the
supply chain's trust root — without any backend, by committing the trust-lock to
the repo: **drift-as-a-diff, not drift-as-a-service.** (Secret-*rotation*
verification fails on the same rocks and worse — it needs live secret-store
credentials, so it cannot be static, offline, or air-gap-safe at all.)

---

## 4. Effort & risk

**Effort: medium–large; roughly 1–2 weeks to a credible v1, plus ongoing table
curation.** The expensive/dangerous part — signature verification — is **wrapped**
(cosign / sigstore-python / `gh attestation verify`), not built. The `uses:`/image
enumeration **already exists** in core. New native code, all in the shape of code
that already ships:

- a bundle fetch/cache layer with an offline `--bundle-dir` mode (the L2 skip
  pattern, `ladder.py:229–253`);
- the expected-signer table + the **trust-lock format and its ratchet** (mirror
  `baseline.py` + `gate_cmd.py` — call it ~2–3× `gate_cmd.py`);
- a SARIF adapter for verify results (mirror `_scorecard_to_sarif`,
  `ladder.py:366–445`, and reuse `sarif_shape_error` — the converter is not
  exempt from the same containment bar);
- `verify` wired as a third subcommand beside `gate`/`attest` in `cli.py`.

**Top risk: provenance coverage is too thin in 2026 for the SLSA-verification
half to be mostly-actionable, so the rung lands as noise and gets muted** — the
exact death DECISIONS is organized around preventing. The mitigation is
structural, not cosmetic: ship the **trust-lock pawl as the headline** (actionable
against a zero-provenance ecosystem on day one) and treat upstream SLSA/publisher
provenance as `note`-level upside that appreciates as adoption grows. If that
framing is wrong — if teams won't adopt a lock file for third-party actions — then
L7 as a *gate* is premature and it should ship first as a *reporter* (`note`-only,
never counted toward the exit code, à la `tridelphi/privileged-trusted-context` in
DECISIONS §1.5) until the ecosystem's provenance coverage justifies promoting it
to a pawl.
```