# Release plan — versions and the draft release

TriDelPhi versions track how far up the hardening ladder a release reaches.
Each major is a stable `uses:` target; the moving major tag (`v1`, `v2`, `v3`)
points at the newest release in that line.

| Version | Ladder | Merged in | Tag target (commit) |
|---|---|---|---|
| **v1.0.0** | L1–L3 — gitleaks, osv-scanner, zizmor + core | PR #6 | `4f96806` (PR #6 merge) |
| **v2.0.0** | L1–L6 — + scorecard, semgrep, attest & gate | PR #7 | `af728b1` (PR #7 merge) |
| **v3.0.0** | L1–L7 — + `tridelphi verify` (trust-lock) | PR #8 | the PR #8 merge commit |
| **v3.1.0** | L1–L7 + `expose`/`privatize` — audit & obfuscate the shipped product | PRs #21–#25 | `origin/main` after #25 (the `v3` major moves forward) |

> **These steps need repository-admin access.** This session's push credential
> is scoped to the feature branch — it cannot create tags or releases (tag
> pushes return an org-policy 403), so a human runs the commands below. Do
> **not** publish to the GitHub Marketplace yet; these are draft releases only.

## 1. Create the version tags

`v1`/`v2` point at commits already on `main`. Create `v3` only after PR #8
merges, pointing at its merge commit.

```bash
git fetch origin main

# v1 — L1–L3
git tag -a v1.0.0 4f96806 -m "TriDelPhi v1.0.0 — L1–L3 hardening ladder"
git tag -f -a v1  4f96806 -m "TriDelPhi v1 — moving major (L1–L3)"

# v2 — L1–L6
git tag -a v2.0.0 af728b1 -m "TriDelPhi v2.0.0 — L1–L6 ladder"
git tag -f -a v2  af728b1 -m "TriDelPhi v2 — moving major (L1–L6)"

# v3 — L1–L7  (after #8 merges; substitute the merge SHA)
MERGE=$(git rev-parse origin/main)
git tag -a v3.0.0 "$MERGE" -m "TriDelPhi v3.0.0 — L1–L7 ladder (adds trust-lock)"
git tag -a v3     "$MERGE" -m "TriDelPhi v3 — moving major (L1–L7)"

git push origin v1.0.0 v1 v2.0.0 v2 v3.0.0 v3
```

On every future release, move the major tag forward
(`git tag -f v3 <new-sha> && git push -f origin v3`); never move a `vX.Y.Z`.

### v3.1.0 — the exposure audit + honest `privatize`

A **minor** release: `expose` and `privatize` are additive sibling commands (not new
ladder rungs), and the only action change is an optional, advisory `expose` input — all
backward-compatible, so the `v3` major moves forward. Create `v3.1.0` at the `#25` merge
commit and advance `v3`:

```bash
git fetch origin main
MERGE=$(git rev-parse origin/main)
git tag -a v3.1.0 "$MERGE" -m "TriDelPhi v3.1.0 — exposure audit + honest privatize"
git tag -f -a v3  "$MERGE" -m "TriDelPhi v3 — moving major (adds expose/privatize)"
git push origin v3.1.0 && git push -f origin v3
```

(The Python package version moves `0.1.0 → 0.2.0` in the same PR — that's the SARIF
driver / CLI-banner version, separate from these Action tags.)

## 2. Draft the GitHub release (do not publish to Marketplace)

Draft a release from `v3.0.0` (Releases → Draft a new release → choose tag
`v3.0.0`), leave **"Set as the latest release"** and any **"Publish this Action
to the GitHub Marketplace"** checkbox **unticked**, and save as **draft**. Body:

---

**TriDelPhi v3.0.0 — the full L1–L7 hardening ladder**

One `uses:` line, seven rungs, one merged SARIF. TriDelPhi's capability-graph
core is the finding no linter produces; around it, `--level` runs best-of-breed
open-source scanners and merges everything into one Security-tab upload and one
gate.

- **L1 secrets** — gitleaks (MIT)
- **L2 supply chain** — osv-scanner (Apache-2.0)
- **L3 CI boundary** — zizmor (MIT) + **tridelphi core**
- **L4 repo posture** — OSSF scorecard (Apache-2.0)
- **L5 code SAST** — semgrep (LGPL-2.1)
- **L6 attest & gate** — native: signed-elsewhere evidence + policy as its own step
- **L7 trust** — native trust-lock: a consumed action whose signer or SHA
  changed fails the build — the case SHA-pinning can't see (the tj-actions class)

```yaml
- uses: girnarholdings/TriDelPhi@v3
  with: { level: '7' }
```

Every wrapped scanner is version-pinned and checksum/hash-verified at install.
Offline-first, deterministic, graceful when a tool is absent. Full credit to
the projects wrapped — run `tridelphi --credits`.

*Not published to the GitHub Marketplace yet.*

---

Repeat for `v2.0.0` (L1–L6) and `v1.0.0` (L1–L3) if you want the older lines
listed as their own draft releases.

For the `v3.1.0` tag, draft a release with this body:

---

**TriDelPhi v3.1.0 — the exposure audit + the honest obfuscator**

The hardening ladder scans your CI. This release adds two commands about your **shipped
product** — what a vibe-coded app actually leaks — while staying honest about what a
*static* tool can prove.

**`tridelphi expose`** — a sibling command (not a ladder rung) that reads your committed
code and config and reports, in plain English, what's exposed:

- **Shipped source & secrets** — a `.map` that embeds your whole repo; a live-key-shaped
  string in a `dist/` bundle across ~25 providers (AWS, Google, Stripe, GitHub/GitLab, npm,
  and AI keys — OpenAI, Anthropic, OpenRouter, Groq, HuggingFace, Replicate); a secret behind
  a framework `NEXT_PUBLIC_`/`VITE_` prefix that ships to the browser. A Firebase web key and
  a Supabase **anon** key are correctly treated as *public by design*; a Supabase
  **service_role** key is critical.
- **Auth & data hygiene** — weak password hashing (md5/sha1), tokens in `localStorage`, PII in
  committed data files, JWT/TLS verification switched off.
- **Self-hosted DB/service left open** — a public port with a default/empty password or auth
  disabled, across ~14 engines (Postgres, MySQL, Mongo, Redis, Elasticsearch/OpenSearch,
  RabbitMQ, MinIO, Neo4j, CouchDB, …).
- **Committed keys & cloud config** — private keys, cloud service-account JSON, AWS
  credentials, terraform state, a real API key in a committed `.env`.
- **Open cloud data rules** — Firebase Security Rules that `allow … : if true`, or a bucket
  set world-readable/writable.

Native detectors are pure, offline file reads (deterministic SARIF, secret values masked);
the code-pattern rung is semgrep with a **bundled local ruleset**. It's a static read — a
clean result is not a pentest, and a browser can never keep a secret, so it always says
*rotate and move it server-side*, never "hide it."

**`tridelphi privatize`** — an opt-in, consent-gated obfuscator for your built JavaScript.
It is **not security** and cannot hide a secret; it refuses if your build ships one. It caps
the transform to a safe preset, forces source maps off, and keeps the result **only if your
own smoke check passes** against it — otherwise it reverts to your exact bytes.

In CI, add `expose: 'true'` to the action to also audit the checkout (advisory — uploads to
the Security tab, never fails the build). `privatize` is deliberately not in the action.

```yaml
- uses: girnarholdings/TriDelPhi@v3
  with: { level: '7', expose: 'true' }
```

*Not published to the GitHub Marketplace yet.*

---
