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
- uses: girnarholdings/TriDelPhi@d5c01388c21de9c1d12159087890d12d2d917990 # v3.1.1
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
- uses: girnarholdings/TriDelPhi@d5c01388c21de9c1d12159087890d12d2d917990 # v3.1.1
  with: { level: '7', expose: 'true' }
```

*Not published to the GitHub Marketplace yet.*

---

---

# The two switches in `tridelphi/release.py`

Everything a user is told to type — the install line and the Action pin — is
generated from `tridelphi/release.py`, and `tests/test_release_pin.py` fails the
build if any surface drifts from it. This is not tidiness. Both strings had
silently stopped resolving: the site, the README and the Setup Studio told people
to run `pipx install tridelphi` against a package that 404s, and every `uses:`
line said `@v3` when only `v3.1.0` and `v3.0.0-beta` were tagged. Those are the
first two commands anybody runs.

## Switch 1 — `ACTION_SHA` / `ACTION_TAG`

We advertise a **commit SHA with the version in a trailing comment**, the same
discipline this repo applies to `actions/checkout`. It resolves today and it
cannot be repointed at code the user never agreed to run.

It is deliberately **not** an older release tag. `v3.1.0` is commit `04bc341`,
which predates the August 2026 remediation of the fix-bot authorization bypass —
advertising it would hand every new user the vulnerable bot. Whatever we pin must
be a default-branch commit carrying the current security posture.

To cut a release:

1. Merge the release commit to `main`.
2. Tag it: `git tag -a v3.1.1 -m "…" <sha> && git push origin v3.1.1`.
3. Set `ACTION_SHA` to that commit and `ACTION_TAG` to that tag.
4. Run `pytest tests/test_release_pin.py` — it rewrites nothing, it only tells
   you which surface you forgot.

If you later want a moving `v3` major tag (`git tag -f v3 <sha>`), point
`action_uses()` at it instead. Keep the SHA form until that tag exists; an
advertised pin that 404s is worse than a long one.

## Switch 2 — `PYPI_PUBLISHED`

Flip to `True` at first publish. Every advertised install becomes the short
registry form in the same commit, everywhere, with no grep. Until then the git
URL is what the README, the site and the Setup Studio print, and what the
generated workflows install (pinned, because an unpinned install inside a job
holding a repository token is the exact supply-chain shape this tool flags).

---

# Publishing to PyPI

`pipx install tridelphi` is the install path we *want* the README, the website
and every generated fix-bot workflow to use, so until the package exists on PyPI
that spelling stays behind `PYPI_PUBLISHED` — the downstream fix bot in
particular could not install itself. This section closes that gap.

## How it publishes: Trusted Publishing, no token

`.github/workflows/publish.yml` uploads via **PyPI Trusted Publishing (OIDC)**.
There is no API token in this repository and there should never be one: PyPI is
configured to trust *this workflow in this repository*, and mints a short-lived
credential for a single upload. Nothing long-lived exists to leak, and a stolen
repository secret cannot be replayed because there is no secret.

The workflow also gates the release on TriDelPhi's own scan and trust-lock, and
verifies the built wheel runs from **outside** the checkout — the only way to
catch the vendored SARIF schema or the rule tables failing to ship.

## 1. One-time setup on PyPI (a human, ~2 minutes)

This cannot be done from a workflow. While the project does not exist on PyPI
yet, register it as a **pending publisher**:

1. Sign in to PyPI and open <https://pypi.org/manage/account/publishing/>.
2. Under "Add a new pending publisher", fill in exactly:

   | Field | Value |
   |---|---|
   | PyPI project name | `tridelphi` |
   | Owner | `girnarholdings` |
   | Repository name | `TriDelPhi` |
   | Workflow name | `publish.yml` |
   | Environment name | `pypi` |

3. Save. The first successful publish creates the project and converts the
   pending publisher into a normal one.

The name `tridelphi` was unclaimed at the time of writing; if that has changed,
the project name must be settled before the first upload.

Optional but recommended: in the repository's **Settings → Environments**, add a
required reviewer to the `pypi` environment. Every publish then waits for a
human click, which is a cheap brake on an automated release.

## 2. Dry run (safe, uploads nothing)

Actions → **Publish to PyPI** → *Run workflow*. On `workflow_dispatch` the
publish job is skipped by its own `if:`, so this only builds, runs the gate, and
validates the distributions. Do this once before the first real release.

## 3. Publish

Publishing a **GitHub Release** triggers the upload. Using the v3.1.0 release
already described above:

```bash
# tags first (see section 1 of this document), then:
gh release create v3.1.0 --title "TriDelPhi v3.1.0" --notes-file <notes>
```

or click **Publish release** on the draft. The workflow builds, gates, uploads,
and attaches PEP 740 attestations signed with the same OIDC identity, so a
consumer can verify the files on PyPI came from this workflow.

If the trusted publisher is not configured yet, the publish step fails with
*"not a trusted publisher"* and **nothing is uploaded** — a safe failure, not a
half-finished release.

## 4. After the first publish

Confirm the install path the docs promise actually works:

```bash
pipx install tridelphi && tridelphi --version
```

Then flip `PYPI_PUBLISHED = True` in `tridelphi/release.py` and re-run
`pytest tests/test_release_pin.py`. That one edit switches the README, the site,
the Setup Studio and every generated workflow to the registry form at once.

Until that flip, downstream workflows install from the pinned git URL, which
works — the earlier failure mode was that they installed from PyPI, which did
not.

## Version numbers

The Python package version (`pyproject.toml`, `tridelphi/__init__.py`) is a
**separate** namespace from the Action tags: package `0.2.0` ships alongside
Action `v3.1.0`. Bump the package version for a PyPI release; PyPI refuses to
overwrite an existing version, so a re-release always needs a new number.
