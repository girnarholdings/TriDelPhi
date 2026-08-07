# Release plan — versions and the draft release

TriDelPhi versions track how far up the hardening ladder a release reaches.
Each major is a stable `uses:` target; the moving major tag (`v1`, `v2`, `v3`)
points at the newest release in that line.

| Version | Ladder | Merged in | Tag target (commit) |
|---|---|---|---|
| **v1.0.0** | L1–L3 — gitleaks, osv-scanner, zizmor + core | PR #6 | `4f96806` (PR #6 merge) |
| **v2.0.0** | L1–L6 — + scorecard, semgrep, attest & gate | PR #7 | `af728b1` (PR #7 merge) |
| **v3.0.0** | L1–L7 — + `tridelphi verify` (trust-lock) | PR #8 | the PR #8 merge commit |

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
