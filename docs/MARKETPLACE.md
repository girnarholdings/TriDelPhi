# Publishing TriDelPhi to the GitHub Marketplace

TriDelPhi already ships a composite action (`action.yml` at the repo root), so it
is **Marketplace-ready**. Publishing is a short, human-only flow in GitHub's UI —
it can't be done from CI, and (like tags) it needs an account with admin rights on
the repo. This file is the copy-paste listing text plus the exact steps.

> **Why a human does this:** creating a release/tag and clicking *Publish to
> Marketplace* both happen in the GitHub web UI. This repo's automated push
> credential also 403s on tag pushes (org policy), so the release tag is pushed by
> a maintainer — see [`RELEASES.md`](RELEASES.md).

## 1. Pre-publish checklist

- [x] `action.yml` is at the **repository root** (not in a subfolder).
- [x] It has a `name`, a `description`, and a `branding` block (`icon: shield`,
      `color: red` — both from GitHub's allowed sets).
- [x] The repository is **public** and has a `README`.
- [ ] The action `name` (**"TriDelPhi"**) is **unique** across the Marketplace —
      GitHub checks this when you tick the publish box; if taken, adjust `name:` in
      `action.yml` (the `uses:` path does not change).
- [ ] A **release tag** exists to publish from. Create `v3.1.0` and move `v3`
      per [`RELEASES.md`](RELEASES.md) first.
- [ ] Two-factor authentication is enabled on the account (Marketplace requires it).

## 2. Publish steps (GitHub UI)

1. Push the tags (maintainer step, see `RELEASES.md`): `v3.1.0` and the moved `v3`.
2. **Releases → Draft a new release →** choose tag **`v3.1.0`**.
3. On the draft, tick **“Publish this Action to the GitHub Marketplace.”**
   GitHub validates `action.yml` and the unique name inline.
4. Pick **Primary category: Security** and **Secondary: Continuous integration**
   (Code review / Code quality also fit).
5. Accept the GitHub Marketplace Developer Agreement (first time only).
6. Leave **“Set as the latest release”** ticked; **Publish release**.

To update the listing later, publish a new release for the next tag; the listing
tracks the moving major (`v3`).

## 3. Listing copy (paste into the fields)

**Name:** `TriDelPhi`

**Tagline** (≤ 125 chars):
> Find the CI job where an attacker's comment becomes RCE — plus a 7-rung hardening ladder and a shipped-secret audit.

**Categories:** Security (primary) · Continuous integration (secondary)

**Description / README shown on the listing** — the repo `README.md` renders on
the listing; no separate copy needed. If a short blurb is requested, use:

> TriDelPhi builds a per-job capability graph of your GitHub Actions and flags the
> job that simultaneously holds untrusted input, privilege, and egress — the
> “Agents Rule of Two” violation that turns a workflow into an exploit. Around that
> core, one `level:` input runs best-of-breed scanners (gitleaks, osv-scanner,
> zizmor, Scorecard, semgrep) and a native attest/gate + trust-lock, merged into a
> single SARIF upload and one gate. `expose: 'true'` also audits what your app
> *ships* — leaked secrets, an open database, published source. Offline by default,
> deterministic, and honest about what a static tool can prove.

**Suggested one-liner for users** (already the README headline):

```yaml
- uses: girnarholdings/TriDelPhi@d5c01388c21de9c1d12159087890d12d2d917990 # v3.1.1
  with: { level: '7', expose: 'true' }
```

## 4. After it's live

- Add the Marketplace badge to `README.md` (swap in the real slug once published):
  `[![Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-TriDelPhi-2ea44f?logo=github)](https://github.com/marketplace/actions/tridelphi)`
- Point the site's Setup Studio “one line” snippet at the Marketplace listing if
  desired (it already uses `girnarholdings/TriDelPhi@d5c01388c21de9c1d12159087890d12d2d917990 # v3.1.1`, which is what Marketplace
  installs).

*Marketplace listing is optional — the action works from the `uses:` path whether or
not it's listed. Do not tick “Publish” until the name check passes and the release
tag is in place.*
