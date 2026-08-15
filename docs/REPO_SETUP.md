# Repository setup — the two switches a workflow cannot flip

Everything else in this repo is code. These two are repository *settings*, and
GitHub deliberately does not let a workflow (or an app token) change them —
otherwise a pull request could disable the checks that gate it. Each takes about
thirty seconds in the UI.

---

## 1. Serve the landing page

`site/index.html` is committed, and `.github/workflows/pages.yml` builds and
deploys it. But committing HTML does not publish it, and the deploy step fails
with *"Pages is not enabled for this repository"* until the source is set.

**Settings → Pages → Build and deployment → Source: `GitHub Actions`**

Then either push a change under `site/`, or run the **Deploy site** workflow
manually from the Actions tab. The URL will be:

```
https://girnarholdings.github.io/TriDelPhi/
```

The deploy job prints the live URL in its summary once it succeeds.

> The workflow only triggers on changes to `site/**` (or manually), so ordinary
> code pushes do not redeploy the page.

---

## 2. Require CI to pass before merge

Without this, **a pull request can merge with no checks having run at all** —
which is exactly what happened during a GitHub Actions outage: the checks never
completed, nothing required them, and the PRs merged untested.

**Settings → Rules → Rulesets → New branch ruleset**

| Field | Value |
|---|---|
| Name | `main protection` |
| Enforcement status | Active |
| Target branches | Include default branch |
| Require a pull request before merging | ✔ (1 approval, or 0 if you are solo) |
| Require status checks to pass | ✔ |
| Required check | **`ci-ok`** |
| Block force pushes | ✔ |

### Why `ci-ok` and not the individual jobs

`ci.yml` ends with an aggregating job called `ci-ok` that depends on `lint`,
`test`, `wheel` and `self-scan` and fails unless all four succeeded. Requiring
that single check has two properties the individual list does not:

- **A new job cannot silently widen what can merge.** If someone adds a job to
  `ci.yml` and forgets to add it to branch protection, the old list still passes.
  Adding it to `ci-ok`'s `needs:` is a code change, reviewed in the PR.
- **It survives the matrix.** `test` runs on three Python versions, so the raw
  check names are `test (3.11)`, `test (3.12)`, `test (3.13)` — a list that has
  to be edited by hand every time the matrix changes.

`ci-ok` uses `if: always()` so it still runs when a dependency fails, and then
explicitly asserts every result is `success`. A cancelled or skipped job is not
`success`, so a job that never ran cannot be mistaken for a passing one — the
failure mode that let the untested merges through.

---

## Optional: make the scan itself blocking

`self-scan` currently uploads SARIF to code scanning and fails the job if
TriDelPhi finds a critical in this repo. To gate on *code scanning alerts*
generally (including zizmor's, if you enable `--with-zizmor` in the workflow),
add a **Code scanning results** requirement to the same ruleset with
`tridelphi` as the tool and *Security alerts: Error* as the threshold.

That is the L6 rung of the ladder this project is about: the gate goes on last,
once it can pass on the first try.

---

## Publishing the action

This section described a `v1` / `v1.0.0` scheme that the project left behind at
`v3.0.0-beta`; the live tags are `v3.1.0` and `v3.0.0-beta`, and no `v3` exists.
That drift is exactly how every `uses:` line in the repo came to advertise a pin
that 404s.

What we advertise now is a **commit SHA with the version in a trailing comment**
— `- uses: girnarholdings/TriDelPhi@d5c01388c21de9c1d12159087890d12d2d917990 # v3.1.1` —
generated from `tridelphi/release.py` and enforced by `tests/test_release_pin.py`.
A SHA resolves immediately, needs no tag to exist first, and cannot be repointed
at code the user never agreed to run. The full runbook, including when to switch
to a moving major tag, is **[`docs/RELEASES.md`](RELEASES.md)** — a single file,
so this one cannot drift again.

Tagging and the Marketplace listing still cannot be done from inside CI safely:
after the release PR merges, tag the merge commit, draft a GitHub release from
it, and tick **Publish this Action to the GitHub Marketplace** (requires the repo
to be public and `action.yml` at the root — both already true).

The wrapped scanners are pinned by version + SHA-256 in
`scripts/install-ladder.sh`; bumping them is a normal PR that updates the
digest alongside the version, with the digest taken from the upstream
release's own checksums file (gitleaks) or SLSA provenance (osv-scanner).
