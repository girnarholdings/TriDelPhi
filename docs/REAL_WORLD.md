# Does it actually work? TriDelPhi vs. real, disclosed attacks

A security tool is only worth anything if it catches attacks that actually
happen. This page runs TriDelPhi against faithful reproductions of **real,
publicly disclosed CI/CD incidents** and shows the unedited output. Every shape
here is committed as a regression test (`tests/test_realworld.py`, with fixtures
under `tests/fixtures/`), so if TriDelPhi ever stops catching one, CI fails.

You can reproduce all of it locally — nothing here needs the network except the
dependency rung (osv.dev).

---

## 1. The "pwn request" — `pull_request_target` secret exfiltration

**What happened, in the wild.** A workflow triggers on `pull_request_target`
(which runs with the base repo's secrets and a write token), then checks out and
runs code from the pull request. A stranger opens a PR whose code — a
`requirements.txt`, a `setup.py`, a test — exfiltrates those secrets. Disclosed
against, among others, **MITRE CAR** and **Splunk** security-content
([Sysdig][sysdig]), **spotipy** ([GHSA-h25v-8c87-rvm8][spotipy]) and
**timescale/pgai** ([GHSA-89qq-hgvp-x37m][pgai]); the pattern was found across
MITRE, Splunk, and other projects at scale.

**The vulnerable shape** (`tests/fixtures/malicious/pwn-request-target/`):

```yaml
on:
  pull_request_target:                              # ← runs with your secrets
jobs:
  integration:
    steps:
      - uses: actions/checkout@…
        with:
          ref: ${{ github.event.pull_request.head.ref }}   # ← attacker's code
      - run: pip install .                          # ← runs it
        env:
          API_CLIENT_SECRET: ${{ secrets.API_CLIENT_SECRET }}
```

**TriDelPhi's output** — flagged **critical**, with line-level evidence for all
three capabilities:

```
CRITICAL .github/workflows/integration.yml:8   job "integration"
  tridelphi/untrusted-checkout-privileged-egress

  U  the working tree contains pull request code — checkout
     resolves to `${{ github.event.pull_request.head.ref }}`
  P  `secrets.API_CLIENT_SECRET` is available to this job
  E  a `run:` step provides an unrestricted shell, which on a
     hosted runner means unrestricted network access

  Cheapest fix: strip U — gate the job on the commenter's association.
```

✅ **Caught.** This is the U∩P∩E core, and it names the exact three lines and the
cheapest fix. `→ tests/test_realworld.py::test_pwn_request_target_is_critical`

---

## 2. Supply-chain takeover — tj-actions/changed-files (CVE-2025-30066)

**What happened, in the wild.** In March 2025 an attacker compromised the
popular `tj-actions/changed-files` action and **moved its tags (v1–v45) to a
malicious commit** (`0e58ed8671d6b60d0890c21b07f8835ace038e67`) that scraped
runner memory for secrets — affecting **over 23,000 repositories**
([Wiz][wiz], [CISA][cisa], [The Hacker News][thn], GHSA-mrrh-fwg8-r2c3). This is
the class SHA-pinning alone struggles with: to a reviewer, a moved pin just
looks like a version bump to a new, legitimate-looking SHA.

**How TriDelPhi's L7 trust-lock catches it.** You record each action's identity
once (`tridelphi verify --write-trust-lock`) and commit `.tridelphi/trust.lock`.
On any later run, an action whose pinned SHA changed **under the same ref** — or
whose owner changed — is an error that fails the build.

**The reproduction** (`tests/fixtures/realworld/supply-chain-tj-actions/`): the
lock records the legitimate pre-attack SHA; the workflow now pins the real
malicious commit. TriDelPhi's output:

```
$ tridelphi verify .
[ERROR] tridelphi-verify/trust-lock-regression
  tj-actions/changed-files was locked to a1b2c3d4e5f6… but the workflow now
  pins 0e58ed8671d6…. If you intended this bump, re-run --write-trust-lock;
  if not, this is the change SHA-pinning cannot catch.

L7 trust: 2 third-party actions · 1 error, 0 notes
exit code = 1        # fails the build
```

The untampered control (pin matches the lock) exits `0` — the pawl does not cry
wolf on a correctly pinned action. ✅ **Caught, and it blocks the build.**
`→ tests/test_realworld.py::test_tj_actions_supply_chain_takeover_is_caught`

---

## 3. The full ladder, on a deliberately messy repo

One `--level 5` run over a repo that has a pwn-request workflow, a committed
token, an old `lodash`, an unpinned action, and a shell-injection code path —
every rung fires, in one plain-language report:

```
  🚫  Can a stranger trick a robot into leaking your keys?      1 to fix   ← core
  🚫  Any passwords left sitting in your files?                 1 to fix   ← gitleaks
  ⚠️   Any known-broken building blocks in use?                 10 worth a look   ← osv-scanner
  🚫  Are your automations set up safely?                       2 to fix   ← zizmor
  ⚠️   Do your repo settings follow safe defaults?              8 worth a look    ← scorecard
  ⚠️   Does your app code have risky patterns?                  1 worth a look    ← semgrep

  Result:  ⚠️  NOT YET SAFE — fix the 4 items above, then run this again.
```

## 4. …and a clean repo passes the whole thing

The same `--level 7` run over a hardened repo (SHA-pinned actions, no committed
secrets, a patched lockfile, a committed trust-lock) passes:

```
  ✅  Can a stranger trick a robot into leaking your keys?      all clear
  ✅  Any passwords left sitting in your files?                 all clear
  ✅  Does your app code have risky patterns?                   all clear
  ✅  Did any trusted outside tool get swapped?                 all clear
  …repo-posture rungs report a few advisory items…

  Result:  ✅  YOU'RE GOOD — nothing urgent to fix.        # exit 0
```

The gating checks come back **all clear**; only scorecard's advisory posture
checks flag minor items (they always find *something* to improve, by design).
The verdict — and the exit code — is a clean pass.

---

## Reproduce it yourself

```console
pip install -e ".[dev]"
python -m pytest tests/test_realworld.py -q     # the CVE regressions
tridelphi tests/fixtures/malicious/pwn-request-target --format checklist
tridelphi verify tests/fixtures/realworld/supply-chain-tj-actions
```

## Sources

- Sysdig — *Dangerous by default: insecure GitHub Actions in MITRE, Splunk, and other repos*: <https://www.sysdig.com/blog/insecure-github-actions-found-in-mitre-splunk-and-other-open-source-repositories>
- spotipy advisory GHSA-h25v-8c87-rvm8: <https://github.com/spotipy-dev/spotipy/security/advisories/GHSA-h25v-8c87-rvm8>
- timescale/pgai advisory GHSA-89qq-hgvp-x37m: <https://github.com/timescale/pgai/security/advisories/GHSA-89qq-hgvp-x37m>
- Wiz — *GitHub Action tj-actions/changed-files supply chain attack (CVE-2025-30066)*: <https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066>
- CISA alert: <https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction>
- The Hacker News — *GitHub Action compromise puts CI/CD secrets at risk in 23,000+ repos*: <https://thehackernews.com/2025/03/github-action-compromise-puts-cicd.html>
- GitHub Advisory GHSA-mrrh-fwg8-r2c3 (CVE-2025-30066): <https://github.com/advisories/GHSA-mrrh-fwg8-r2c3>

[sysdig]: https://www.sysdig.com/blog/insecure-github-actions-found-in-mitre-splunk-and-other-open-source-repositories
[spotipy]: https://github.com/spotipy-dev/spotipy/security/advisories/GHSA-h25v-8c87-rvm8
[pgai]: https://github.com/timescale/pgai/security/advisories/GHSA-89qq-hgvp-x37m
[wiz]: https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066
[cisa]: https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction
[thn]: https://thehackernews.com/2025/03/github-action-compromise-puts-cicd.html
