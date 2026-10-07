# Dogfood report

Blunt pass on TriDelPhi after PR #76 (`3d69340`, `tridelphi launch`) landed on `main`.
This branch does not tag a release, does not publish to PyPI, and does not change
`ACTION_SHA` in `tridelphi/release.py`.

Baseline is `main` at `3d693401d70225051bd7b114a20d6b1b23d23286`.
Package version stays **0.2.0**. Action pin stays **`v3.2.0`** /
`b7d5f909aab5ae8a118a0e43c7302859d3f1bca9`. `PYPI_PUBLISHED` stays `False`.

A clean `tridelphi` run is not a compliance certificate and not legal advice.

## Commands

Fresh installs, from a machine that did not already have TriDelPhi:

```console
python3 -m venv /tmp/td-fresh
/tmp/td-fresh/bin/pip install /workspace
python3 -m venv /tmp/td-git
/tmp/td-git/bin/pip install 'git+https://github.com/girnarholdings/TriDelPhi'
python3 -m venv /tmp/td-dev
/tmp/td-dev/bin/pip install -e '.[dev]'
```

`td-fresh` and `td-git` both resolved **tridelphi 0.2.0** from `main` (the before
column). `td-dev` is the editable checkout used for tests and the after column.
`python3 -m venv` needed the distro `python3.12-venv` package; `ensurepip` is
not installed by default on this image.

Doors, before (`/tmp/td-fresh/bin/tridelphi`) and again after
(`/tmp/td-dev/bin/tridelphi`), against this repo:

```console
tridelphi --version
tridelphi --help
tridelphi start .
tridelphi . --format text --fail-on critical
tridelphi . --format text --fail-on warning
tridelphi . --format text --fail-on none
tridelphi .github/workflows --format text --fail-on none
tridelphi . --format markdown --fail-on none
tridelphi . --format sarif --fail-on none
tridelphi scan . --format text --fail-on none
tridelphi audit . --format text --fail-on none
tridelphi expose . --format text --fail-on none
tridelphi launch . --format text --fail-on none
tridelphi launch . --format text --fail-on warning
tridelphi launch site --format text --fail-on none
tridelphi launch portal --format text --fail-on none
tridelphi launch site --format markdown --fail-on none
tridelphi launch site --format sarif --fail-on none
tridelphi privatize .
tridelphi init --help
tridelphi fix --help
tridelphi guard --help
tridelphi gate --help
tridelphi attest --help
tridelphi verify --help
```

`init --local` on a non-git directory exits 2 (“not a git repository”).
`init --wizard` with no TTY exits 1. Both are the existing contract.
SARIF written under `/opt/cursor/artifacts` exits 2 because that directory is a
symlink and the tool refuses to write through one. Stdout SARIF itself was valid.
`privatize` was answered `n` so it did not rewrite anything.

`--format markdown` was rejected by argparse before this branch (`launch` only
honored `--markdown`). It is a real choice now, for the core door and for `launch`.

Third-party, on this repo, before the edits (tools under `/tmp/td-tools` and the
dev venv; versions are the ones those installs actually ran):

```console
ruff check .
mypy tridelphi
bandit -r tridelphi -ll
pip-audit
osv-scanner scan --offline -r .
zizmor --offline .github/workflows
actionlint -no-color .github/workflows
gitleaks detect --no-banner
trufflehog filesystem .
python -m build
twine check dist/*
```

`osv-scanner`’s `.tar.gz` asset URL 404s. The raw binary
`osv-scanner_linux_amd64` at v2.2.4 (the pin in `scripts/install-ladder.sh`) works.
`actionlint -color=never` is not a flag; the flag is `-no-color`. The first
actionlint invocation also failed because it was not started in the repo root
(`could not read action.yml`). Re-run from `/workspace` is clean.

Logs from this pass live in `/opt/cursor/artifacts/dogfood/` (`*-before*`,
`after-*`, `after2-*`, `pytest-*.txt`). They are local artifacts, not part of
the commit.

## Tests

| Run | Result |
|---|---|
| `pytest` on `main` before these edits | **1059 passed, 8 skipped** (526.95s) |
| `pytest` on this branch | **1072 passed, 8 skipped** (595.14s). Exit 0 |

`ruff check .` was clean before the edits and clean after.

## Before / after on this repo

| Door | Before (`main` @ `3d69340`) | After |
|---|---|---|
| Core Rule-of-Two (`.`, and `.github/workflows`) | 0 critical, 0 warning, 7 notes (unresolved matrix / environment). Exit 0 at `--fail-on critical` | Same 7 notes. Exit 0 |
| `scan` (pre-install) | **DO NOT INSTALL.** Criticals: `eval(atob` comment in `preflight.py`, `~/.ssh` gloss plus the letters `ncat` in the detector, and “do not guess silently” in `.claude/agents/fixture-adversary.md`. Duplicated under setuptools `build/lib/` | **0 critical.** Exit 0. Remaining warnings are the README, `docs/SCAN_RULES.md` and this report showing `curl \| bash`, `eval(atob)`, and `~/.ssh` on purpose, plus the key-name list in `tridelphi/expose.py` |
| `audit` | 5 critical, 16 warning, 9 note. Exit 1 | **0 critical, 13 warning, 9 note** after the review below (9 before it). Exit 0 at the default gate. Warnings are the doc examples above, the `expose.py` key-name list, and the real missing privacy / terms / DMCA links on `portal/public/index.html` |
| `expose` | Clean except an informational “shipped JS is not minified” on `site/` and `portal/`. Exit 0 | Same |
| `launch .` | Privacy + terms warnings on `portal/public/index.html`. **DMCA falsely quiet**, because `docs/LAUNCH_RULES.md` contains the text `/dmca`. HIPAA, GLBA, and “written by our team” false positives on `build/lib/.../launch_rules.yml` and the rule table | DMCA, privacy, and terms warnings on the portal page (true). No HIPAA/GLBA/AI false positives. No PostHog false positive on `launch.py` |
| `launch site` and `launch portal` | 3 warnings: missing DMCA, privacy, terms. Self-hosted fonts, no analytics. Exit 0 at `--fail-on critical`, exit 1 at `--fail-on warning` | Same 3 warnings, now with an example snippet and a source URL. Still the right result |
| `privatize .` | Offered setuptools `build/` as the obfuscation target. Declined, exit 0, nothing written | “no built output”. Exit 2. Does not offer `build/lib` |
| `start`, help, `init`/`fix`/`guard`/`gate`/`attest`/`verify` help | Ran. No crash | Same. `--format markdown` accepted |

`launch` on the repo root still reports the legal-page gap **once**, anchored at
`portal/public/index.html`. `site/` has the same gap. Scan `site/` and `portal/`
separately before a deploy; a footer link anywhere in the tree satisfies the
repo-level check. That is the existing contract, and it is why the two site
directories were scanned on their own.

## Findings

Severity is the tool’s own word. “Fixed” means this branch. Owner-only items are
not papered over with invented legal copy.

| Severity | Where | What was wrong | Status |
|---|---|---|---|
| Critical (false) | `tridelphi/preflight.py` comment with the literal `eval(atob(` | Pre-install scan said the file evaluates JavaScript. It is a comment describing the detector | **Fixed.** A Python `#` comment is masked only when the file parses to the same AST with and without it, so a `#` inside a string is never blanked. JS/TS comments are **not** masked: a pattern cannot tell `//` from the slashes in a string or regex literal, and masking them let a payload hide (see Review follow-up). Agent-file comments are not masked |
| Critical (false) | `tridelphi/preflight.py` gloss `~/.ssh`, upgraded because the regex source contains `ncat` | “Also sends data over the network” was the detector matching itself | **Fixed.** Gloss no longer contains that path. `ncat` counts as a word unless a backslash precedes it (a regex escape in the detector's own source), so `["ncat", host]` in a subprocess list still counts. A key path next to a network tool is critical in code and a warning in documentation |
| Critical (false) | `.claude/agents/fixture-adversary.md` “do not guess silently” near “read-only token” | Bare word “silently” plus the word “token” was treated as a poisoned skill | **Fixed.** “Silently” and “covertly” still gate, including a bare “do this silently”. They are skipped only after a negation (“not”, “never”, “no”, or an “n't” word within two words), so “do not guess silently” does not gate |
| Critical (false, duplicate) | `build/lib/tridelphi/...` after `pip install .` | setuptools copied the package and the scanner reported every hit twice | **Fixed.** A root `build/lib` file is skipped only when it is byte-identical to its source, and `*.egg-info` only at the root or under `src/`. A changed `build/lib` copy, a `build/lib` deeper in the tree, and `.eggs` (third-party `setup_requires` code) are scanned |
| Warning (false) | `tridelphi/expose.py` set of key *names* (`id_rsa`, …) | A bare filename was a credential path | **Changed in review.** A bare `id_rsa` is how code names the file (`path.join(home, '.ssh', 'id_rsa')`), so the name counts again. The list is a warning, which does not gate |
| Warning (false) | `tridelphi/data/launch_rules.yml` and `build/lib/.../launch_rules.yml` | HIPAA/GLBA/AI fired because the rule table contains `name="diagnosis"`, `name=`, “written by our team”, and `openai` | **Fixed.** YAML/JSON/TOML/Markdown are not the app. Health and bank checks require a real `<form>` or `<input>` |
| Warning (false) | `tridelphi/launch.py` string `startsessionrecording` | The PostHog detector matched its own source and reported CIPA session replay | **Fixed.** PostHog matching is limited to HTML/JS/CSS, same as the other recorders |
| Warning (false negative) | Repo-root `launch` | `docs/LAUNCH_RULES.md` mentioning `/dmca` suppressed `missing-dmca-agent` for the real sites | **Fixed.** A DMCA link counts only on a visitor page |
| UX | `tridelphi . --format markdown` | argparse rejected `markdown` even though the renderer exists | **Fixed.** Core door prints the checklist markdown. `launch --format markdown` prints the launch report |
| UX | Launch findings | Fix text had no copy-paste example and no citation | **Fixed.** Text, markdown, and SARIF include Example and Source. SARIF `helpUri` is the first URL in the citation |
| Warning (true) | `site/index.html`, `site/setup.html`, `portal/public/index.html` | Visitor pages. Fonts are self-hosted (`@font-face`, Barlow). No analytics tags. **No privacy policy, no terms, no DMCA agent link.** The portal class `privacy` is a layout hook, not a policy | **Not fixed here.** Writing those pages is legal copy, not a scanner change. See owner list |
| Warning (intentional) | `README.md` and `docs/SCAN_RULES.md` | They show `curl \| bash`, `eval(atob)`, and `~/.ssh` so a reader can see the shape. `scan` warns. That is the detector working | **Left.** Deleting the examples would hide the rule |
| Note | `.github/workflows/*` | Unresolved matrix, `runs-on`, and environment approvals cannot be proved from files | **Left.** The note says unknown, not passed |
| Note | `site/` and `portal/` JS | `expose` says shipped JavaScript is not minified | **Left.** Minify at the bundler when those assets are built for production |
| Info | `tridelphi/init_cmd.py` CodeQL action SHA | trufflehog unverified Github detector. gitleaks: no leaks in 123 commits | **Not a secret** |
| Low | bandit on `tridelphi/` | 16 low, 0 medium, 0 high. Mostly B105 on the emoji “✅” and on fix-text that contains the word “password” | **Not a bug.** No `#nosec` spam added |
| Typecheck | `mypy tridelphi` | 36 errors, pre-existing (`preflight`, `checklist`, `cli`, `apply`, parsers). Not a crash | **Not boiled.** ruff is the bar this repo enforces. The launch PostHog walrus that mypy flagged was rewritten while fixing the detector |
| Advisory | `scripts/semgrep-requirements.txt` pyjwt 2.13.0; `.tridelphi/privatize/package-lock.json` brace-expansion 1.1.18 and undici 6.28.0; `bot/package-lock.json` sharp 0.35.4 (dev) and undici 7.29.0 (dev) | osv-scanner: 5 packages, 31 known vulns (1 critical, 11 high, 15 medium, 4 low). `pip-audit` on the installed env: no known vulns (TriDelPhi itself skipped, not on PyPI) | **Bumped in review**, each release at least seven days old: bot wrangler 4.144.0 (undici 7.29.1) with `sharp` overridden to 0.35.5; privatize undici 6.29.0 and brace-expansion 1.1.21. **PyJWT waits:** semgrep 1.177 and 1.178 pin `pyjwt~=2.13.0`, and 1.179.0 (the first to admit PyJWT 2.15) passes the seven-day minimum on Oct 9, 2026. The weekly `dependency-advisories` run on Oct 5 was red, which is its notification |
| Packaging | `python -m build`, `twine check` | On `main`, both sdist and wheel passed `twine check`. On this branch, `python -m build --wheel` of the edited tree passed `twine check`. The wheel contains `tridelphi/data/launch_rules.yml` (rule table version 2, 29 rules) and `tridelphi = tridelphi.cli:main`. Installed from that wheel: `tridelphi --version` is 0.2.0, `launch` on `next-clean` exits 0, `launch --fail-on warning` on `next-trap` exits 1. Version 0.2.0 matches `pyproject.toml` and `tridelphi/__init__.py` | **Checked.** Not published |
| Action | `action.yml` | Composite action not executed on GitHub Actions from this environment. `actionlint -no-color` on `.github/workflows` from the repo root: no findings. zizmor 1.29.0 offline: no findings (1 ignored, 26 suppressed). Install step is `pip install $GITHUB_ACTION_PATH`, the same as `pip install .` | **Left.** Shipping the action SHA is a release |
| Link | `https://github.com/marketplace/actions/tridelphi` | 404 | **Expected.** `docs/MARKETPLACE.md` says the listing is not published |
| Performance | `launch` ~1s, `audit` a few seconds, full `pytest` ~9–10 min | Not a hang. No change aimed at the suite runtime | **Left** |

`git+https://github.com/girnarholdings/TriDelPhi` (main) matched the local
`pip install .` of `main`: same 0.2.0, same launch result on `site/`.

## What `launch` detects now

Rule table version is **2**. Every rule has a primary-source citation (with an
`http` URL) and a copy-paste snippet. Messages and fixes still name only three
dollar figures: about **$53,000** (COPPA; the exact $53,088, the 2025 level the
FTC kept for 2026, lives in the citation),
about **$5,000** (CIPA statutory figure, not a prediction), and **$6** (DMCA
filing fee). A citation may mention other amounts. The report says this is not
legal advice, and a clean run is not a certificate.

Checked against fixtures in `tests/fixtures/launch/`: the original vibe app and
clean app, plus Next.js and Vite trap apps and Next.js and Vite clean apps.
Comments, `*.min.js`, Markdown, and YAML that only mention a trap stay quiet. A
comment is found outside string literals, so `href="//fonts.googleapis.com"` and
a `"/*"` route string are still code.
`next/font/google` and a self-hosted `@font-face` stay quiet.

| Trap | What a file has to show | Primary source |
|---|---|---|
| COPPA age gate | Signup (path, “create an account”, or Firebase/Supabase `.signUp(` / `createUserWithEmailAndPassword`) and no age or date of birth | 15 U.S.C. §§ 6501–6506; 16 C.F.R. Part 312 as amended, 90 Fed. Reg. 16918 (Apr. 22, 2025), effective June 23, 2025, most operators comply by Apr. 22, 2026. https://www.federalregister.gov/documents/2025/04/22/2025-05904/childrens-online-privacy-protection-rule |
| Third-party fonts | Google Fonts, gstatic, Typekit, Adobe Fonts, Font Awesome CDNs (cdnjs, jsDelivr, BootstrapCDN, cdnfonts), Hoefler, `fast.fonts.net` | LG München I, 20 Jan. 2022, 3 O 17493/20. GDPR Art. 6; ePrivacy Directive 2002/58/EC Art. 5(3). https://www.gesetze-bayern.de/Content/Document/Y-300-Z-BECKRS-B-2022-N-612 |
| Session replay and chat widgets | FullStory, Hotjar, LogRocket, Clarity, Heap, Smartlook, Mouseflow, Inspectlet, Lucky Orange, Contentsquare, Sentry Replay, OpenReplay, Datadog RUM, Amplitude Session Replay, PostHog recording, Intercom, Drift, Crisp, Tidio, Zendesk, HubSpot, LiveChat, Olark — without a consent marker | Cal. Penal Code §§ 631(a), 637.2. Courts disagree about metadata versus contents (Popa v. Microsoft and later CIPA cases). The check does not predict liability. SB 690 (signed Sept. 30, 2026) ends private pen-register (§ 638.51) suits over websites, not § 631 wiretap claims. https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=PEN&sectionNum=631. |
| CAN-SPAM | Marketing email template missing unsubscribe or a postal address | 15 U.S.C. § 7704(a)(3)–(5). https://www.ftc.gov/business-guidance/resources/can-spam-act-compliance-guide-business |
| Auto-renewal | Subscribe / trial, or Stripe `mode: "subscription"` / `subscriptions.create`, with a price and no renewal or cancel language in that file | Cal. Bus. & Prof. Code §§ 17600–17606, AB 2863 (contracts entered, amended, or extended on or after July 1, 2025). ROSCA, 15 U.S.C. §§ 8401–8405, still in force. The 2024 FTC Negative Option / click-to-cancel rule was **vacated** by the Eighth Circuit on July 8, 2025, and is not cited as current law. The FTC reopened the rulemaking with an advance notice on March 13, 2026; no replacement rule is in force. https://leginfo.legislature.ca.gov/faces/billTextClient.xhtml?bill_id=202320240AB2863 |
| DMCA agent | Visitor pages and no `/dmca` link on a page | 17 U.S.C. § 512(c)(2). Designation expires after three years unless amended or resubmitted, 37 C.F.R. § 201.38(c)(4). Fee $6 under 37 C.F.R. § 201.3. A page is not registration. TriDelPhi does not submit the filing. https://www.copyright.gov/dmca-directory/faq.html |
| Privacy and terms | Visitor page, no policy page, no footer link. Empty or “TODO” pages do not count | GDPR Arts. 13–14; Cal. Civ. Code §§ 1798.100, 1798.130. https://oag.ca.gov/privacy/ccpa |
| Analytics / ads before consent | GA, GTM, Meta, TikTok, LinkedIn, X, Google Ads, Segment, Mixpanel, Amplitude, HubSpot. Ad pixels without “Do Not Sell or Share” are a warning. Analytics without that link is a checklist. GPC is a checklist when an opt-out exists and the code never reads `globalPrivacyControl` / `Sec-GPC` | ePrivacy Art. 5(3); Cal. Civ. Code §§ 1798.120, 1798.135; Cal. Code Regs. tit. 11, § 7025. https://cppa.ca.gov/regulations/ https://oag.ca.gov/privacy/ccpa |
| TCPA texts | Marketing SMS/WhatsApp or Twilio, Telnyx, Plivo, MessageBird, Vonage, without express-consent language. A verification code with no promotion stays quiet | 47 U.S.C. § 227; 47 C.F.R. § 64.1200. The FCC’s 2023 one-to-one consent rule for lead generators was set aside in 2025; the statute was not. https://www.fcc.gov/consumers/guides/stop-unwanted-robocalls-and-texts |
| AI sold as human, and chatbots | Model code plus “written by our team” on a page. Chat completions with no “you are talking to an AI” sentence | FTC Act § 5, 15 U.S.C. § 45. EU AI Act, Regulation 2024/1689 Art. 50, applicable from August 2, 2026 and not postponed by the 2026 Digital Omnibus (only Art. 50(2) marking has a grace period to Dec. 2, 2026). https://artificialintelligenceact.eu/article/50/ |
| Uploads | `<input type="file">` (and common upload SDKs) with no report or DMCA path | 17 U.S.C. § 512 |
| HIPAA / GLBA | A real form collecting diagnosis/prescription, or routing number / bank account / SSN. Checklist only. Not an audit | 45 C.F.R. Parts 160 and 164; 15 U.S.C. §§ 6801–6809 |
| Vendored NOTICE | MIT/Apache/SPDX under `vendor/` or `third_party/` and no NOTICE file | Apache-2.0 redistribution terms. https://www.apache.org/licenses/LICENSE-2.0#redistribution |
| Accessibility | Images and no alt and no landmark (`a11y-primary-page`). Any `<img>` missing `alt`, even inside `<main>` (`a11y-missing-alt`). `alt=""` stays quiet. Not a WCAG audit | ADA Title III, 42 U.S.C. § 12182. DOJ web guidance, March 18, 2022. https://www.ada.gov/resources/web-guidance/ |

Not matched on purpose: comments, minified bundles, `node_modules`, `tests/`,
Markdown essays, YAML/JSON rule tables, `vendor/` (that path is the NOTICE
check), setuptools `build/lib`. Login is not signup. A password-reset email is
not marketing until it also promotes. A consent-banner *string* cannot prove
the tag waited. HIPAA and GLBA do not certify that you are a covered entity or
a financial institution.

## Third-party vs TriDelPhi on this repo

| Tool | Result | Did TriDelPhi see it? |
|---|---|---|
| ruff | Clean | n/a (style) |
| mypy | 36 pre-existing type errors | No. TriDelPhi is not a typechecker. Left as owner follow-up if mypy becomes a gate |
| bandit | 16 low, no medium/high | No meaningful overlap. The emoji and the word “password” in a fix string are not secrets |
| pip-audit | No known vulns in the installed env | TriDelPhi does not audit PyPI from `launch`/`scan`. osv-scanner is the ladder job |
| osv-scanner | pyjwt, brace-expansion, undici, sharp in pinned optional locks | **False negative if you expected `audit` to read those lockfiles offline.** `audit` does not vendor the OSV database. The workflow `dependency-advisories` job is the place those run. Called out above; not silently “fixed” by editing hashes |
| zizmor | No findings | Core door’s 7 notes are unresolved context, which zizmor does not report. Complementary, not a miss |
| actionlint | No findings once invoked correctly | Same |
| gitleaks | No leaks | `expose` also clean on committed keys |
| trufflehog | 0 verified. Unverified hit is a CodeQL action SHA in `init_cmd.py` | Correctly not a TriDelPhi secret finding |

TriDelPhi’s own false positives (the criticals on `main`) were things the
third-party tools did **not** flag. The third-party tools’ real advisories are
in pinned optional files TriDelPhi’s offline doors do not claim to cover.

## Owner-only (do not pretend this PR did these)

1. **Release.** Tag when you mean to. Until then `ACTION_SHA` stays the `v3.2.0`
   pin. Moving it to this branch’s HEAD without a tag would make the comment lie.
2. **PyPI.** `PYPI_PUBLISHED` is `False`. Do not publish from this PR. The git
   install URL is the one that works today.
3. **Legal pages for the public sites.** `site/` (tridelphi.com) and `portal/`
   (scan.tridelphi.com) have no privacy policy, no terms, and no DMCA
   designated-agent page or footer link. Write them, link them, and file the
   agent at copyright.gov. Renew it before three years. This PR does not invent
   that copy and does not submit the filing.
4. **Deploy.** Merging YAML does not update tridelphi.com or scan.tridelphi.com.
5. **Dependency pins.** undici, sharp and brace-expansion are bumped. PyJWT in
   `scripts/semgrep-requirements.txt` moves with semgrep 1.179.0 once it is seven
   days old (Oct 9, 2026); run the `pin-closure` line in `docs/RELEASES.md`.
6. **Marketplace.** The action listing 404s until someone publishes it.
7. **mypy**, if you want it as a gate. It is not clean, and this PR did not make
   it a project requirement.
8. **Minify** `site/` and `portal/` JavaScript when those bundles ship, if you
   care about the `expose` note. It is not a vulnerability.

## Review follow-up

A second pass on this branch found that several of the self-match fixes opened
places for a real payload to hide, and that the launch door's comment stripper
hid what a page loads. Each case below was critical (or detected) on `main`,
silent on the first pass, and is detected again, with a test that fails on the
first pass.

| What hid | Why | Now |
|---|---|---|
| `eval(atob(...))` after `"http://x"` or inside a JS regex class | JS `//` masking blanked the rest of the line from the slashes in a string or regex | JS comments are not masked |
| A payload in a Python f-string with a `#` (PEP 701) | `#` masking trusted the tokenizer alone | Masking is kept only when the AST is unchanged |
| Code under a dependency's `lib/build/`, or `.eggs/` | Any `build` + `lib` in the path, and `.eggs`, were skipped | Only a byte-identical root `build/lib` copy is skipped |
| `path.join(home, ".ssh", "id_rsa")` with `["ncat", host]` | The key name needed a separator, and `ncat` needed a destination after it | Both count again |
| “do this silently” next to a token | Bare “silently” was dropped | Only a negated “silently” is dropped |
| `<link href="//fonts.googleapis.com/...">`, `url(//...)`, a `"/*"` route string | `launch` blanked `//` and `/* */` with a pattern | Comments are found outside strings; `web/build/lib/` is the app |

The legal sources were checked again in October 2026: the FTC made no 2026
penalty adjustment (FR Doc. 2026-18853), reopened negative-option rulemaking
(March 13, 2026), California SB 690 was signed (Sept. 30, 2026), and the Digital
Omnibus on AI left Article 50 in place.
