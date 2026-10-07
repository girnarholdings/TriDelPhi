# Launch rules

`tridelphi launch` is the fourth door. It answers **“what lawsuit traps am I
about to ship?”** It sits next to `scan` (before you install), the core Agents
Rule of Two check (CI), and `expose` (what the shipped app leaks). It does not
replace any of them.

```console
tridelphi launch .
tridelphi launch . --format sarif --fail-on warning
tridelphi audit .          # launch is one of the native engines
```

`init` and the GitHub Action do not run this door. Wire it into CI only when
you mean to.

## What this is

A static read of files on disk. Patterns live in
[`tridelphi/data/launch_rules.yml`](../tridelphi/data/launch_rules.yml). The
detector in [`tridelphi/launch.py`](../tridelphi/launch.py) decides when a
pattern is strong enough to report. Reports go through the same SARIF helper
as `scan` and `expose` (`tridelphi-launch/<rule>`).

Every report says this, and a finding repeats it:

> This is not legal advice. A clean result is not a compliance certificate.
> TriDelPhi only matched patterns in files it could read.

A row that says **nothing found** means that pattern was absent from the files
opened. It does not mean a statute does not apply, that a child did not sign
up, or that a lawyer would clear the launch.

## Exit codes

Same contract as the other doors:

| Code | Meaning |
|---|---|
| 0 | Nothing at or above `--fail-on` (default `critical`) |
| 1 | A finding at or above `--fail-on` |
| 2 | The path is unusable, or coverage is partial. Partial is never a pass |

Launch findings are **warnings** and **notes**, not criticals. A font tag
should not turn `tridelphi audit` red the way a live key in a bundle does.
`tridelphi launch . --fail-on warning` is the strict gate. Notes (checklists)
do not fail that gate; warnings do.

No network calls. No paid APIs. No claim that TriDelPhi is a lawyer, that a
filing was submitted, or that a clean tree is compliant.

## Static detector or checklist

**Static** means the files themselves contain the bad pattern (or lack a
pattern that should sit next to one). **Checklist** means a person still has
to do something files cannot prove. High-severity checklists (health and bank
forms) are warnings so they are hard to miss, and the message says they are
checklists.

| Rule | Kind | When it fires | When it stays quiet |
|---|---|---|---|
| `coppa-age-gate` | static warning | Account signup (path, “create an account”, or Firebase/Supabase/Auth0-style `.signUp(` / `createUserWithEmailAndPassword`) and no age, date of birth, or under-13 gate | Login only. No password field and no auth SDK call. Age language on the same file. No website |
| `third-party-font` | static warning | `fonts.googleapis.com`, `fonts.gstatic.com`, Typekit, Adobe Fonts, Font Awesome CDN (including cdnjs, jsDelivr, BootstrapCDN, cdnfonts), Hoefler, or `fast.fonts.net` in HTML, CSS, or JS | Self-hosted `@font-face`, `next/font`, fontsource. A comment, a minified bundle, Markdown, or a YAML rule table |
| `session-replay` | static warning | FullStory, Hotjar, LogRocket, Clarity, Microsoft Clarity, Heap, Smartlook, Mouseflow, Inspectlet, Lucky Orange, Contentsquare, Sentry Replay, OpenReplay, Datadog RUM, Amplitude Session Replay, or a chat widget (Intercom, Drift, Crisp, Tidio, Zendesk, HubSpot, LiveChat, Olark), or PostHog with recording turned on, and no consent marker | Consent and input masking both present. SDK absent. Comment, minified file, or `vendor/` |
| `session-replay-unmasked` | checklist note | Recorder plus a consent marker, no masking setting | Masking present, or no recorder |
| `posthog-replay-default` | checklist note | `posthog.init` (or `app.posthog.com`) and recording is not switched off in code | `disable_session_recording: true`, or no PostHog |
| `can-spam-footer` | static warning | Marketing HTML under an email/newsletter/campaign path (including `.tsx` templates) missing an unsubscribe link or a physical postal address | Footer has both. Password-reset / receipt with no promotion. A sales page that is not an email |
| `auto-renewal-terms` | static warning | Subscribe / trial / upgrade control, or Stripe `mode: "subscription"` / `subscriptions.create`, with a price and no renewal or cancel language in that file | Renewal, cancel, and price sit in the same file. The 2024 FTC click-to-cancel rule was vacated; the check cites California AB 2863 and ROSCA |
| `auto-renewal-review` | checklist note | Subscribe control or Stripe subscription mode, and plan language, but no price | Price and renewal present, or no subscribe control |
| `missing-dmca-agent` | static warning | Visitor-facing pages and no `/dmca` (or copyright-agent) page or link **on a page** | A DMCA page or a link on a visitor page. A library with no website. A README that merely says “/dmca” |
| `dmca-registration-steps` | checklist note | The agent page is missing. The copyright.gov steps, the $6 fee, and the three-year renewal | A page or link exists. **A page is not proof you registered, and TriDelPhi did not submit the filing.** |
| `missing-privacy-policy` / `missing-terms` | static warning | A visitor page and no policy page and no footer link | Page or footer link present |
| `empty-privacy-policy` / `empty-terms` | static warning | The page is there and it is empty, “TODO”, or shorter than a real notice | A notice a person can read |
| `analytics-before-consent` | static warning | GA, GTM, Meta, TikTok, LinkedIn, X, Google Ads, Segment, Mixpanel, Amplitude, or HubSpot tracking and no consent-banner marker | No tag. Or a banner marker (see the checklist below) |
| `consent-order-unproven` | checklist note | A tag and a banner marker both exist. Runtime order is invisible | No tag |
| `ccpa-do-not-sell` | static warning | An **ad** pixel and no “Do Not Sell or Share” language | Analytics only (that case is the checklist). Link present |
| `ccpa-do-not-sell-checklist` | checklist note | Analytics tag, no ad pixel, no do-not-sell link | No tag, or the link exists |
| `ccpa-gpc-checklist` | checklist note | A do-not-sell marker and no Global Privacy Control read | No tag, or `globalPrivacyControl` / `Sec-GPC` present |
| `tcpa-sms-consent` | static warning | SMS or WhatsApp opt-in or a Twilio/Telnyx/Plivo/MessageBird/Vonage-style send, plus marketing language, without express-consent language | Express consent, frequency, and message-and-data rates. A verification code with no promotion. A `wa.me` social link |
| `tcpa-sms-review` | checklist note | An opt-in with no marketing words and no consent language | Consent present, or no opt-in |
| `ai-human-disclosure` | checklist note | Generative-model code **and** a visitor page that calls the output human-made | Either signal alone. The phrase in a README or a rule table |
| `ai-chatbot-disclosure` | checklist note | Generative-model code and a chat-completion call, with no “you are talking to an AI” sentence | A disclosure phrase in the same tree. Not a finding that production lacked a banner |
| `ugc-no-report-path` | static warning | A file upload and no report, moderation, or DMCA path | A report link or a DMCA page |
| `hipaa-may-apply` | checklist warning | A real `<form>` or `<input>` collects a diagnosis, prescription, or similar health field | The word in a blog, a YAML rule table, or `name=` with no form. This is **not** a HIPAA audit |
| `glba-may-apply` | checklist warning | A real form collects a routing number, SSN, bank account, or Plaid field | A card checkout that does not ask for a bank account. This is **not** a GLBA audit |
| `missing-oss-notice` | checklist note | A file under `vendor/` or `third_party/` carries an MIT, Apache, or SPDX marker and no NOTICE / ATTRIBUTION / THIRD-PARTY-NOTICES file | The notice file exists. Dependencies in `node_modules` are not scanned. Vendored files are not also treated as the app |
| `a11y-primary-page` | checklist note | At least one image, zero `alt` attributes, and no `main` or `nav` landmark | Any alt, or any landmark, or no images. Not a WCAG audit |
| `a11y-missing-alt` | checklist note | An `<img>` tag has no `alt` attribute, even when a landmark exists | Every image has an `alt`, including `alt=""`. Not a WCAG audit |

## Dollar figures

Only three numbers are named, and only because the door was built around them.
They are not a current legal opinion:

- COPPA: about **$53,000 per child under 13**
- CIPA-style session replay: about **$5,000 per session**
- DMCA designated-agent filing: **$6** (a fee, not damages)

Other rules name the statute family and the shape — per email, per
subscription, per visitor, per consumer, per text, per violation — and do not
invent an amount.

Each finding’s text report and SARIF result include a copy-paste **Example**
and a **Source** line. The SARIF rule `helpUri` is the first URL in that
source when one exists. The three dollar figures above stay in the message
and the fix. A citation may name the exact published maximum (COPPA’s
$53,088, the 2025 figure in 16 C.F.R. § 1.98, which the FTC kept for 2026)
without adding a fourth amount to the message.

## What the files are not

Trap matching ignores:

- Markdown, YAML, JSON, and TOML (a rule table that contains `name="diagnosis"` is not a clinic)
- HTML comments, `/* */` comments, and `//` comments (not the slashes in `https://`)
- `*.min.*` files and other short files with a line over 2,000 characters
- `vendor/`, `third_party/`, and `third-party/` (those directories are the NOTICE check, not the app)
- setuptools output (`build/lib`, `*.egg-info`)
- `node_modules`, lockfiles, and `tests/`

A DMCA, privacy, or terms *link* counts only on a visitor page. A sentence in
`docs/` that mentions `/dmca` does not clear a site that has no footer link.

## Honesty limits (known misses)

These are deliberate. A false alarm that blocks a launch is worse than a miss
the docs admit. A clean run is not a compliance certificate.

- Login pages are not signups, even when they link to “Sign up”.
- A password-reset or receipt email is not marketing until it also promotes.
- `next/font`, fontsource, and a self-hosted file are not third-party font loads.
- Google Tag Manager is treated as analytics, not as an ad pixel, unless an ad snippet is also present.
- A consent-banner *string* downgrades tags to a checklist. The check cannot see whether the banner runs first.
- A footer link counts even if the target page is missing.
- Markdown essays do not count as the website, so a docs-only repo is not told it lacks a privacy policy.
- Registration at copyright.gov cannot be seen, and the designation expires after three years unless it is amended or resubmitted (37 C.F.R. § 201.38). The checklist is the steps, not a status. TriDelPhi does not submit the filing.
- The 2024 FTC Negative Option Rule (click-to-cancel) was vacated by the Eighth Circuit on July 8, 2025. The check cites California’s automatic renewal law as amended by AB 2863 (contracts entered, amended, or extended on or after July 1, 2025) and ROSCA, which were not vacated. The FTC reopened negative-option rulemaking with an advance notice published March 13, 2026; until a new rule is final, it is not cited as law.
- HIPAA and GLBA are “may apply” checklists. They do not certify that you are a covered entity or a financial institution.
- `a11y-primary-page` stays quiet when any image has `alt` or the tree has a landmark. `a11y-missing-alt` still notes an `<img>` with no `alt` attribute. Neither is a WCAG audit.
- EU AI Act Article 50 (chatbot transparency, applicable from August 2, 2026) is a checklist. The 2026 Digital Omnibus on AI postponed the high-risk obligations, not Article 50; only the Art. 50(2) machine-readable marking got a grace period (to December 2, 2026) for systems already on the market. It is not a finding that a deployed chat lacked a disclosure.
- CIPA session-replay and chat-widget suits are real and the courts disagree (metadata versus contents). The check does not predict that a court would find liability. The “about $5,000” figure is the statutory number in Cal. Penal Code § 637.2, not a damages estimate. SB 690 (signed September 30, 2026) ends private pen-register (§ 638.51) suits over websites and apps; it does not touch the § 631 wiretap theory recorder suits use, so the check is unchanged.
- The project’s own `LICENSE` file is not a third-party NOTICE.

## Coverage

The walk is the same bounded, no-symlink walk `expose` uses. A file over the
read cap, a symlink that is not followed, or a directory that cannot be read
makes the result **partial** and the exit code **2**. Partial is not a pass.

## Review notes

Architecture mirrors `expose`: `launch.py` analyzes, `launch_cmd.py` renders,
the rule table is YAML, `tridelphi audit` composes the engine, and `tridelphi
start` plus the core checklist name the door. Severity stays off `critical`
so this heuristic does not share a gate with a leaked key. SARIF rule ids are
`tridelphi-launch/<id>`.
