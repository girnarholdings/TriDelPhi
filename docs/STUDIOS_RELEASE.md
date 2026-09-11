# Two-studio website release — 2026-09-11

The homepage and Manual Setup Studio now share the owner-approved navy,
amber/manual and cyan/cloud identity. The two studios are alternatives, not
consecutive product steps. New favicon, sharing image, canonical URLs and
plain-language limitations are included. See WEBSITE_BRAND_ASSETS.md for asset
provenance; PRODUCT.md and DESIGN.md record the design decisions.

## Verification

- Full Python suite: 867 passed, 13 skipped. Skips require optional semgrep,
  gitleaks, zizmor, osv-scanner, scorecard or javascript-obfuscator installations.
- Browser setup matrix: 96 generated CI configurations parsed as YAML; six
  build-command edge cases; permissions, repository validation, clipboard
  recovery, keyboard choices and unchanged preview on repository typing.
- Desktop/mobile, dark/light and 320px at 200% text checks passed. No external
  browser requests were permitted during local checks.
- Four theme tests passed, including blocked local storage and OS preference.
- Ruff, local asset/navigation/canonical validation and diff checks passed.
- Synthetic adversarial sweep: 109 attacks detected, 11 benign controls clean.
  These fixtures are not evidence of universal threat detection.

Run `python -m pytest -q`, `python scripts/check-site.py`,
`node --test tests/site-theme.test.mjs`, and `python scripts/redteam.py --show-missed`.
The optional real-browser pytest matrix needs Playwright available to Node;
set SETUP_NODE, NODE_PATH and (for installed Chrome) SETUP_BROWSER_CHANNEL=chrome.

## Publication boundaries

The homepage publishes through the existing GitHub Pages workflow after its PR
is merged into main. This branch does not replace the Cloudflare scan portal.
Portal work is in PR #71, with its own deployment receipt in DEPLOYMENT_HANDOFF.md
on that branch. Do not deploy main's older portal over that version.

No paid plan, real Codespace or external scanner service was enabled by these
tests. A live authenticated GitHub creation remains an owner-approved acceptance
test. Source is not retained for training by default; optional donations require
explicit review and consent. A clean static scan is not a safety guarantee.
