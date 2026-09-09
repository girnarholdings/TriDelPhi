## Summary

- Harden the existing scanner and beginner workflows (includes the earlier local hardening commit).
- Add `tridelphi audit` for the three native offline scanners, with explicit partial-coverage and exit-code reporting.
- Add GitHub-App-authenticated scan portal, PKCE/browser-bound single-use login, short-lived sessions, fresh installation/identity checks and server-side paid-tier denial.
- Free scans use a checked handoff to a pinned trusted TriDelPhi Codespace under the user's own GitHub billing; no automatic machine creation or Cloudflare fallback.
- Configure `tridelphi-security` (App ID 4889186) and the owner-approved `scan.tridelphi.com` custom domain without replacing the homepage.
- Add Windows-compatible exposure discovery and native static acceptance CI for macOS, Linux and Windows.

## Privacy and release boundaries

No repository source, scan results or training examples are collected by this portal. Short-lived authentication credentials remain server-side; Codespaces storage is user-owned and persists until deletion/provider cleanup. This is not a provider-wide zero-retention claim.

**Paid scanning is reserved but disabled**, including for pilot entitlements. No payment processor, isolated paid backend or embedded Codespace scanner UI is shipped here. Production launch remains gated on provider authentication, DNS readiness, the App secret and real GitHub/Codespaces acceptance tests.

## Validation

- 862 Python tests passed; 13 optional-tool skips on local macOS/Python 3.12.
- 32 portal authorization/billing/security tests passed.
- 37 existing bot checks passed in the preceding validation pass; bot implementation unchanged.
- Ruff and whitespace checks passed.
- Wrangler 4.120.0 deployment dry-run passed; it is not a live deployment.
- Cross-platform CI is configured; Windows/Linux execution remains to be confirmed by GitHub Actions.

## Deployment handoff

See `docs/DEPLOYMENT_HANDOFF.md` for exact identifiers, blocking access errors, DNS precautions, secret setup, publication commands, live acceptance tests and rollback guidance. No real secrets are committed. Do not merge/deploy on the assumption that a successful build proves the live OAuth or Codespaces flow.
