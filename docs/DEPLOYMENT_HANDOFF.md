# TriDelPhi deployment and GitHub publication handoff

Updated: 2026-09-10. **The callback runtime fix is deployed; fresh real-user
sign-in acceptance is still pending. The App secret is configured.**
[PR #70](https://github.com/girnarholdings/TriDelPhi/pull/70) is merged as
`84b0a10fb28ab679fdba2069c4b6e1487e93c44e`. The deployed callback fix is in
the follow-up PR #71, along with this updated handoff.
The owner migrated nameservers and confirmed this account uses **Workers Free**.
The agent deployed only `tridelphi-scan-portal` and attached `scan.tridelphi.com`.
No changes were made to the apex homepage, email records, App settings or billing.

## Deployment receipt and immediate next step

### Automatic installation follow-up

Sign-in now redirects verified users with no active App installation to GitHub's
fixed installation page, instead of returning the installation-required JSON.
No scan session is created before installation passes. Existing session state
is removed; login/session cookies are cleared. API routes remain fail-closed.
The new `/auth/installed` endpoint discards all installation query parameters
and redirects to `/auth/login` for fresh PKCE and identity/installation checks.
Validation: 36 Node unit tests + 5 workerd runtime tests pass (41 total).

**One-time owner setting still required:** in the existing GitHub App settings,
set **Post installation → Setup URL** to
`https://scan.tridelphi.com/auth/installed`; enable **Redirect on update**.
Leave **Request user authorization (OAuth) during installation** unchecked so
GitHub uses the Setup URL, not an unsolicited callback without portal PKCE/state.
Keep Callback URL `https://scan.tridelphi.com/auth/callback` unchanged.
Until configured, installation redirects work but users must return and click
Sign in manually. A forged installation ID never authenticates anyone.
See [GitHub Setup URL documentation](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/about-the-setup-url).

The deployment receipt below records the earlier runtime fix; the follow-up
installation deployment receipt is recorded in PR #71.

- Portal: https://scan.tridelphi.com
- Account: `1b5410140e248d8064f8ef81c8c52a1c`
- Active zone: `cf76915fb3935c4d8059d4067dc9214e`
- Callback fix deployed at: `2026-09-10T13:42:14Z`
- Deployment: `acaa0701-e693-42bb-9284-3eaf733ec0d1`
- Version: `0660df04-a629-4418-9ac6-cc42c803e5bd` (100% traffic)
- Custom-domain association: `40f259fa9cdd056443d3d21d584783fd1e95975c`
- SQLite Durable Object migration: `v1`, class `PortalState`
- Worker preview URLs and workers.dev are disabled; observability is disabled.
- No paid execution backend, AI service, Codespace, or plan upgrade was started.

**The owner already added `GITHUB_CLIENT_SECRET` as a Secret. Do not rotate it
just to retry sign-in.** The binding is verified by name/type only; its value was
not retrieved. No App private key is needed for the portal's user-token flow.
Start fresh at the portal and click Sign in with GitHub; an old callback URL
cannot be reused because login state is consumed once.

The prior callback 503 was reproduced in workerd using fake credentials:
Workers rejects `redirect: "error"` before making the token request. Both token
exchange and authenticated GitHub API calls now use `manual`; their non-2xx
gates reject redirects without following them. Four actual-runtime tests cover
successful session creation/revalidation, invalid grants, token/API redirects,
and callback replay. All outbound test requests are intercepted; no credentials
or raw production exceptions are logged.

Live checks after the fix: page/JS/CSS/config 200, anonymous session 401,
deliberately invalid-code callback 401 (previously generic 503), replay 401.
This proves the runtime crash is fixed, not that the real secret and full
provider authorization flow have passed. The owner must complete fresh sign-in.

Then run the live acceptance checklist below. Until that succeeds, this is a
deployed setup page, not a completed hosted-scanning launch. Do not add a homepage
scan link yet. No source/report uploads are accepted by the portal.

## Owner spending rule — mandatory for all future work

**Never spend money on Cloudflare or anywhere else without asking the owner
first and receiving explicit approval.** An instruction to deploy is not an
approval to incur charges, enable a paid plan, start billable compute, purchase
credits or increase a spending limit. Unknown billing status means stop before
resource creation. Free-tier allowances and budget alerts are not proof of a
hard spending cap on a paid account. Do not create even a test Codespace until
its billing consequences are verified or separately approved. Keep paid scanning
disabled and never introduce an automatic paid fallback.

## Decisions and configured identity

| Item | Value |
|---|---|
| Local checkout | `/Users/kathanthakkar/VibeCode/TriDelPhi` |
| Repository | `https://github.com/girnarholdings/TriDelPhi` |
| Published branch | `codex/fortify-beginner-followups` |
| Pull request | `https://github.com/girnarholdings/TriDelPhi/pull/70` |
| PR base | `main` |
| Homepage (leave intact) | `https://tridelphi.com` |
| Portal (owner-approved) | `https://scan.tridelphi.com` |
| GitHub callback (must match App settings) | `https://scan.tridelphi.com/auth/callback` |
| GitHub App | `https://github.com/apps/tridelphi-security` |
| App owner | `girnarholdings` |
| App ID | `4889186` |
| Client ID | `Iv23li3y8yo2DOaLlZ7K` |
| Worker name | `tridelphi-scan-portal` |
| Configuration | `portal/wrangler.toml` |
| Pinned scanner candidate | `78fb22015299b3fc98b2bfbdc4e3c0a06aa469b8` |

Public identifiers are committed. **No real client secret, private key, GitHub
token or Cloudflare token is in this document or the configuration.**

The original idea of placing the portal at `/scan/` on the homepage was replaced
with the owner-approved separate subdomain. Keep that separation: host-only
portal session cookies must not be delivered to the homepage's hosting provider.

## Current access and remaining blockers

1. Cloudflare MCP read/write access works. The active zone and deployed Worker
   are verified. Billing API reads still fail with error `10000`; the **owner's
   explicit Workers Free confirmation on 2026-09-10** resolved the plan blocker.
   No subscription changes were made. Recheck before deploying to another
   account or enabling any additional products. Terminal Wrangler is still
   unauthenticated; MCP authorization does not authenticate the CLI.
2. `GITHUB_CLIENT_SECRET` is present as `secret_text` and was preserved during
   the callback fix deployment. The callback URL is owner-confirmed. Real OAuth
   completion, installation consent and Codespaces eligibility still need the
   live acceptance checks below.
3. Public nameservers now match Cloudflare: `dalary.ns.cloudflare.com` and
   `eoin.ns.cloudflare.com`. Authoritative DNS and Cloudflare's public resolver
   resolve `scan.tridelphi.com`. This Mac initially retained a negative cached
   result; HTTPS was tested against the returned Cloudflare address with the
   real hostname and normal certificate verification, never `curl -k`.
4. Terminal Git push authentication failed with
   **“could not read Username for 'https://github.com': terminal prompts disabled.”**
   `gh` is not installed/on PATH in the agent environment.
5. GitHub connector write access is now confirmed: creating the requested remote
   branch succeeded after reauthentication. The previous integration 403 is
   resolved. Terminal Git credentials remain separate; publication uses the
   GitHub Git Data API, with complete tree-hash verification before updating the
   branch. Do not force-push the old local history over the published API history.

The TriDelPhi App authenticates portal visitors. It is **not** the Git credential
used by Codex/the terminal to publish this repository. Do not broaden its runtime
permissions just to solve the publication problem.

## Local work and validation

The preserved original local branch contains earlier hardening commit
`dca62051daaf0710c9bb1d53a20b532ffe38307f`, then portal/audit implementation commit
`dba0783dc7873bb122b10b3731a080e138f3e576`, then the deployment configuration and
handoff commit. API publication preserved its exact file tree under new commit
IDs. Current verified merged main is `84b0a10fb28ab679fdba2069c4b6e1487e93c44e`;
refresh remote state before further publication.

Completed validation:

- Python: **862 passed, 13 optional-tool skips** on local macOS/Python 3.12.
- Portal: **32 passing tests**, covering identity, installation, PKCE/state,
  revocation, expiry, request boundaries, billing ownership and paid-tier denial.
- Callback fix: **4 additional passing actual-Workers-runtime tests**, also
  wired into CI. Node-only mocks had accepted a fetch option workerd rejects.
- Existing webhook bot: **37 passing checks**, rerun in this publication pass;
  its implementation is unchanged by this deployment update.
- `ruff check tridelphi/ tests/ scripts/` and `git diff --check` pass.
- Wrangler 4.120.0 deployment **dry-run** bundles the Worker, 3 static files,
  Durable Object and rate-limit bindings. Dry-run does not validate credentials,
  DNS ownership, the live App callback or actual Codespaces billing/availability.
- The prior local workerd smoke test served the page with HTTP 200 and returned
  HTTP 503 for unconfigured authentication, with no-store and security headers.
- All 13 [GitHub CI jobs](https://github.com/girnarholdings/TriDelPhi/actions/runs/34417173417)
  passed on the merged PR head, including macOS/Linux/Windows native audit,
  Python 3.11/3.12/3.13, real-scanner ladder and the aggregate gate.
- On deployment day, all 32 portal tests and Wrangler 4.120.0 dry-run passed again.
- Live portal HTML/CSS/JavaScript each returned HTTP 200 with byte-for-byte
  matches to local assets. HTTPS certificate validation succeeded. CSP, no-store,
  HSTS, frame denial and nosniff headers were present.
- Before the owner added the secret, dynamic routes returned the expected 503
  setup error. After the callback fix, live config returns 200, login redirects
  303, anonymous session is 401 and invalid-code/replayed callbacks are 401.
  A real successful authentication/scan round-trip is not yet claimed.
- Apex homepage returned HTTP 200 from GitHub Pages, unchanged.

## 1. GitHub publication and local history

The GitHub connection can publish without terminal Git authentication. Publication
uses Git Data API trees and commits on `codex/fortify-beginner-followups`, based
on `152507f801bb0f55af862c41d91ad92fd9915f61`. The initial published source tree
was verified to exactly match local candidate `1258cca290d2221eb77380822affcbf457051527`
(tree `01f81230e177448e493da8a4f9a9b3e4c8405d32`). A follow-up updates the
scanner pin to the published candidate and records this handoff/spending rule.
Published candidate commit: `78fb22015299b3fc98b2bfbdc4e3c0a06aa469b8`.
PR: https://github.com/girnarholdings/TriDelPhi/pull/70 (merged).

API-created commits have different IDs from the original local commits. Preserve
the original `codex/fortify-beginner-followups` local branch and the full-history
backup at `outputs/tridelphi-ready-to-publish.bundle` in the Codex workspace.
For continuing work, fetch the published branch and use a separate tracking
branch, `codex/published-portal`, after verifying the working tree is clean.
Do not force-push the original local branch over the API-published branch.

If terminal publishing is desired later, use normal GitHub CLI/Desktop login and
the credential manager, never a token in a remote URL or shell command. Classic
OAuth needs the `workflow` scope for workflow changes; fine-grained credentials
need Contents, Workflows and Pull requests write for this repository.
PR #70 is merged; follow-up changes belong on a new branch from current main.
Refresh remote state, inspect conflicts and rerun affected tests before publication.

**Pinned scanner prerequisite:** verify that GitHub can retrieve the pinned
commit and its devcontainer before deploying the portal. After review/merge,
especially a squash merge, update `SCANNER_REF` to the tested merged or release
commit in a follow-up change. Do not switch to a moving branch name.

## 2. Verify the existing App, not a new one

Open [the existing App settings](https://github.com/settings/apps/tridelphi-security)
as `girnarholdings`. Confirm:

- Homepage: `https://tridelphi.com`.
- Callback: **`https://scan.tridelphi.com/auth/callback`** (the root-domain callback
  discussed earlier is no longer the configured callback).
- User-token expiration enabled, device flow off.
- Repository permissions: Codespaces read/write and mandatory Metadata read.
  The GitHub eligibility endpoint requires Codespaces write even though the
  portal does not create machines automatically. No Actions, Workflows or
  Codespaces secrets permission is needed by this portal.
- Install the App on the trusted `girnarholdings/TriDelPhi` scanner repository.
  Test visitor authorization and selected-repository installation using a second
  account; installation alone is not browser sign-in.
- Generate the client secret if needed and enter it directly into Wrangler's
  interactive secret prompt below. A JWT/private key is not needed for this flow.

If you changed permissions after an installation, approve its pending permission
update. Do not assume a previously issued authorization already has new access.

## 3. Prepare Cloudflare and DNS without breaking the homepage

The owner completed the migration and `tridelphi.com` is active in the account
above. Do not repeat the migration or change nameservers. Preserve all existing
A/AAAA/CNAME/MX/TXT/CAA, verification records and DNSSEC settings. The registrar
and the GitHub Pages homepage remain unchanged. This handoff does not authorize
deleting DNS records or moving email/hosting.

The custom-domain entry attaches **only `scan.tridelphi.com`**, not the apex or
`www`. Do not replace the homepage's DNS target with this Worker. Check for an
existing conflicting record on `scan` before adding the custom domain.

Reference: [Cloudflare Custom Domain prerequisites](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/).
If a DNS migration is not wanted, explicitly agree on a permanent workers.dev
staging origin and change both App callback and `PUBLIC_ORIGIN`; do not silently
enable alternate origins or temporary accounts. This config keeps them disabled.

## 4. Verify no-charge operation, authenticate, store the secret and deploy

**Stop before the write commands below unless the spending rule above is met.**
Verify the correct account's Workers plan in the dashboard or through a
read-authorized billing connection. Cloudflare documents SQLite Durable Objects
on the Free plan with operations failing at free limits; paid plans can bill
usage. Do not infer which plan this account uses from the availability of the
API, an existing subscription, a Free DNS zone, or a successful dry-run.
See [Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/)
and [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/).
Record the plan check before proceeding. Never upgrade automatically.

For the first deployment this requirement was satisfied by the owner's explicit
Workers Free confirmation. The CLI remained unauthenticated, so the agent used
Wrangler only for bundling/dry-run and deployed through Cloudflare's official
asset-upload and Worker APIs using the authorized connection. Three public
assets were uploaded with short-lived upload credentials held only in process
memory; no account token, App secret or upload credential was saved to Git.
Remote bindings were checked against `portal/wrangler.toml`, including the
unchanged immutable scanner pin and empty paid entitlements.

Wrangler 4.120.0 dependencies already exist under `bot/node_modules` on this Mac.
The bundled Node runtime is not on the default shell PATH. For this checkout:

```bash
cd /Users/kathanthakkar/VibeCode/TriDelPhi
export PATH="/Users/kathanthakkar/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin:$PATH"
node bot/node_modules/wrangler/bin/wrangler.js login
node bot/node_modules/wrangler/bin/wrangler.js whoami
node bot/node_modules/wrangler/bin/wrangler.js deploy --config portal/wrangler.toml --dry-run
node bot/node_modules/wrangler/bin/wrangler.js secret put GITHUB_CLIENT_SECRET --config portal/wrangler.toml
node bot/node_modules/wrangler/bin/wrangler.js deploy --config portal/wrangler.toml
```

Select the correct Cloudflare account. If you have several accounts, set the
nonsecret `account_id` in `portal/wrangler.toml` after confirming it. For a fresh
machine install Node 22+ and run `npm ci` inside `bot` to get the locked tooling.
Do not commit `node_modules`, `.dev.vars`, Wrangler auth files, logs or tokens.

This Worker now exists. Do not recreate it or replay migration `v1` manually.
The secret already exists: preserve it, the assets, and existing bindings on
code-only updates. The callback fix used API `keep_assets: true` and
`keep_bindings` for assets, plaintext vars, secrets, Durable Objects and rate
limits, with observability/logpush disabled. Do not claim a working login merely
because the static page is reachable.

If using an API token instead of browser login, use a scoped deployment token
for the correct account and zone. Store it securely as `CLOUDFLARE_API_TOKEN`,
never in Git or this document. The live GitHub App client secret is a separate
Worker secret; setting the Cloudflare token does not provide it.

Keep `PAID_ENTITLEMENTS = "{}"`. Paid scanning is deliberately unavailable even
to pilot paid users; this launch does not enable an execution backend or checkout.

## 5. Live acceptance checks before linking from the homepage

1. Confirm the original `https://tridelphi.com` homepage still loads normally.
2. Confirm `https://scan.tridelphi.com` has a valid certificate and serves the
   scan page, CSS and JavaScript. Do not bypass certificate checks for production.
3. Confirm `/api/config` returns the correct App installation link and anonymous
   `/api/session` returns 401 (not 503). No-store/security headers should be present.
4. Complete sign-in, return through the configured callback, and confirm only
   opaque HttpOnly/Secure/host-only session cookies are set. Never paste callback
   URLs, cookies or tokens into an issue, log dump or chat.
5. Test revoked/suspended/missing installation and expired login/session paths.
6. Test Codespaces permission/availability failure and a different billable owner:
   no paid fallback and no machine created by the portal.
7. For the positive path, verify the creation page uses the pinned trusted scanner
   commit and `.devcontainer/scan/devcontainer.json`. Confirm GitHub displays the
   signed-in user as payer before consenting to create a machine.
8. Upload a harmless source ZIP into that Codespace, run `tridelphi audit` on it,
   and verify the report and incomplete/error behavior. Do not install target
   dependencies, start the target's devcontainer, or run its setup scripts.
9. Stop and **delete** the test Codespace. Stopping alone retains files/storage.
10. Verify free `/api/scan` calls return 402 and operator-paid pilot calls return
    503. There must still be no upload processing, scan containers or auto-upgrade.
11. Only then add a homepage link to `https://scan.tridelphi.com`.

## Rollback and known remaining work

If the portal fails, remove only its homepage link and disable only the scan
Worker's custom-domain association, or roll back that Worker's version. Preserve
the apex website, unrelated DNS records and the existing webhook bot. Revoke the
App secret/user authorization if exposed; do not publish diagnostics containing
credentials. Review provider certificate cleanup separately if deleting a domain.

This is a **manual Codespaces handoff** plus offline audit, not an embedded
one-click scan UI. Paid containers, payment verification, in-website results,
automatic private-repo retrieval, opt-in redacted training donations and the AI/
device-protection roadmap are not implemented. Source/report uploads are absent
from the portal; short-lived authentication metadata and user-owned Codespace
storage mean this is not provider-wide zero retention. More architecture detail:
[portal README](../portal/README.md).

## Resume instructions for the next agent

Read this document and `portal/README.md`, inspect Git status, and preserve local
commits. Do not restart the implementation or recreate the App. Verify GitHub and
Cloudflare write access independently; GitHub's earlier 403 is resolved. Respect
the mandatory owner spending rule. Do not ask for secrets in chat. Complete
App secret → live OAuth/installation verification → Codespaces acceptance,
updating this handoff with actual results. The code is merged and the Worker is
already deployed. Do not repeat solved authentication/DNS work or mark the full
scanning workflow complete on the strength of a reachable setup page.
