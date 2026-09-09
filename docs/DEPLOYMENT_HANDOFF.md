# TriDelPhi deployment and GitHub publication handoff

Updated: 2026-09-09. This is the current operational handoff, not a claim of a
live service. **Deployment, push and PR creation did not complete.** No changes
were made to the live homepage, DNS, nameservers, GitHub App settings or billing.

## Decisions and configured identity

| Item | Value |
|---|---|
| Local checkout | `/Users/kathanthakkar/VibeCode/TriDelPhi` |
| Repository | `https://github.com/girnarholdings/TriDelPhi` |
| Branch to publish | `codex/fortify-beginner-followups` |
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
| Pinned scanner candidate | `dba0783dc7873bb122b10b3731a080e138f3e576` |

Public identifiers are committed. **No real client secret, private key, GitHub
token or Cloudflare token is in this document or the configuration.**

The original idea of placing the portal at `/scan/` on the homepage was replaced
with the owner-approved separate subdomain. Keep that separation: host-only
portal session cookies must not be delivered to the homepage's hosting provider.

## Exact blockers observed

1. `wrangler whoami` returned **“You are not authenticated. Please run wrangler
   login.”** No `CLOUDFLARE_API_TOKEN` or account ID was available in the command
   environment. A real noninteractive `wrangler deploy` attempt stopped with the
   missing-API-token error. No deployment ID or live Worker URL was returned.
   Do not use Wrangler's suggested `--temporary` account workaround.
2. The GitHub App **client secret** is not available in the environment, and
   `portal/.dev.vars` does not exist. The App ID/Client ID are not substitutes.
   A secret already stored in Cloudflare could not be checked without Cloudflare
   authentication. Check secret names after login; do not disclose values.
3. Public DNS lookup returned Porkbun nameservers:
   `maceio.ns.porkbun.com`, `salvador.ns.porkbun.com`,
   `curitiba.ns.porkbun.com`, `fortaleza.ns.porkbun.com`.
   The apex returned `185.199.108.153`; no A/CNAME answer was returned for `scan`.
   Cloudflare Custom Domains require an **active Cloudflare zone**; readiness
   cannot be established from this workspace. Nameserver changes were not made.
4. Terminal Git push authentication failed with
   **“could not read Username for 'https://github.com': terminal prompts disabled.”**
   `gh` is not installed/on PATH in the agent environment.
5. The GitHub connector can read repository metadata, which reports that the
   owner's account has push/admin rights. However, an actual branch-creation
   attempt returned **HTTP 403: Resource not accessible by integration**.
   Account rights do not mean the connector token has write permission. No
   remote branch was created by that attempt and no PR was opened.

The TriDelPhi App authenticates portal visitors. It is **not** the Git credential
used by Codex/the terminal to publish this repository. Do not broaden its runtime
permissions just to solve the publication problem.

## Local work and validation

The branch contains earlier hardening commit
`dca62051daaf0710c9bb1d53a20b532ffe38307f`, then portal/audit implementation commit
`dba0783dc7873bb122b10b3731a080e138f3e576`, then the deployment configuration and
handoff commit. Run `git log -3 --oneline` for the final tip. The last observed
remote main was `152507f801bb0f55af862c41d91ad92fd9915f61`; refresh before pushing.

Completed validation:

- Python: **862 passed, 13 optional-tool skips** on local macOS/Python 3.12.
- Portal: **32 passing tests**, covering identity, installation, PKCE/state,
  revocation, expiry, request boundaries, billing ownership and paid-tier denial.
- Existing webhook bot: **37 passing checks** in the previous validation pass;
  its implementation is unchanged by this deployment update.
- `ruff check tridelphi/ tests/ scripts/` and `git diff --check` pass.
- Wrangler 4.120.0 deployment **dry-run** bundles the Worker, 3 static files,
  Durable Object and rate-limit bindings. Dry-run does not validate credentials,
  DNS ownership, the live App callback or actual Codespaces billing/availability.
- The prior local workerd smoke test served the page with HTTP 200 and returned
  HTTP 503 for unconfigured authentication, with no-store and security headers.
- Native static-scan acceptance CI is configured for macOS, Windows and Linux;
  the remote jobs cannot run until the branch is published. Do not describe
  Windows/Linux runtime validation as already completed.

## 1. Publish the branch and open the PR

On this Mac, use a normal terminal. If GitHub CLI is absent, install it from
[cli.github.com](https://cli.github.com/) first, or use GitHub Desktop to publish
the existing local branch. Do not re-clone over or reset the current checkout.

```bash
cd /Users/kathanthakkar/VibeCode/TriDelPhi
git status --short
git branch --show-current
gh auth login --hostname github.com --git-protocol https --web --scopes workflow
gh auth setup-git
gh auth status
git fetch origin
git log --oneline origin/main..HEAD
git push -u origin codex/fortify-beginner-followups
gh pr create --repo girnarholdings/TriDelPhi --base main \
  --head codex/fortify-beginner-followups \
  --title "Harden TriDelPhi and add GitHub-App-gated scan portal" \
  --body-file docs/PORTAL_PR_BODY.md
```

The extra `workflow` scope is needed by a classic OAuth token because this branch
modifies GitHub Actions workflow files. A fine-grained alternative must permit
this repository's Contents write, Workflows write and Pull requests write.
Use the normal credential manager, not a token in a remote URL or shell command.
If a PR already exists for this branch, update it instead of creating a duplicate.
Never force-push if the branch has changed on GitHub: inspect and reconcile first.
If remote main advanced, review conflicts and rerun the tests before publishing.

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

Use the Cloudflare account that should own this service. Add/verify the
`tridelphi.com` zone and confirm it is active. The current public nameservers
are Porkbun's. The normal full-zone setup requires a separately approved DNS
migration: export existing records, preserve **all** A/AAAA/CNAME/MX/TXT/CAA and
verification records, and handle DNSSEC correctly before changing nameservers.
Keep the registrar at Porkbun and the homepage's hosting unchanged if desired.
This handoff does not authorize deleting DNS records or moving email/hosting.

The custom-domain entry attaches **only `scan.tridelphi.com`**, not the apex or
`www`. Do not replace the homepage's DNS target with this Worker. Check for an
existing conflicting record on `scan` before adding the custom domain.

Reference: [Cloudflare Custom Domain prerequisites](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/).
If a DNS migration is not wanted, explicitly agree on a permanent workers.dev
staging origin and change both App callback and `PUBLIC_ORIGIN`; do not silently
enable alternate origins or temporary accounts. This config keeps them disabled.

## 4. Authenticate, store the secret and deploy

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

On a new Worker, `secret put` may ask to create it first. Approve only the named
`tridelphi-scan-portal` service in the correct account. If creation cannot happen
before the first deployment, deploy the fail-closed configuration once, set the
secret immediately, then redeploy and test. Do not claim a working login merely
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
Cloudflare write access independently; the known 403 is not a code/build failure.
Do not ask for secrets in chat. Complete publish → PR → DNS readiness → App secret
→ deploy → live verification, updating this handoff with actual PR/deployment
URLs and failures. Never mark the service live on the strength of a dry-run.
