# GitHub App scan portal

Deployment rails for a separate scan subdomain. Keep the main static website on
its existing host; **do not route source uploads, credentials or scan jobs through cPanel**.
This Worker handles authentication and eligibility metadata, not scanning compute.
Cloudflare therefore still serves the lightweight portal for free users; only
Cloudflare **scan compute** is reserved for the future paid tier.

**Current deployment target:** `https://scan.tridelphi.com`, with callback
`https://scan.tridelphi.com/auth/callback`. The existing homepage at
`https://tridelphi.com` remains on its current host (currently reported as GitHub
Pages). App identity is configured and GitHub connector write access works.
Deployment is on hold pending Cloudflare account/zone and billing verification,
the App secret, and live acceptance checks.
Follow [the deployment handoff](../docs/DEPLOYMENT_HANDOFF.md).

**Operator rule:** never spend money on Cloudflare or any other service without
the owner's explicit approval. Verify no-charge operation before deployment or
test-machine creation; do not infer it from an included quota or budget alert.
Never upgrade a plan or enable paid fallback automatically.

## What works in this implementation

| Visitor | Portal behavior |
|---|---|
| Not signed in | Can read instructions; cannot obtain a scan handoff or use the paid endpoint |
| GitHub App authorized but not installed, or suspended/revoked | Denied |
| Signed in + installed App | Can request a Codespaces eligibility check |
| Eligible, with the signed-in user as billable owner | Gets a GitHub creation-page link for the pinned trusted scanner |
| Codespaces unavailable, permission missing, or different payer | Denied; no fallback to Cloudflare |
| Free account calling `/api/scan` | HTTP 402; no body processing or execution |
| Paid pilot account calling `/api/scan` | HTTP 503 until an isolated execution plane is implemented |

The free flow is an **explicit handoff**, not an automatically launched scan.
Users confirm creation on GitHub, upload an archive in the trusted Codespace,
and run `python -m tridelphi.audit ./project.zip` there. For private repositories,
download the ZIP on GitHub while authenticated and upload it in the Codespace.
Do not create a Codespace from the target repo: its devcontainer can run scripts.
Do not install target dependencies or execute the target's setup instructions.

GitHub makes the final billing, quota, policy, machine and availability decision.
A successful preflight is not a quota reservation or a promise of free compute.
Check the payer on GitHub before creation. **Stop and delete the Codespace after
scanning**; stopped Codespaces retain files and can consume storage allowance.
Never enable organization-sponsored Codespaces for the scanner repository if
the intent is to avoid operator-paid free scans. The portal rejects a different
billable owner, but GitHub's final creation page remains authoritative.

Local TriDelPhi remains open source and requires no login. The website cannot
prevent people from running it independently or opening GitHub directly; these
gates protect the service's routes, not the public source code.

## Existing GitHub App

The owner has created [tridelphi-security](https://github.com/apps/tridelphi-security):
App ID `4889186`, Client ID `Iv23li3y8yo2DOaLlZ7K`, owned by `girnarholdings`.
These are public identifiers, already in `wrangler.toml`. No client secret has
been supplied to this workspace. Verify the following settings on that existing
App; **do not create a duplicate**.

1. Choose a unique App name. Set its homepage to your TriDelPhi website.
2. Set **Callback URL** to `https://scan.tridelphi.com/auth/callback`.
3. Keep user access token expiration enabled. Do not enable device flow.
4. Disable webhooks for this portal-only App; no events are required. The
   existing `bot/` webhook receiver is independent and unchanged.
5. Repository permissions: **Codespaces: read and write**, and GitHub's mandatory
   **Metadata: read**. GitHub requires Codespaces write even for the default
   attributes eligibility endpoint. This grant is broader than this portal's
   read-only preflight; explain it to users. Do not grant Actions, workflows,
   contents write, administration, or Codespaces secrets access for this flow.
6. Allow installation on other accounts if offering the public service. Install
   the App on the trusted scanner repository as its owner. Users authorize the
   App and install it on selected repositories/accounts; the token is a GitHub
   App **user token**, not a PAT or an installation token.
7. Copy App ID, slug, and Client ID into `wrangler.toml`. Store the generated
   **Client Secret** using Wrangler's secret input, never chat, Git or browser JS.
   This flow does not need the App's private key.

GitHub references:
- [GitHub App user authorization and PKCE](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app)
- [Codespaces REST permissions and billable-owner preflight](https://docs.github.com/en/rest/codespaces/codespaces)
- [Creating a Codespace and reviewing who pays](https://docs.github.com/en/codespaces/developing-in-a-codespace/creating-a-codespace-for-a-repository)
- [Codespaces billing](https://docs.github.com/en/billing/concepts/product-billing/github-codespaces)

## Configure and deploy later

Tests have no npm dependencies: `cd portal && npm test` with Node 22 or newer.
Use the repository's pinned Wrangler tooling from `bot/`:

```bash
cd bot
npm ci
./node_modules/.bin/wrangler deploy --config ../portal/wrangler.toml --dry-run
./node_modules/.bin/wrangler secret put GITHUB_CLIENT_SECRET --config ../portal/wrangler.toml
```

`PUBLIC_ORIGIN` and the dedicated Cloudflare custom-domain route are configured
for `https://scan.tridelphi.com`. `workers_dev` and preview URLs are
disabled to avoid alternate authentication origins. The portal is not a Sites
deployment and must not be put behind ChatGPT-only authentication.

`SCANNER_REF` points to published candidate
`78fb22015299b3fc98b2bfbdc4e3c0a06aa469b8`, containing
`.devcontainer/scan/devcontainer.json` and `tridelphi/audit.py`.
Review [PR #70](https://github.com/girnarholdings/TriDelPhi/pull/70)
and use a reviewed merged/release commit for production.
An unpublished local commit or moving `main` is not a released scanner. The
devcontainer installs TriDelPhi from this trusted checkout, never target code.
The base image is version-tagged, not digest-pinned: pin and test a vetted image
digest before a public production launch.

Run a staging round-trip with a test account before public launch: new login,
installation/permission consent, callback replay rejection, Codespaces permission
failure, own-payer success, another-payer denial, expired session and revoked App.
Confirm GitHub honors the pinned ref/devcontainer link parameters, and that a
clean Codespace runs the audit command. Unit tests mock GitHub and cannot prove
live provider behavior. Native Windows/Linux CI is separate from local macOS tests.

No Cloudflare account, App secret, DNS, payment setup or live deployment was
created by this change. The GitHub App was created separately by the owner.
Keep the scan link off the main website until staging
passes. Do not send secrets to cPanel or enable request-body logging there.

## Privacy and security boundaries

- This portal has **no source upload, repository download, report storage or
  training-donation endpoint**. It never receives source in the intended flow.
  An attacker can still send arbitrary HTTP bodies; `/api/scan` never reads them.
- Auth state lives for 5 minutes. Opaque, rotated sessions live for at most
  30 minutes in a private Durable Object, containing the GitHub user token and
  numeric user ID. HttpOnly/Secure/host-only cookies contain random identifiers,
  never tokens. No credentials go in localStorage or public JavaScript.
- GitHub identity and unsuspended App installation are checked again on every
  protected request. Authorization failures never fall back to cached access.
- OAuth state is browser-bound and consumed transactionally once. PKCE protects
  code exchange; POSTs require exact-origin checks. Redirect destinations and
  GitHub API hosts are fixed. Network responses and input metadata are bounded.
- Logout removes the portal session. It does not revoke the GitHub App grant;
  users can revoke that in GitHub settings. Refresh tokens are not retained or used.
- Durable Object expiry alarms delete session records, and expired records cannot
  authorize access even if alarm delivery is delayed. Provider backup/operational
  retention is outside the application's deletion guarantee. Codespace source
  resides under the user's GitHub account until deletion and provider cleanup.
- Worker observability is disabled and no code logs requests or exceptions.
  Cloudflare/GitHub can still retain operational metadata. Do not advertise this
  as provider-wide “zero data retention.”
- The rate limiter is an edge abuse control, **not a globally exact spending cap**.
  Verify a non-billable plan with enforced free limits, or obtain explicit owner
  approval for costs before launch. Budgets/alerts and abuse controls do not
  replace that approval or guarantee that charges stop.
- Reviewed/redacted training donations remain a separate future opt-in feature.
  No examples are silently collected from scans or sign-ins.

## Paid tier: reserved, not launched

`PAID_ENTITLEMENTS` is an operator-maintained pilot mapping from immutable GitHub
user IDs to expiry timestamps in milliseconds. It is not checkout, subscription
billing or proof of payment. Invalid/missing/expired values deny access. Browser
headers, query parameters and request bodies can never upgrade a user.

`/api/scan` is intentionally disabled even for a paid pilot. Before enabling it:
implement verified payment webhook processing and revocation, per-user and global
quotas, bounded uploads, ephemeral isolated containers with no target-code execution,
no scanner credentials or outbound network, cancellation/timeouts/cleanup, and
independent security/load testing. Never simply connect the endpoint to the shared
Porkbun account. A GitHub login is not a resource budget or sandbox.

## Remaining product work

The rails do not yet provide an embedded Codespace scan UI, automated private-repo
retrieval, in-website results, a payment processor, paid containers, training
donations, device protection or an AI model. These are separate milestones.
Native audit checks cover selected patterns, not all vulnerabilities; suppression
counts and partial coverage are reported. For a tree being actively modified by
hostile processes, use a disposable environment: portable path checks do not make
Windows filesystem race attacks impossible.
