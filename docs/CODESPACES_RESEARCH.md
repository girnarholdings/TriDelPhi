# Codespaces: included usage and user-confirmed creation

Verified against GitHub documentation on 2026-09-10. The owner approved
user-confirmed creation with a concise billing disclosure; this is NOT approval
to start a live test on the owner's account, incur operator charges, or upgrade
Cloudflare. No real Codespace was created during implementation testing.

## What is free?

Personal GitHub Free accounts include 120 core-hours and 15 GB-month of storage
per month. Pro includes 180 core-hours and 20 GB-month. On a 2-core machine those
compute allowances are 60 and 90 running hours, respectively. Organization and
enterprise plans do not include a Codespaces allowance. Usage is shared with
other Codespaces on the account, including retained storage.

An illustrative 10-minute run on 2 cores uses one-third of a core-hour: 360 such
runs would consume 120 core-hours, ignoring setup time and assuming no other
usage. This is arithmetic, NOT a measured scanner runtime or scan-count promise.

Sources: [billing](https://docs.github.com/en/billing/concepts/product-billing/github-codespaces),
[included usage](https://docs.github.com/en/billing/reference/product-usage-included),
[core-hours and storage](https://docs.github.com/en/codespaces/troubleshooting/troubleshooting-included-usage).

## Can the App enforce free-only creation?

The documented creation API supports GitHub App user tokens with Codespaces
write permission. It exposes machine, ref, devcontainer, idle timeout and
retention settings, but no free-only/max-charge parameter. The current public
billing APIs do not expose a personal Codespaces allowance reservation and
enforced zero-charge check through this App's permissions. Billing reports are
not reservations and cannot prevent concurrent consumption elsewhere.

GitHub says accounts without a valid payment method are blocked when included
usage runs out. Users with billing enabled can be charged for overages. Users
can configure budgets that stop usage; alerts alone do not stop spending, and
new budgets do not retroactively account for earlier usage. Do not claim that
sign-in, an available machine, a checkbox, a short timeout or a budget alert
proves zero cost. Do not request broad billing administration permissions to
pretend otherwise.

Sources: [creation API](https://docs.github.com/en/rest/codespaces/codespaces),
[billing APIs](https://docs.github.com/en/rest/billing/usage),
[budget APIs](https://docs.github.com/en/rest/billing/budgets),
[budget controls](https://docs.github.com/en/billing/concepts/budgets-and-alerts).

## Implemented flow

Two alternative locations: cloud workspace or local computer. Cloud has two
steps: connect GitHub, then explicitly confirm/create the workspace. The App
now creates it instead of returning GitHub's manual creation form. Instructions
for running the audit are nested under that workspace, not a third scan method.

Before creation, the server revalidates identity, installation, trusted public
scanner repository and own-account payer. It selects only a reported 2-core
machine (no larger fallback), pins the scanner commit and devcontainer, opts out
of additional repository permissions, and requests a 5-minute idle timeout and
60-minute retention after stopping. Users consent to cleanup before creation
and must save their report. Idle timeout is not a hard wall-clock execution
limit; active terminals/processes and user changes can affect lifecycle.

A per-user transactional 30-minute reservation blocks parallel creation even
across sessions. A successful result is reused during that window. Uncertain
POST outcomes are never retried automatically; users are sent to GitHub's
workspace list and creation is blocked for the remainder of the window. This
is a bounded duplicate guard, not a permanent one-workspace quota or global
spending cap. After expiry, another explicit creation can make another workspace.
No unrelated workspace is stopped/deleted. Cleanup of files is delegated to
GitHub's requested retention policy, not to a portal alarm holding credentials.

The server checks returned owner/payer/repository/machine and the exact
workspace-name.github.dev URL. Failed post-creation checks report uncertainty,
not “nothing was created.” Tokens stay server-side. Cloudflare paid scanning
remains disabled. Source still goes into the user's Codespace, not this portal.

## Still needs live acceptance / further product work

- Owner-controlled real sign-in, installation return, and a separately approved
  creation test. Mock tests cannot establish provider policy, machine availability,
  supported immutable ref behavior, actual idle shutdown or retention timing.
- If no 2-core option exists, offer local scanning; do not silently increase size.
- Verify the trusted devcontainer build and audit on an explicitly approved test
  machine. Save the report and delete the machine after the test.
- An integrated archive picker/results interface INSIDE the trusted Codespace
  remains future work. Creating a workspace is not automatically scanning a repo.
- Future lifecycle reconciliation should identify only app-created workspaces,
  survive expired/revoked tokens, and avoid deleting user work. No background
  cleanup guarantee should depend on a 30-minute portal session.
- For an absolute no-cloud-charge option, local scanning remains available.
