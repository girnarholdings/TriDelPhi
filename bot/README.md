# TriDelPhi bot — Cloudflare Worker

A small Cloudflare Worker that lets you run TriDelPhi as a **hosted GitHub bot**.

## Two layers, and why

| | **Control plane** (this Worker) | **Execution plane** (GitHub Actions) |
|---|---|---|
| Job | Verify the signature, decide whether an event deserves a run, dispatch it | Check out the repository and run the scan |
| Reads your code | **Never** | Yes — that is the point |
| Credential | One token: **Actions: write**, on allowlisted repos only | The run's own `GITHUB_TOKEN`, scoped per job |
| If compromised | Can misuse the token's Actions permissions on its selected repos | Can misuse the scan job's granted permissions |

The split is the security property, not a deployment detail. TriDelPhi is a
Python analyzer that shells out to five pinned scanners — the edge cannot host
that, and pretending otherwise would mean shipping a public endpoint that reads
source. So the public half holds no `contents` access at all, and the half that
can read your code runs inside GitHub Actions. **Actions: write is not a
dispatch-only permission**: a stolen token can also manage workflow runs and
related Actions resources. Scope the token to the smallest repository set;
the Worker's allowlist does not constrain an attacker using a stolen token
directly against GitHub.

Most people need neither: [`tridelphi init`](../README.md) writes a workflow that
already scans every pull request and comments on same-repository branches, no
server involved. Fork pull requests still scan and gate, but GitHub's read-only
fork token cannot post a comment, so their report lives in the job Summary. This
Worker is for running **one hosted bot in front of many repositories**.

## Configure it

```bash
npx wrangler secret put GITHUB_WEBHOOK_SECRET   # same value as the webhook's secret
npx wrangler secret put GITHUB_DISPATCH_TOKEN   # fine-grained token, Actions: write ONLY
```

Then set the allowlist in `wrangler.toml` — this is the blast radius:

```toml
[vars]
ALLOWED_REPOS = "acme/api, acme/web"
```

For local development, copy the non-secret template and replace its placeholder:

```bash
cp .dev.vars.example .dev.vars
```

`.dev.vars` is gitignored. There is deliberately no webhook-secret default in
`wrangler.toml`: a forgotten local example must never become a predictable
production authentication key.

**It fails closed.** With an empty allowlist the Worker verifies signatures and
dispatches nothing, because a hosted bot that dispatches into any repository
whose webhook carries the shared secret is not a defensible default for a
security tool. Without `GITHUB_DISPATCH_TOKEN` it verifies and acknowledges only,
which is a useful way to watch what it *would* do before granting it anything.
With a dispatch token, the `REPLAY_GUARD` Durable Object binding is mandatory;
the Worker returns 503 instead of pretending per-process memory is a replay
defense.

The request boundary is deliberately small: JSON bodies are streamed into a
hard 1 MiB cap before parsing, delivery IDs are single-use for 10 minutes, and
each repository gets at most 30 dispatches per minute. Replays return 409,
rate-limited requests return 429, and unavailable state fails closed with 503.
GitHub may retry non-2xx webhook deliveries, so investigate repeated 503s rather
than weakening either guard.

Rotate both secrets on a schedule and immediately after any suspected leak:
create the replacement GitHub token first, update `GITHUB_DISPATCH_TOKEN`, then
revoke the old token; update the webhook secret in GitHub and
`GITHUB_WEBHOOK_SECRET` in the same maintenance window. Keep the token limited
to the allowlisted repositories with only **Actions: write**, and review the
allowlist whenever a repository is transferred or archived.

## What it acts on

| Event | Action |
|---|---|
| `pull_request` opened / synchronize / reopened / ready_for_review, same-repo | dispatch `tridelphi.yml` with the PR number |
| anything else (forks, drafts, label churn, comments) | ignored, with the reason in the log |

**Fix requests are NOT handled here.** `tridelphi fix` comments and the "Fix these
for me" checkbox are handled entirely by the in-repo `tridelphi-fix.yml` workflow,
which triggers on the comment event and gates on the comment body plus write
access. The control plane deliberately never dispatches a fix: a `workflow_dispatch`
would run the fix job *without* that comment-body trust gate.

Drafts are skipped until marked ready, and label/assignee churn is ignored — none
of it changes code, and a runner minute spent on it is a minute wasted. The only
fix trust decision lives in the in-repo workflow, so there is no second policy
here for the two layers to disagree about.

Every delivery logs one JSON line — `{"at":"tridelphi-bot","delivery":…,
"result":"ignored","reason":"pull request is a draft"}` — so an ignored event
says why instead of going quiet.

## Test it locally (no deploy, no account)

```bash
cd bot
npm ci
npm test                       # signature, schema, routing, replay, limits
npx wrangler dev               # run the Worker at http://localhost:8787
```

Then send it a signed webhook, the way GitHub would:

```bash
SECRET="replace-with-your-.dev.vars-value"
BODY='{"action":"opened","pull_request":{"number":7,"draft":false,"base":{"ref":"main"},"head":{"repo":{"full_name":"acme/demo"}}},"repository":{"name":"demo","owner":{"login":"acme"}}}'
SIG="sha256=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')"

# forged signature is rejected (401):
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8787 \
  -H 'content-type: application/json' -H 'x-github-delivery: local-forged-001' \
  -H 'x-github-event: pull_request' -H 'x-hub-signature-256: sha256=deadbeef' -d "$BODY"

# correctly signed pull-request event is accepted (200):
curl -s -X POST http://localhost:8787 \
  -H 'content-type: application/json' -H 'x-github-delivery: local-signed-001' \
  -H 'x-github-event: pull_request' -H "x-hub-signature-256: $SIG" -d "$BODY"
```

Add `acme/demo` to your local allowlist to exercise routing. Use a fresh delivery
ID for each attempt; repeated IDs are rejected. Without a dispatch token, this
only acknowledges the event and does not contact GitHub.

## Deploy it

```bash
npx wrangler secret put GITHUB_WEBHOOK_SECRET   # the webhook's shared secret
npx wrangler secret put GITHUB_DISPATCH_TOKEN   # optional PAT with actions:write
npx wrangler deploy
```

Then add a webhook to your repo (Settings → Webhooks): payload URL = the Worker
URL, content type `application/json`, secret = the same `GITHUB_WEBHOOK_SECRET`,
events = *Pull requests*. Add a `.github/workflows/tridelphi.yml` (via
`tridelphi init`) so there is a workflow to dispatch.

## Files

| File | What it is |
|---|---|
| `src/verify.js` | GitHub HMAC-SHA256 signature verification — the security boundary |
| `src/index.js` | The `fetch` handler: verify → parse → dispatch |
| `src/state.js` | Durable Object: atomic replay TTL and per-repository rate slots |
| `test/*.test.mjs` | Node tests for signatures, schemas, request limits, routing and state |
| `package-lock.json` | Reproducible Wrangler dependency graph |
| `wrangler.toml` | Worker config; real secrets go through `wrangler secret put` |
