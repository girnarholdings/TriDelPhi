# TriDelPhi bot — Cloudflare Worker

A small Cloudflare Worker that lets you run TriDelPhi as a **hosted GitHub bot**.

## Two layers, and why

| | **Control plane** (this Worker) | **Execution plane** (GitHub Actions) |
|---|---|---|
| Job | Verify the signature, decide whether an event deserves a run, dispatch it | Check out the repository and run the scan |
| Reads your code | **Never** | Yes — that is the point |
| Credential | One token: **Actions: write**, on allowlisted repos only | The run's own `GITHUB_TOKEN`, scoped per job |
| If compromised | Can start a workflow that was going to run anyway | Same blast radius as your CI already has |

The split is the security property, not a deployment detail. TriDelPhi is a
Python analyzer that shells out to five pinned scanners — the edge cannot host
that, and pretending otherwise would mean shipping a public endpoint that reads
source. So the public half holds no `contents` access at all, and the half that
can read your code is not reachable from the internet.

Most people need neither: [`tridelphi init`](../README.md) writes a workflow that
already scans and comments on every pull request, no server involved. This Worker
is for running **one hosted bot in front of many repositories**.

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

**It fails closed.** With an empty allowlist the Worker verifies signatures and
dispatches nothing, because a hosted bot that dispatches into any repository
whose webhook carries the shared secret is not a defensible default for a
security tool. Without `GITHUB_DISPATCH_TOKEN` it verifies and acknowledges only,
which is a useful way to watch what it *would* do before granting it anything.

## What it acts on

| Event | Action |
|---|---|
| `pull_request` opened / synchronize / reopened / ready_for_review | dispatch `tridelphi.yml` with the PR number |
| `issue_comment` created, saying `tridelphi fix`, by OWNER/MEMBER/COLLABORATOR | dispatch `tridelphi-fix.yml` |
| anything else | ignored, with the reason in the log |

Drafts are skipped until marked ready, and label/assignee churn is ignored — none
of it changes code, and a runner minute spent on it is a minute wasted. The fix
path applies the same author-association rule the in-repo workflow uses; two
different answers to "who is trusted" is how gaps appear.

Every delivery logs one JSON line — `{"at":"tridelphi-bot","delivery":…,
"result":"ignored","reason":"pull request is a draft"}` — so an ignored event
says why instead of going quiet.

## Test it locally (no deploy, no account)

```bash
cd bot
npm install
node test/verify.test.mjs      # unit-test the signature check
npx wrangler dev               # run the Worker at http://localhost:8787
```

Then send it a signed webhook, the way GitHub would:

```bash
SECRET="dev-secret-change-me"   # matches [vars] in wrangler.toml
BODY='{"action":"opened","pull_request":{"number":7,"base":{"ref":"main"}},"repository":{"name":"demo","owner":{"login":"acme"}}}'
SIG="sha256=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')"

# forged signature is rejected (401):
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8787 \
  -H 'x-github-event: pull_request' -H 'x-hub-signature-256: sha256=deadbeef' -d "$BODY"

# correctly signed pull-request event is accepted (200):
curl -s -X POST http://localhost:8787 \
  -H 'x-github-event: pull_request' -H "x-hub-signature-256: $SIG" -d "$BODY"
```

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
| `test/verify.test.mjs` | Node unit tests for the signature check (no wrangler needed) |
| `wrangler.toml` | Worker config; real secrets go through `wrangler secret put` |
