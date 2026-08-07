# TriDelPhi bot — Cloudflare Worker

A small Cloudflare Worker that lets you run TriDelPhi as a **hosted GitHub bot**.

## What it does (and doesn't)

It is the **webhook front door**: it verifies GitHub's delivery signature and, on
a pull-request event, triggers your repo's TriDelPhi workflow through the Actions
API. The scan itself runs in **GitHub Actions**, where the repository is checked
out — TriDelPhi is a Python analyzer and cannot run on the edge, and this Worker
does not pretend otherwise. Its whole job is **authentication + dispatch**, which
is exactly the part you want small and auditable.

Most people don't need this — [`tridelphi init`](../README.md) writes a workflow
that already comments on PRs, no server required. The Worker is for a single
hosted bot fronting many repos.

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
