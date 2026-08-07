// TriDelPhi bot — a Cloudflare Worker that is the front door for a hosted scan.
//
// What it IS: a GitHub webhook receiver. It verifies the delivery signature and,
// on a pull-request event, triggers the repository's TriDelPhi workflow via the
// Actions API (workflow_dispatch). It is the "deploy as a bot" glue.
//
// What it is NOT: the analyzer. TriDelPhi is a Python static analyzer and it
// runs in GitHub Actions, where it can read the repo's files. The edge cannot do
// that, and this Worker does not pretend to. Its job is authentication and
// dispatch — deliberately small, so it is auditable in one sitting.
//
// Test locally without deploying:
//   cd bot && npm install && npx wrangler dev
//   node test/verify.test.mjs          # unit-test the signature check
// See bot/README.md for a signed sample-payload curl.

import { verifySignature } from "./verify.js";

const OK = (body, status = 200) => new Response(body, { status });

export default {
  async fetch(request, env) {
    if (request.method !== "POST") {
      return OK("TriDelPhi bot: POST GitHub webhooks here.", 405);
    }

    // Read the RAW body first — signature verification must see the exact bytes.
    const rawBody = await request.text();
    const signature = request.headers.get("x-hub-signature-256");

    const verified = await verifySignature(env.GITHUB_WEBHOOK_SECRET, rawBody, signature);
    if (!verified) {
      // A security bot that acts on unverified events is worse than no bot.
      return OK("invalid or missing signature", 401);
    }

    const eventType = request.headers.get("x-github-event") || "";
    let payload;
    try {
      payload = JSON.parse(rawBody);
    } catch {
      return OK("bad JSON", 400);
    }

    // Only act on pull-request activity that warrants a fresh scan.
    if (eventType !== "pull_request" || !["opened", "synchronize", "reopened"].includes(payload.action)) {
      return OK(`ignored: ${eventType}.${payload.action || ""}`, 202);
    }

    const repo = payload.repository;
    if (!repo) return OK("no repository in payload", 400);

    const dispatched = await dispatchScan(env, repo.owner.login, repo.name, payload.pull_request);
    return OK(JSON.stringify(dispatched), dispatched.ok ? 200 : 502);
  },
};

// Trigger the repo's TriDelPhi workflow. The scan itself runs there, in Actions,
// with the repository checked out. Requires a GitHub App / PAT with `actions:
// write` on the target repo, stored as the GITHUB_DISPATCH_TOKEN secret.
async function dispatchScan(env, owner, name, pull) {
  if (!env.GITHUB_DISPATCH_TOKEN) {
    // Still a useful, testable path: acknowledge without dispatching.
    return { ok: true, dispatched: false, reason: "no dispatch token; acknowledged only", pr: pull?.number };
  }

  const url = `https://api.github.com/repos/${owner}/${name}/actions/workflows/tridelphi.yml/dispatches`;
  const resp = await fetch(url, {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.GITHUB_DISPATCH_TOKEN}`,
      accept: "application/vnd.github+json",
      "user-agent": "tridelphi-bot",
      "content-type": "application/json",
    },
    body: JSON.stringify({ ref: pull?.base?.ref || "main" }),
  });

  return { ok: resp.ok, dispatched: resp.ok, status: resp.status, pr: pull?.number };
}
