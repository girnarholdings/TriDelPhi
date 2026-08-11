// TriDelPhi bot — the control plane of a two-layer bot.
//
//   layer 1 (here)          Cloudflare Worker. Verifies the delivery signature,
//                           decides whether an event deserves a run, and asks
//                           GitHub Actions to do it. Touches no repository
//                           content, ever.
//
//   layer 2 (Actions)       Runs the scan with the repository checked out.
//                           TriDelPhi is a Python analyzer that shells out to
//                           five pinned scanners; the edge cannot host that and
//                           this Worker does not pretend otherwise.
//
// The division is the security property, not an implementation detail. The
// public-facing half holds no `contents` access and can read nothing, so the
// worst a compromised Worker can do is ask Actions to run the workflow that was
// already going to run. The half that can read your code is not public-facing.
//
// Test locally without deploying:
//   cd bot && npm install && npm test        # signature + routing, no network
//   npx wrangler dev                          # serve at http://localhost:8787
// See bot/README.md for a signed sample-payload curl.

import { route, parseAllowlist } from "./route.js";
import { verifySignature } from "./verify.js";

// One line, one event, machine-greppable and human-readable. Webhook logs are
// read at 3am during an incident: a JSON blob per delivery beats prose, and
// beats a stack of unlabelled lines even harder.
function log(fields) {
  console.log(JSON.stringify({ at: "tridelphi-bot", ...fields }));
}

const text = (body, status) => new Response(body + "\n", { status, headers: { "content-type": "text/plain" } });

export default {
  async fetch(request, env) {
    if (request.method !== "POST") {
      return text("TriDelPhi bot. POST GitHub webhooks here.", 405);
    }

    // The raw bytes, before anything parses them: the signature covers exactly
    // these, and a re-serialized object would not reproduce them.
    const raw = await request.text();
    const delivery = request.headers.get("x-github-delivery") || "unknown";
    const event = request.headers.get("x-github-event") || "";

    if (!(await verifySignature(env.GITHUB_WEBHOOK_SECRET, raw, request.headers.get("x-hub-signature-256")))) {
      // A security bot that acts on unverified events is worse than no bot, so
      // this is the one rejection that is logged as a warning.
      log({ delivery, event, result: "rejected", reason: "bad or missing signature" });
      return text("invalid or missing signature", 401);
    }

    let payload;
    try {
      payload = JSON.parse(raw);
    } catch {
      log({ delivery, event, result: "rejected", reason: "body is not JSON" });
      return text("bad JSON", 400);
    }

    const decision = route(event, payload, { allowlist: parseAllowlist(env.ALLOWED_REPOS) });
    if (decision.act === "ignore") {
      log({ delivery, event, result: "ignored", reason: decision.reason });
      return text(`ignored: ${decision.reason}`, 202);
    }

    const target = `${decision.owner}/${decision.repo}#${decision.pr}`;
    const outcome = await dispatch(env, decision);
    log({ delivery, event, result: outcome.dispatched ? "dispatched" : "not dispatched",
          act: decision.act, target, reason: outcome.reason });
    return text(`${outcome.dispatched ? "dispatched" : "acknowledged"} ${decision.act} for ${target}: ${outcome.reason}`,
                outcome.ok ? 200 : 502);
  },
};

// Ask Actions to run. The workflow file is named per act, and the pull-request
// number rides along as an input so the run can check that pull request out and
// comment on it — dispatching the bare branch would scan the wrong tree and lose
// the thread to reply on.
//
// The token needs exactly one permission: `actions: write` on the allowlisted
// repositories. Not contents, not pull-requests — the run itself holds those,
// scoped to the job that needs them. If this credential leaks, it can start a
// workflow and nothing else.
async function dispatch(env, decision) {
  if (!env.GITHUB_DISPATCH_TOKEN) {
    return { ok: true, dispatched: false, reason: "no GITHUB_DISPATCH_TOKEN; verified and acknowledged only" };
  }

  const workflow = decision.act === "fix" ? "tridelphi-fix.yml" : "tridelphi.yml";
  const url = `https://api.github.com/repos/${decision.owner}/${decision.repo}/actions/workflows/${workflow}/dispatches`;

  let response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: {
        authorization: `Bearer ${env.GITHUB_DISPATCH_TOKEN}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        "user-agent": "tridelphi-bot",
        "content-type": "application/json",
      },
      body: JSON.stringify({ ref: decision.ref, inputs: { pr: String(decision.pr) } }),
    });
  } catch (err) {
    return { ok: false, dispatched: false, reason: `dispatch request failed: ${err?.message || err}` };
  }

  if (response.ok) return { ok: true, dispatched: true, reason: `${workflow} on ${decision.ref}` };
  // GitHub's error body is small and says useful things ("workflow does not have
  // workflow_dispatch trigger"), so surface it rather than only the status.
  const detail = (await response.text().catch(() => "")).slice(0, 200);
  return { ok: false, dispatched: false, reason: `GitHub returned ${response.status}: ${detail}` };
}
