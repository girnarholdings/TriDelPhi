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
// public-facing half holds no `contents` access. Its Actions:write credential
// still permits Actions operations beyond dispatch if stolen, so restrict its
// repository scope. An application allowlist cannot constrain a stolen token.
//
// Test locally without deploying:
//   cd bot && npm install && npm test        # signature + routing, no network
//   npx wrangler dev                          # serve at http://localhost:8787
// See bot/README.md for a signed sample-payload curl.

import { route, parseAllowlist } from "./route.js";
import { verifySignature } from "./verify.js";

const MAX_BODY_BYTES = 1024 * 1024;
const MAX_BODY_CHUNKS = 4096;
const DELIVERY_TTL_MS = 10 * 60 * 1000;
const MAX_DELIVERIES = 10_000;
const RATE_WINDOW_MS = 60 * 1000;
const MAX_DISPATCHES_PER_REPO = 30;
const DELIVERY_ID = /^[A-Za-z0-9_-]{8,128}$/;
const deliveryCache = new Map();
const dispatchWindows = new Map();

export { ReplayGuard } from "./state.js";

// One line, one event, machine-greppable and human-readable. Webhook logs are
// read at 3am during an incident: a JSON blob per delivery beats prose, and
// beats a stack of unlabelled lines even harder.
function log(fields) {
  console.log(JSON.stringify({ at: "tridelphi-bot", ...fields }));
}

const text = (body, status) => new Response(body + "\n", {
  status,
  headers: {
    "content-type": "text/plain; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  },
});

function rememberDeliveryLocally(delivery, now = Date.now()) {
  for (const [key, expires] of deliveryCache) {
    if (expires <= now) deliveryCache.delete(key);
  }
  if (deliveryCache.has(delivery)) return false;
  while (deliveryCache.size >= MAX_DELIVERIES) {
    deliveryCache.delete(deliveryCache.keys().next().value);
  }
  deliveryCache.set(delivery, now + DELIVERY_TTL_MS);
  return true;
}

function withinDispatchRateLocally(key, now = Date.now()) {
  const recent = (dispatchWindows.get(key) || []).filter((at) => now - at < RATE_WINDOW_MS);
  if (recent.length >= MAX_DISPATCHES_PER_REPO) {
    dispatchWindows.set(key, recent);
    return false;
  }
  recent.push(now);
  dispatchWindows.set(key, recent);
  return true;
}

async function guardRequest(env, kind, key) {
  if (env.REPLAY_GUARD) {
    try {
      const id = env.REPLAY_GUARD.idFromName("tridelphi-webhook-state");
      const response = await env.REPLAY_GUARD.get(id).fetch("https://state.invalid/guard", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ kind, key, now: Date.now() }),
      });
      if (!response.ok) return { allowed: false, reason: "state guard failed closed" };
      const result = await response.json();
      return { allowed: result.allowed === true, reason: result.reason || "state guard refused" };
    } catch {
      return { allowed: false, reason: "state guard unavailable; failed closed" };
    }
  }
  // Unit tests and acknowledgement-only local development do not need a
  // Cloudflare binding. A credentialed deployment does: per-isolate memory is
  // not a global replay boundary, so refuse to dispatch without the Durable
  // Object rather than pretending it is sufficient.
  if (env.GITHUB_DISPATCH_TOKEN) {
    return { allowed: false, reason: "REPLAY_GUARD binding is required before dispatch" };
  }
  const allowed = kind === "delivery" ? rememberDeliveryLocally(key) : withinDispatchRateLocally(key);
  const refusal = kind === "delivery" ? "replayed delivery id" : "dispatch rate exceeded";
  return { allowed, reason: allowed ? "local development guard" : refusal };
}

async function readBoundedBody(request) {
  const declared = request.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_BODY_BYTES)) {
    return { error: "body is too large" };
  }
  if (!request.body) {
    const bytes = new Uint8Array();
    return { bytes, text: "" };
  }
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!(value instanceof Uint8Array)) {
      await reader.cancel();
      return { error: "body stream was not bytes" };
    }
    if (chunks.length >= MAX_BODY_CHUNKS) {
      await reader.cancel();
      return { error: "body used too many chunks" };
    }
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      return { error: "body is too large" };
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { bytes, text: new TextDecoder("utf-8", { fatal: true }).decode(bytes) };
}

async function responseSnippet(response, limit = 1024) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (total < limit) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!(value instanceof Uint8Array)) break;
    const remaining = limit - total;
    chunks.push(value.subarray(0, remaining));
    total += Math.min(value.byteLength, remaining);
    if (value.byteLength > remaining) break;
  }
  await reader.cancel().catch(() => {});
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8").decode(bytes);
}

export default {
  async fetch(request, env) {
    if (request.method !== "POST") {
      return text("TriDelPhi bot. POST GitHub webhooks here.", 405);
    }

    const contentType = (request.headers.get("content-type") || "")
      .split(";", 1)[0].trim().toLowerCase();
    if (contentType !== "application/json") {
      return text("content-type must be application/json", 415);
    }

    const delivery = request.headers.get("x-github-delivery") || "";
    const event = request.headers.get("x-github-event") || "";
    if (!DELIVERY_ID.test(delivery)) return text("missing or malformed delivery id", 400);

    // The raw bytes, before anything parses them: the signature covers exactly
    // these, and a re-serialized object would not reproduce them.
    let bounded;
    try {
      bounded = await readBoundedBody(request);
    } catch {
      return text("body is not valid UTF-8", 400);
    }
    if (bounded.error) return text(bounded.error, 413);
    const { bytes, text: raw } = bounded;

    if (!(await verifySignature(env.GITHUB_WEBHOOK_SECRET, bytes, request.headers.get("x-hub-signature-256")))) {
      // A security bot that acts on unverified events is worse than no bot, so
      // this is the one rejection that is logged as a warning.
      log({ delivery, event, result: "rejected", reason: "bad or missing signature" });
      return text("invalid or missing signature", 401);
    }

    const replay = await guardRequest(env, "delivery", delivery);
    if (!replay.allowed) {
      log({ delivery, event, result: "rejected", reason: replay.reason });
      const unavailable = replay.reason.includes("required") || replay.reason.includes("unavailable");
      return text(replay.reason, unavailable ? 503 : 409);
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
    const rate = await guardRequest(
      env,
      "rate",
      `${decision.owner}/${decision.repo}`.toLowerCase(),
    );
    if (!rate.allowed) {
      log({ delivery, event, result: "rejected", target, reason: rate.reason });
      const unavailable = rate.reason.includes("required") || rate.reason.includes("unavailable");
      return text(rate.reason, unavailable ? 503 : 429);
    }
    const outcome = await dispatch(env, decision);
    log({ delivery, event, result: outcome.dispatched ? "dispatched" : "not dispatched",
          act: decision.act, target, reason: outcome.reason });
    return text(`${outcome.dispatched ? "dispatched" : "acknowledged"} ${decision.act} for ${target}: ${outcome.reason}`,
                outcome.ok ? 200 : 502);
  },
};

// Ask Actions to run the scan. The pull-request number rides along as an input
// so the run can check that pull request out and comment on it — dispatching the
// bare branch would scan the wrong tree and lose the thread to reply on.
//
// Only `tridelphi.yml` (the scan) is ever dispatched. Fix requests are handled
// by the in-repo issue_comment workflow, never from here — see route.js.
//
// The token needs exactly one permission: `actions: write` on the allowlisted
// repositories. Not contents, not pull-requests — the run itself holds those,
// scoped to the job that needs them. If this credential leaks, it can start a
// workflow and nothing else.
async function dispatch(env, decision) {
  if (!env.GITHUB_DISPATCH_TOKEN) {
    return { ok: true, dispatched: false, reason: "no GITHUB_DISPATCH_TOKEN; verified and acknowledged only" };
  }

  const workflow = "tridelphi.yml";
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
      signal: AbortSignal.timeout(10_000),
    });
  } catch (err) {
    return { ok: false, dispatched: false, reason: `dispatch request failed: ${err?.message || err}` };
  }

  if (response.ok) return { ok: true, dispatched: true, reason: `${workflow} on ${decision.ref}` };
  // GitHub's error body is small and says useful things ("workflow does not have
  // workflow_dispatch trigger"), so surface it rather than only the status.
  const detail = (await responseSnippet(response).catch(() => "")).slice(0, 200);
  return { ok: false, dispatched: false, reason: `GitHub returned ${response.status}: ${detail}` };
}
