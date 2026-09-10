export { PortalState } from "./state.js";

const SESSION = "__Host-tridelphi-session";
const LOGIN = "__Host-tridelphi-login";
const HEX = /^[a-f0-9]{64}$/;
const SHA = /^[a-f0-9]{40}$/;
const REPO = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/;
const API = "https://api.github.com";
const random = () => [...crypto.getRandomValues(new Uint8Array(32))]
  .map(x => x.toString(16).padStart(2, "0")).join("");

class Failure extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
class InstallationRequired extends Failure {
  constructor() { super(403, "Install or re-enable the TriDelPhi GitHub App, then sign in again."); }
}
const installationUrl = env => `https://github.com/apps/${env.GITHUB_APP_SLUG}/installations/new`;
const fail = (status, message) => { throw new Failure(status, message); };
const json = (value, status = 200) => Response.json(value, { status });
const redirect = url => new Response(null, { status: 303, headers: { location: url } });
const cookie = (name, value, age) =>
  `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${age}`;

function getCookie(request, name) {
  const matches = (request.headers.get("cookie") || "").split(";")
    .map(s => s.trim()).filter(s => s.startsWith(`${name}=`));
  return matches.length === 1 ? matches[0].slice(name.length + 1) : "";
}

function secure(response) {
  const headers = new Headers(response.headers);
  headers.set("Cache-Control", "no-store");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Strict-Transport-Security", "max-age=31536000");
  headers.set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  return new Response(response.body, { status: response.status, headers });
}

async function boundedJson(response, max = 256 * 1024, client = false) {
  if (!response.body) fail(502, "GitHub returned an empty response. Try again.");
  const reader = response.body.getReader();
  let total = 0;
  const chunks = [];
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > max) fail(client ? 413 : 502, "Response exceeded the safety limit.");
      chunks.push(value);
    }
  } finally { await reader.cancel(); }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  try { return JSON.parse(new TextDecoder().decode(bytes)); }
  catch { fail(client ? 400 : 502, "Invalid JSON. Try again."); }
}

async function github(path, token, fetcher, body) {
  const response = await fetcher(API + path, {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json",
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      "User-Agent": "TriDelPhi-Portal", "X-GitHub-Api-Version": "2026-03-10" },
    // Workers supports manual, not error. The !ok gate below rejects every 3xx.
    redirect: "manual", signal: AbortSignal.timeout(15_000),
    ...(body === undefined ? {} : { method: "POST", body: JSON.stringify(body) }),
  });
  if (!response.ok) {
    await response.body?.cancel();
    fail(response.status === 401 ? 401 : 403,
      "GitHub could not authorize this step. Check your App permissions and Codespaces availability, then sign in again.");
  }
  return boundedJson(response);
}

async function state(env, id, op, record) {
  if (!HEX.test(id)) fail(401, "Sign in with the TriDelPhi GitHub App to continue.");
  const response = await env.PORTAL_STATE.get(env.PORTAL_STATE.idFromName(id)).fetch(
    "https://state.internal/", { method: "POST", body: JSON.stringify({ op, record }) });
  if (!response.ok) fail(503, "Sign-in storage is unavailable. No scan was started.");
  return response.json();
}

function configured(env) {
  if (!env.PORTAL_STATE || !env.RATE_LIMITER || !env.GITHUB_CLIENT_SECRET ||
      !/^[A-Za-z0-9_.-]+$/.test(env.GITHUB_CLIENT_ID || "") ||
      !/^[1-9][0-9]*$/.test(env.GITHUB_APP_ID || "") ||
      !/^[a-z0-9-]+$/.test(env.GITHUB_APP_SLUG || "")) {
    fail(503, "GitHub App sign-in has not been configured yet. Local scanning is still available.");
  }
}

async function identity(env, token, fetcher) {
  const user = await github("/user", token, fetcher);
  if (!Number.isSafeInteger(user.id) || user.id <= 0 || typeof user.login !== "string") {
    fail(401, "GitHub identity could not be verified.");
  }
  // Installation is not login. Require both, and match immutable App ID.
  let installed = false;
  for (let page = 1; page <= 10; page++) {
    const data = await github(`/user/installations?per_page=100&page=${page}`, token, fetcher);
    if (!Array.isArray(data.installations)) fail(502, "GitHub installation check failed.");
    if (data.installations.some(i => String(i.app_id) === env.GITHUB_APP_ID && !i.suspended_at)) {
      installed = true;
      break;
    }
    if (data.installations.length < 100) break;
  }
  if (!installed) throw new InstallationRequired();
  return { id: user.id, login: user.login };
}

function paid(env, id) {
  // Operator-managed, expiring pilot entitlements. Never accept client tier claims.
  try {
    const entries = JSON.parse(env.PAID_ENTITLEMENTS || "{}");
    const expiry = entries[String(id)];
    return Number.isSafeInteger(expiry) && expiry > Date.now();
  } catch { return false; }
}

export function createPortal(fetcher = fetch) {
  return { async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (!env.PUBLIC_ORIGIN || url.origin !== env.PUBLIC_ORIGIN || url.protocol !== "https:") {
        fail(403, "Use the configured secure TriDelPhi scan address.");
      }
      const dynamic = url.pathname.startsWith("/auth/") || url.pathname.startsWith("/api/");
      if (!dynamic) {
        if (!["/", "/index.html", "/app.js", "/style.css"].includes(url.pathname) ||
            !["GET", "HEAD"].includes(request.method)) fail(404, "Not found.");
        if (!env.ASSETS) fail(503, "The scan page is unavailable.");
        return secure(await env.ASSETS.fetch(request));
      }
      configured(env);
      if (request.method === "POST" && request.headers.get("origin") !== env.PUBLIC_ORIGIN) {
        fail(403, "Open the scan page and try again.");
      }
      // Cloudflare-supplied IP, never a user-supplied account/tier or forwarding header.
      const ip = request.headers.get("CF-Connecting-IP");
      if (!ip) fail(503, "The request could not be verified.");
      if (!(await env.RATE_LIMITER.limit({ key: ip })).success) {
        fail(429, "Too many requests. Wait a minute before trying again.");
      }
      let response;
      if (url.pathname === "/auth/login" && request.method === "GET") {
        const id = random(), verifier = random();
        await state(env, id, "put", { kind: "login", verifier, expires: Date.now() + 5 * 60_000 });
        const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
        const challenge = btoa(String.fromCharCode(...digest)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
        const target = new URL("https://github.com/login/oauth/authorize");
        target.search = new URLSearchParams({ client_id: env.GITHUB_CLIENT_ID,
          redirect_uri: env.PUBLIC_ORIGIN + "/auth/callback", state: id,
          code_challenge: challenge, code_challenge_method: "S256" });
        response = redirect(target.href);
        response.headers.append("Set-Cookie", cookie(LOGIN, id, 300));
      } else if (url.pathname === "/auth/callback" && request.method === "GET") {
        const id = url.searchParams.get("state") || "";
        if (!HEX.test(id) || getCookie(request, LOGIN) !== id) fail(401, "Sign-in expired or did not start in this browser. Start again.");
        const login = await state(env, id, "take");
        if (login?.kind !== "login") fail(401, "Sign-in expired or was already used. Start again.");
        const code = url.searchParams.get("code");
        if (!code || code.length > 512) fail(401, "GitHub sign-in was not completed.");
        const tokenResponse = await fetcher("https://github.com/login/oauth/access_token", {
          method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json" },
          body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET,
            code, code_verifier: login.verifier, redirect_uri: env.PUBLIC_ORIGIN + "/auth/callback" }),
          // Never follow redirects carrying the client secret or authorization code.
          redirect: "manual", signal: AbortSignal.timeout(15_000),
        });
        if (!tokenResponse.ok) {
          await tokenResponse.body?.cancel();
          fail(401, "GitHub sign-in failed. Start again.");
        }
        const grant = await boundedJson(tokenResponse, 16_384);
        if (typeof grant.access_token !== "string" || !/^ghu_[A-Za-z0-9]+$/.test(grant.access_token)) {
          fail(401, "A GitHub App user authorization is required.");
        }
        let user;
        try { user = await identity(env, grant.access_token, fetcher); }
        catch (error) {
          if (!(error instanceof InstallationRequired)) throw error;
          // Only verified OAuth callbacks get this navigation, never API calls.
          // No token/session is retained before installation is verified.
          const previous = getCookie(request, SESSION);
          if (HEX.test(previous)) await state(env, previous, "delete");
          response = redirect(installationUrl(env));
          response.headers.append("Set-Cookie", cookie(LOGIN, "", 0));
          response.headers.append("Set-Cookie", cookie(SESSION, "", 0));
          return secure(response);
        }
        const session = random();
        const lifetime = Math.min(1800, Number(grant.expires_in ?? 1800));
        if (!Number.isFinite(lifetime) || lifetime < 1) fail(401, "GitHub authorization expired.");
        await state(env, session, "put", { kind: "session", token: grant.access_token,
          userId: user.id, expires: Date.now() + Math.floor(lifetime) * 1000 });
        const previous = getCookie(request, SESSION);
        if (HEX.test(previous)) await state(env, previous, "delete");
        response = redirect(env.PUBLIC_ORIGIN + "/");
        response.headers.append("Set-Cookie", cookie(SESSION, session, Math.floor(lifetime)));
        response.headers.append("Set-Cookie", cookie(LOGIN, "", 0));
      } else if (url.pathname === "/auth/installed" && request.method === "GET") {
        // GitHub Setup URL: installation_id/setup_action are untrusted hints.
        // Start fresh browser-bound OAuth, then re-check identity + installation.
        // Never reuse the consumed callback state or infer authentication here.
        response = redirect(env.PUBLIC_ORIGIN + "/auth/login");
      } else if (url.pathname === "/auth/logout" && request.method === "POST") {
        const id = getCookie(request, SESSION);
        if (HEX.test(id)) await state(env, id, "delete");
        response = json({ ok: true });
        response.headers.append("Set-Cookie", cookie(SESSION, "", 0));
        response.headers.append("Set-Cookie", cookie(LOGIN, "", 0));
      } else if (url.pathname === "/api/config" && request.method === "GET") {
        response = json({ installUrl: installationUrl(env) });
      } else if (["/api/session", "/api/codespaces", "/api/scan"].includes(url.pathname)) {
        if (request.method !== (url.pathname === "/api/session" ? "GET" : "POST")) fail(405, "Method not allowed.");
        const session = await state(env, getCookie(request, SESSION), "get");
        if (session?.kind !== "session") fail(401, "Sign in with the TriDelPhi GitHub App to continue.");
        // Re-check on every privileged request: revocation/suspension must take effect.
        const user = await identity(env, session.token, fetcher);
        if (user.id !== session.userId) fail(401, "GitHub identity changed. Sign in again.");
        if (url.pathname === "/api/session") {
          response = json({ login: user.login, tier: paid(env, user.id) ? "paid" : "free", paidScanningAvailable: false });
        } else if (url.pathname === "/api/scan") {
          if (!paid(env, user.id)) fail(402, "Cloudflare scanning is reserved for paid accounts. Use your own Codespace or scan locally.");
          // No public paid execution plane exists yet. Never proxy to an arbitrary URL
          // or accept uploads just because a payment/identity check succeeded.
          fail(503, "Paid hosted scanning is not launched yet. No upload was processed and no scan was started.");
        } else {
          if (request.headers.get("content-type") !== "application/json") fail(415, "Send a JSON request.");
          const input = await boundedJson(request, 1024, true);
          if (input?.acceptGitHubBilling !== true) fail(400, "Acknowledge GitHub compute and storage billing before continuing.");
          if (!REPO.test(env.SCANNER_REPO || "") || !SHA.test(env.SCANNER_REF || "")) {
            fail(503, "The trusted scanner release has not been configured yet.");
          }
          const repo = await github(`/repos/${env.SCANNER_REPO}`, session.token, fetcher);
          if (repo.full_name?.toLowerCase() !== env.SCANNER_REPO.toLowerCase() ||
              !Number.isSafeInteger(repo.id) || repo.id <= 0 || repo.private !== false) fail(503, "The trusted scanner repository could not be verified.");
          const defaults = await github(`/repos/${env.SCANNER_REPO}/codespaces/new?ref=${env.SCANNER_REF}`, session.token, fetcher);
          if (defaults.billable_owner?.id !== user.id) {
            fail(403, "This Codespace would bill another account. Free TriDelPhi scans require your own GitHub compute.");
          }
          if (input.createWorkspace !== true) fail(400, "Confirm workspace creation to continue.");
          const machines = await github(`/repos/${env.SCANNER_REPO}/codespaces/machines?ref=${env.SCANNER_REF}`, session.token, fetcher);
          const machine = Array.isArray(machines.machines) && machines.machines.find(m =>
            m.cpus === 2 && typeof m.name === "string" && /^[A-Za-z0-9_-]{1,100}$/.test(m.name));
          if (!machine) fail(409, "A 2-core workspace is not available. We will not choose a larger machine. Try scanning locally.");
          const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`workspace:${user.id}`)));
          const slot = [...digest].map(x => x.toString(16).padStart(2, "0")).join("");
          const expires = Date.now() + 30 * 60_000;
          const reservation = await state(env, slot, "reserve", { kind: "creating", expires });
          if (!reservation.acquired) {
            if (reservation.record?.kind === "workspace") return secure(json(reservation.record.result));
            fail(409, "A workspace request is already in progress or its result is uncertain. Check github.com/codespaces before trying again. Creation is paused here for up to 30 minutes to avoid duplicates.");
          }
          // Never retry this POST: a timeout can still mean GitHub created it.
          try {
            const workspace = await github(`/repos/${env.SCANNER_REPO}/codespaces`, session.token, fetcher, {
              ref: env.SCANNER_REF, machine: machine.name,
              devcontainer_path: ".devcontainer/scan/devcontainer.json",
              multi_repo_permissions_opt_out: true, idle_timeout_minutes: 5,
              retention_period_minutes: 60, display_name: "TriDelPhi security scan",
            });
            if (workspace.owner?.id !== user.id || workspace.billable_owner?.id !== user.id ||
                workspace.repository?.id !== repo.id || workspace.machine?.cpus !== 2 ||
                typeof workspace.name !== "string" || !/^[a-z0-9-]{1,100}$/.test(workspace.name)) {
              throw new Error("Unverified workspace");
            }
            const target = new URL(workspace.web_url);
            if (target.protocol !== "https:" || target.hostname !== `${workspace.name}.github.dev` ||
                target.port || target.username || target.password || target.pathname !== "/" || target.search || target.hash) {
              throw new Error("Unverified workspace URL");
            }
            const result = { url: target.href, created: true, message: "Your workspace is being prepared. Open it below. Save your report before deleting it; idle workspaces are scheduled for cleanup." };
            await state(env, slot, "put", { kind: "workspace", result, expires });
            response = json(result);
          } catch {
            fail(503, "GitHub did not confirm workspace creation. A workspace may already exist: check github.com/codespaces. We will not retry automatically; creation is paused here for up to 30 minutes to avoid duplicates.");
          }
        }
      } else fail(404, "Not found.");
      return secure(response);
    } catch (error) {
      // Never log exceptions, authorization codes, tokens, request bodies or URLs.
      return secure(json({ error: error instanceof Failure ? error.message :
        "The service is unavailable. No scan was started. Try again later." },
      error instanceof Failure ? error.status : 503));
    }
  } };
}

export default createPortal();
