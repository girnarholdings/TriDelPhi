import { test } from "node:test";
import assert from "node:assert/strict";
import { createPortal } from "../src/index.js";
import { PortalState } from "../src/state.js";

const origin = "https://scan.example.test";
const sessionId = "a".repeat(64);
const token = "ghu_testAuthorization";
const session = () => ({ kind: "session", token, userId: 7, expires: Date.now() + 60_000 });

function fixture(options = {}) {
  const records = new Map([[sessionId, session()]]);
  const calls = [];
  const env = {
    PUBLIC_ORIGIN: origin, GITHUB_APP_ID: "123", GITHUB_APP_SLUG: "tridelphi-test",
    GITHUB_CLIENT_ID: "Iv1.test", GITHUB_CLIENT_SECRET: "test-client-secret",
    SCANNER_REPO: "girnarholdings/TriDelPhi", SCANNER_REF: "b".repeat(40),
    PAID_ENTITLEMENTS: "{}",
    RATE_LIMITER: { limit: async () => ({ success: true }) },
    PORTAL_STATE: {
      idFromName: id => id,
      get: id => ({ fetch: async (_url, init) => {
        const { op, record } = JSON.parse(init.body);
        if (op === "reserve") {
          const previous = records.get(id);
          if (previous?.expires > Date.now()) return Response.json({ acquired: false, record: previous });
          records.set(id, record); return Response.json({ acquired: true });
        }
        if (op === "put") { records.set(id, record); return Response.json({ ok: true }); }
        if (op === "delete") { records.delete(id); return Response.json({ ok: true }); }
        const value = records.get(id);
        if (op === "take" || value?.expires <= Date.now()) records.delete(id);
        return Response.json(value?.expires > Date.now() ? value : null);
      } }),
    },
    ASSETS: { fetch: async () => new Response("static page") },
  };
  const fetcher = async (url, init) => {
    calls.push({ url, init });
    assert.equal(init.redirect, "manual");
    if (url === "https://github.com/login/oauth/access_token") {
      return Response.json({ access_token: options.pat ? "ghp_notAnAppUserToken" : token, expires_in: 3600 });
    }
    assert.equal(init.headers.Authorization, `Bearer ${token}`);
    if (options.unavailable) throw new Error("private-sensitive-error");
    if (options.revoked) return new Response("sensitive GitHub detail", { status: 401 });
    if (options.oversized) return new Response("x".repeat(300 * 1024));
    const path = new URL(url).pathname;
    if (path.endsWith("/codespaces/machines")) return Response.json({ machines: [{ name: "basicLinux", cpus: options.noSmall ? 4 : 2 }] });
    if (path === "/repos/girnarholdings/TriDelPhi/codespaces") {
      if (options.createTimeout) throw new Error("timeout");
      return Response.json({ owner: { id: 7 }, billable_owner: { id: options.createWrongPayer ? 99 : 7 },
        repository: { id: 1234 }, machine: { cpus: 2 }, name: "tridelphi-test-space",
        web_url: options.evilUrl ? "https://evil.test/" : "https://tridelphi-test-space.github.dev/" }, { status: 201 });
    }
    if (path === "/user") return Response.json({ id: options.userId ?? 7, login: "builder" });
    if (path === "/user/installations") return Response.json({ installations: options.noInstall ? [] : [
      { app_id: options.wrongApp ? 456 : 123, suspended_at: options.suspended ? "today" : null },
    ] });
    if (path.endsWith("/codespaces/new")) {
      if (options.codespacesDenied) return new Response(null, { status: 403 });
      return Response.json({ billable_owner: { id: options.otherPayer ? 99 : 7 } });
    }
    if (path === "/repos/girnarholdings/TriDelPhi") {
      return Response.json({ id: 1234, full_name: env.SCANNER_REPO, private: false });
    }
    throw new Error(`Unexpected network call: ${url}`);
  };
  const worker = createPortal(fetcher);
  const request = (path, opts = {}) => {
    const method = opts.method ?? (path === "/api/codespaces" || path === "/api/scan" || path === "/auth/logout" ? "POST" : "GET");
    const headers = {
      "CF-Connecting-IP": "192.0.2.1", Origin: origin,
      ...(opts.auth === false ? {} : { Cookie: `__Host-tridelphi-session=${sessionId}` }),
      ...(method === "POST" ? { "Content-Type": "application/json" } : {}),
      ...opts.headers,
    };
    return worker.fetch(new Request(origin + path, { method, headers,
      ...(method === "POST" ? { body: JSON.stringify(opts.body ?? { acceptGitHubBilling: true, createWorkspace: true }) } : {}) }), env);
  };
  return { env, request, worker, records, calls };
}

test("unconfigured App fails closed without contacting GitHub", async () => {
  const f = fixture(); f.env.GITHUB_CLIENT_SECRET = "";
  assert.equal((await f.request("/auth/login")).status, 503);
  assert.equal(f.calls.length, 0);
});

for (const path of ["/api/session", "/api/codespaces", "/api/scan"]) {
  test(`anonymous requests cannot use ${path}`, async () => {
    const f = fixture(); assert.equal((await f.request(path, { auth: false })).status, 401);
    assert.equal(f.calls.length, 0);
  });
}

test("spoofed user and paid headers do not authenticate", async () => {
  const f = fixture();
  assert.equal((await f.request("/api/scan", { auth: false, headers: {
    Authorization: "Bearer arbitrary-token", "X-User-Id": "7", "X-Tier": "paid",
  } })).status, 401);
});

test("free user cannot trigger paid compute, even by claiming payment", async () => {
  const f = fixture();
  assert.equal((await f.request("/api/scan", { body: { paid: true, tier: "paid" } })).status, 402);
  assert.equal(f.calls.length, 2);
});

test("paid pilot remains disabled, receives no uploads and starts no compute", async () => {
  const f = fixture(); f.env.PAID_ENTITLEMENTS = JSON.stringify({ 7: Date.now() + 60_000 });
  assert.equal((await f.request("/api/scan")).status, 503);
  assert.equal((await (await f.request("/api/session")).json()).paidScanningAvailable, false);
  assert.ok(f.calls.every(c => c.url.startsWith("https://api.github.com/")));
});

for (const entitlement of ['{"7":1}', '{"7":"paid"}', '{', 'null']) {
  test(`invalid/expired entitlement fails closed: ${entitlement}`, async () => {
    const f = fixture(); f.env.PAID_ENTITLEMENTS = entitlement;
    assert.equal((await f.request("/api/scan")).status, 402);
  });
}

for (const options of [{ noInstall: true }, { wrongApp: true }, { suspended: true },
  { revoked: true }, { userId: 8 }]) {
  test(`revalidate GitHub identity and App installation: ${JSON.stringify(options)}`, async () => {
    const f = fixture(options);
    assert.ok([401, 403].includes((await f.request("/api/codespaces")).status));
    assert.ok(f.calls.every(c => !c.url.includes("/codespaces/")));
  });
}

test("Codespaces creation is pinned and bounded, never requested target", async () => {
  const f = fixture();
  const response = await f.request("/api/codespaces", { body: {
    acceptGitHubBilling: true, createWorkspace: true, repo: "attacker/evil", ref: "evil", returnTo: "https://evil.test",
  } });
  assert.equal(response.status, 200);
  const url = new URL((await response.json()).url);
  assert.equal(url.href, "https://tridelphi-test-space.github.dev/");
  const writes = f.calls.filter(c => c.init.method === "POST");
  assert.equal(writes.length, 1);
  assert.equal(writes[0].url, "https://api.github.com/repos/girnarholdings/TriDelPhi/codespaces");
  assert.deepEqual(JSON.parse(writes[0].init.body), { ref: f.env.SCANNER_REF, machine: "basicLinux",
    devcontainer_path: ".devcontainer/scan/devcontainer.json", multi_repo_permissions_opt_out: true,
    idle_timeout_minutes: 5, retention_period_minutes: 60, display_name: "TriDelPhi security scan" });
  assert.equal((await f.request("/api/codespaces")).status, 200);
  assert.equal(f.calls.filter(c => c.init.method === "POST").length, 1);
});

test("concurrent workspace clicks create at most one workspace", async () => {
  const f = fixture();
  const responses = await Promise.all([f.request("/api/codespaces"), f.request("/api/codespaces")]);
  assert.ok(responses.every(r => [200, 409].includes(r.status)));
  assert.equal(f.calls.filter(c => c.init.method === "POST").length, 1);
});
for (const options of [{ createTimeout: true }, { createWrongPayer: true }, { evilUrl: true }]) {
  test(`uncertain creation stays locked and never automatically retries: ${JSON.stringify(options)}`, async () => {
    const f = fixture(options);
    const response = await f.request("/api/codespaces");
    assert.equal(response.status, 503);
    assert.match((await response.json()).error, /may already exist/);
    assert.equal((await f.request("/api/codespaces")).status, 409);
    assert.equal(f.calls.filter(c => c.init.method === "POST").length, 1);
  });
}
test("no automatic larger machine or missing creation confirmation", async () => {
  const f = fixture({ noSmall: true });
  assert.equal((await f.request("/api/codespaces")).status, 409);
  const g = fixture();
  assert.equal((await g.request("/api/codespaces", { body: { acceptGitHubBilling: true } })).status, 400);
  assert.ok([...f.calls, ...g.calls].every(c => c.init.method !== "POST"));
});

for (const options of [{ otherPayer: true }, { codespacesDenied: true }]) {
  test(`Codespaces unavailable/wrong payer has no Cloudflare fallback: ${JSON.stringify(options)}`, async () => {
    const f = fixture(options);
    assert.equal((await f.request("/api/codespaces")).status, 403);
    assert.ok(f.calls.every(c => c.url.startsWith("https://api.github.com/")));
  });
}

test("billing acknowledgement and immutable release required", async () => {
  const f = fixture();
  assert.equal((await f.request("/api/codespaces", { body: {} })).status, 400);
  f.env.SCANNER_REF = "main";
  assert.equal((await f.request("/api/codespaces")).status, 503);
});

test("cross-origin POST rejected before identity check", async () => {
  const f = fixture();
  assert.equal((await f.request("/api/codespaces", { headers: { Origin: "https://evil.test" } })).status, 403);
  assert.equal(f.calls.length, 0);
});

test("rate limiter fails closed and prevents new state allocation", async () => {
  const f = fixture(); f.env.RATE_LIMITER.limit = async () => ({ success: false });
  assert.equal((await f.request("/auth/login")).status, 429);
  assert.equal(f.records.size, 1);
});

test("missing rate binding fails closed", async () => {
  const f = fixture(); delete f.env.RATE_LIMITER;
  assert.equal((await f.request("/api/codespaces")).status, 503);
  assert.equal(f.calls.length, 0);
});

test("upstream response is bounded and never reflected", async () => {
  const f = fixture({ oversized: true });
  const response = await f.request("/api/session");
  assert.equal(response.status, 502);
  assert.ok((await response.text()).length < 256);
});

test("duplicate session cookies are rejected", async () => {
  const f = fixture();
  assert.equal((await f.request("/api/session", { headers: {
    Cookie: `__Host-tridelphi-session=${sessionId}; __Host-tridelphi-session=${sessionId}`,
  } })).status, 401);
});

test("unsafe host and route aliases do not bypass the gates", async () => {
  const f = fixture();
  assert.equal((await f.worker.fetch(new Request("https://evil.test/api/session"), f.env)).status, 403);
  assert.equal((await f.request("/api/scan/", { auth: false })).status, 404);
  assert.equal((await f.request("/api/codespaces", { method: "GET" })).status, 405);
  assert.equal((await f.request("/auth/logout", { method: "GET" })).status, 404);
  assert.equal(f.calls.length, 0);
});

test("OAuth exchange cannot substitute a PAT for App authorization", async () => {
  const f = fixture({ pat: true });
  const response = await f.request("/auth/login");
  const id = new URL(response.headers.get("location")).searchParams.get("state");
  const callback = await f.request(`/auth/callback?state=${id}&code=code`, {
    headers: { Cookie: `__Host-tridelphi-login=${id}` },
  });
  assert.equal(callback.status, 401);
  assert.equal(f.calls.length, 1);
});

for (const options of [{ noInstall: true }, { wrongApp: true }, { suspended: true }]) {
  test(`OAuth prompts installation without granting access: ${JSON.stringify(options)}`, async () => {
    const f = fixture(options);
    const login = await f.request("/auth/login");
    const id = new URL(login.headers.get("location")).searchParams.get("state");
    const path = `/auth/callback?state=${id}&code=code&returnTo=https://evil.test`;
    const headers = { Cookie: `__Host-tridelphi-login=${id}; __Host-tridelphi-session=${sessionId}` };
    const response = await f.request(path, { headers });
    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), "https://github.com/apps/tridelphi-test/installations/new");
    assert.equal(response.headers.get("referrer-policy"), "no-referrer");
    assert.equal(f.records.size, 0);
    assert.ok(!response.headers.get("set-cookie").includes(token));
    assert.equal((await f.request(path, { headers })).status, 401);
    assert.equal((await f.request("/api/session")).status, 401);
  });
}

test("installation return ignores forged IDs and starts a fresh login, not a session", async () => {
  const f = fixture();
  const response = await f.request("/auth/installed?installation_id=123&setup_action=install&returnTo=https://evil.test", { auth: false });
  assert.equal(response.status, 303);
  assert.equal(response.headers.get("location"), origin + "/auth/login");
  assert.equal(response.headers.get("set-cookie"), null);
  assert.equal(f.calls.length, 0);
  assert.equal((await f.request("/api/session", { auth: false })).status, 401);
  assert.equal((await f.request("/auth/installed", { method: "POST" })).status, 404);
});

test("oversized metadata refused", async () => {
  const f = fixture();
  assert.equal((await f.request("/api/codespaces", { body: { junk: "x".repeat(2048) } })).status, 413);
});

test("OAuth PKCE, browser binding, rotation and single use", async () => {
  const f = fixture();
  const login = await f.request("/auth/login", { auth: false });
  assert.equal(login.status, 303);
  const location = new URL(login.headers.get("location"));
  const id = location.searchParams.get("state");
  assert.match(id, /^[a-f0-9]{64}$/);
  assert.equal(location.searchParams.get("code_challenge_method"), "S256");
  assert.ok(location.searchParams.get("code_challenge"));
  const path = `/auth/callback?state=${id}&code=test-code`;
  assert.equal((await f.request(path, { auth: false })).status, 401);
  assert.ok(f.records.has(id));
  const callback = await f.request(path, { headers: {
    Cookie: `__Host-tridelphi-login=${id}; __Host-tridelphi-session=${sessionId}`,
  } });
  assert.equal(callback.status, 303);
  assert.equal(callback.headers.get("location"), origin + "/");
  const cookies = callback.headers.get("set-cookie");
  assert.ok(cookies.includes("Secure; HttpOnly; SameSite=Lax"));
  assert.ok(!cookies.includes(token));
  assert.ok(!f.records.has(sessionId));
  assert.ok(!f.records.has(id));
  assert.equal((await f.request(path, { headers: { Cookie: `__Host-tridelphi-login=${id}` } })).status, 401);
  assert.equal(f.calls.filter(c => c.url.includes("access_token")).length, 1);
});

test("logout destroys session and expired sessions do not authenticate", async () => {
  const f = fixture();
  assert.equal((await f.request("/auth/logout")).status, 200);
  assert.equal((await f.request("/api/session")).status, 401);
  f.records.set(sessionId, { ...session(), expires: Date.now() - 1 });
  assert.equal((await f.request("/api/session")).status, 401);
});

test("errors and static responses have security headers and no sensitive details", async () => {
  const f = fixture({ unavailable: true });
  for (const path of ["/", "/api/session", "/unknown"]) {
    const response = await f.request(path);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(response.headers.get("referrer-policy"), "no-referrer");
    assert.match(response.headers.get("content-security-policy"), /frame-ancestors 'none'/);
    assert.ok(!(await response.text()).includes("private-sensitive-error"));
  }
});

test("real storage object consumes records once and purges by alarm", async () => {
  const data = new Map(); let alarm;
  const storage = {
    get: async k => data.get(k), put: async (k, v) => { data.set(k, v); },
    delete: async k => data.delete(k), deleteAll: async () => data.clear(),
    setAlarm: async time => { alarm = time; },
    transaction: async fn => fn(storage),
  };
  const object = new PortalState({ storage });
  const call = async (op, record) => object.fetch(new Request("https://state.internal", {
    method: "POST", body: JSON.stringify({ op, record }),
  }));
  assert.equal((await call("put", { expires: Date.now() + 31 * 60_000 })).status, 400);
  await call("put", session());
  assert.ok(alarm > Date.now());
  assert.equal((await (await call("take")).json()).token, token);
  assert.equal(await (await call("take")).json(), null);
  await call("put", session());
  await object.alarm();
  assert.equal(await (await call("get")).json(), null);
});
