// Run explicitly with node --test test/runtime.mjs. Reuses bot dependencies;
// PORTAL_TEST_PACKAGE_JSON may point to another checkout's bot/package.json.
// All outbound traffic terminates in the mock, including unexpected requests.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
const require = createRequire(process.env.PORTAL_TEST_PACKAGE_JSON || new URL("../../bot/package.json", import.meta.url));
const { build } = require("esbuild");
const { Miniflare, convertV4MiniflareOptions } = require("miniflare");
// Miniflare 5 takes a `workers` array; older toolchains take the v4 shape as-is.
const v4Options = convertV4MiniflareOptions ?? (options => options);
const origin = "https://scan.example.test";
const bundle = await build({ stdin: { contents: `
  export { default } from './index.js';
  import { PortalState } from './state.js';
  export class TestState extends PortalState {
    async fetch(request) {
      const path = new URL(request.url).pathname;
      if (path === '/inspect') return Response.json({
        record: await this.ctx.storage.get('record') ?? null,
        alarm: await this.ctx.storage.getAlarm(),
      });
      if (path === '/alarm') { await this.alarm(); return Response.json({ ok: true }); }
      return super.fetch(request);
    }
  }`, resolveDir: fileURLToPath(new URL("../src/", import.meta.url)), sourcefile: "runtime-harness.js" },
  bundle: true, write: false, format: "esm", platform: "browser" });

for (const uncertain of [false, true]) {
  test(`full mocked install/auth/workspace/logout workflow, uncertain=${uncertain}`, async () => {
    let installed = false;
    const calls = [];
    const mf = new Miniflare(v4Options({
      modules: true, script: bundle.outputFiles[0].text, compatibilityDate: "2026-08-01",
      bindings: { PUBLIC_ORIGIN: origin, GITHUB_CLIENT_ID: "fake-client", GITHUB_CLIENT_SECRET: "fake-secret",
        GITHUB_APP_ID: "123", GITHUB_APP_SLUG: "tridelphi-test", PAID_ENTITLEMENTS: "{}",
        SCANNER_REPO: "girnarholdings/TriDelPhi", SCANNER_REF: "b".repeat(40) },
      durableObjects: { PORTAL_STATE: { className: "TestState", useSQLite: true } },
      ratelimits: { RATE_LIMITER: { namespace_id: "1001", simple: { limit: 100, period: 60 } } },
      outboundService: async request => {
        calls.push({ url: request.url, method: request.method });
        if (request.url === "https://github.com/login/oauth/access_token") {
          const input = await request.json();
          assert.equal(input.client_secret, "fake-secret");
          assert.match(input.code_verifier, /^[a-f0-9]{64}$/);
          return Response.json({ access_token: "ghu_fakeToken", expires_in: 3600 });
        }
        assert.equal(request.headers.get("authorization"), "Bearer ghu_fakeToken");
        const url = new URL(request.url);
        assert.equal(url.origin, "https://api.github.com");
        if (url.pathname === "/user") return Response.json({ id: 7, login: "builder" });
        if (url.pathname === "/user/installations") return Response.json({ installations: installed ? [{ app_id: 123, suspended_at: null }] : [] });
        if (url.pathname === "/repos/girnarholdings/TriDelPhi") return Response.json({ id: 1234, full_name: "girnarholdings/TriDelPhi", private: false });
        if (url.pathname.endsWith("/codespaces/new")) return Response.json({ billable_owner: { id: 7 } });
        if (url.pathname.endsWith("/codespaces/machines")) return Response.json({ machines: [{ name: "basicLinux", cpus: 2 }] });
        if (url.pathname === "/repos/girnarholdings/TriDelPhi/codespaces") {
          assert.equal(request.method, "POST");
          assert.deepEqual(await request.json(), { ref: "b".repeat(40), machine: "basicLinux",
            devcontainer_path: ".devcontainer/scan/devcontainer.json", multi_repo_permissions_opt_out: true,
            idle_timeout_minutes: 5, retention_period_minutes: 60, display_name: "TriDelPhi security scan" });
          if (uncertain) return Response.json({ error: "mock ambiguous failure" }, { status: 503 });
          return Response.json({ owner: { id: 7 }, billable_owner: { id: 7 }, repository: { id: 1234 },
            machine: { cpus: 2 }, name: "test-workspace", web_url: "https://test-workspace.github.dev/" }, { status: 201 });
        }
        assert.fail(`Unexpected outbound request: ${url.pathname}`);
      },
    }));
    const headers = { "CF-Connecting-IP": "192.0.2.1" };
    const send = (path, init = {}) => mf.dispatchFetch(origin + path, { redirect: "manual", ...init,
      headers: { ...headers, ...init.headers } });
    const login = async () => {
      const response = await send("/auth/login");
      assert.equal(response.status, 303);
      return { state: new URL(response.headers.get("location")).searchParams.get("state"),
        cookie: response.headers.get("set-cookie").split(";")[0] };
    };
    const callback = pending => send(`/auth/callback?state=${pending.state}&code=fake-code`, { headers: { Cookie: pending.cookie } });
    try {
      const first = await login();
      const install = await callback(first);
      assert.equal(install.headers.get("location"), "https://github.com/apps/tridelphi-test/installations/new");
      assert.equal((await callback(first)).status, 401);
      assert.equal((await send("/api/session")).status, 401);
      installed = true;
      const returned = await send("/auth/installed?installation_id=999&setup_action=install");
      assert.equal(returned.headers.get("location"), origin + "/auth/login");
      const second = await login();
      assert.notEqual(second.state, first.state);
      const signedIn = await callback(second);
      assert.equal(signedIn.status, 303);
      const cookie = signedIn.headers.get("set-cookie").match(/__Host-tridelphi-session=[a-f0-9]{64}/)[0];
      assert.equal((await callback(second)).status, 401);
      assert.deepEqual(await (await send("/api/session", { headers: { Cookie: cookie } })).json(),
        { login: "builder", tier: "free", paidScanningAvailable: false });
      const post = (path, body = {}, extraCookie = "") => send(path, { method: "POST",
        headers: { Origin: origin, Cookie: cookie + extraCookie, "Content-Type": "application/json" }, body: JSON.stringify(body) });
      assert.equal((await post("/api/scan", { source: "must-not-be-stored" })).status, 402);
      assert.equal((await post("/api/codespaces", { acceptGitHubBilling: true })).status, 400);
      const create = () => post("/api/codespaces", { acceptGitHubBilling: true, createWorkspace: true });
      const attempts = await Promise.all([create(), create()]);
      assert.ok(attempts.every(r => (uncertain ? [503, 409] : [200, 409]).includes(r.status)));
      assert.ok(attempts.some(r => r.status === (uncertain ? 503 : 200)));
      const before = calls.length;
      assert.equal((await create()).status, uncertain ? 409 : 200);
      assert.equal(calls.length - before, 2);
      assert.equal(calls.filter(c => c.method === "POST" && c.url.endsWith("/codespaces")).length, 1);
      installed = false;
      assert.equal((await create()).status, 403, "stored results cannot bypass revoked installation");
      const pending = await login();
      assert.equal((await post("/auth/logout", {}, `; ${pending.cookie}`)).status, 200);
      assert.equal((await callback(pending)).status, 401);
      assert.equal((await send("/api/session", { headers: { Cookie: cookie } })).status, 401);
      const namespace = await mf.getDurableObjectNamespace("PORTAL_STATE");
      const consumed = namespace.get(namespace.idFromName(second.state));
      assert.deepEqual(await (await consumed.fetch("https://state.internal/inspect")).json(),
        { record: null, alarm: null }, "consumed login has no token or unnecessary alarm");
      const replacement = namespace.get(namespace.idFromName("c".repeat(64)));
      const record = { kind: "creating", expires: Date.now() + 60_000 };
      assert.equal((await replacement.fetch("https://state.internal/", { method: "POST",
        body: JSON.stringify({ op: "reserve", record }) })).status, 200);
      await replacement.fetch("https://state.internal/alarm");
      assert.deepEqual(await (await replacement.fetch("https://state.internal/inspect")).json(),
        { record, alarm: record.expires }, "stale alarm preserves replacement lock in SQLite runtime");
    } finally { await mf.dispose(); }
  });
}
