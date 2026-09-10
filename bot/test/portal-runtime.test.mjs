// Uses the workerd/Miniflare toolchain pinned by bot/package-lock.json.
// All outbound traffic is intercepted: no GitHub credentials or network needed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import { fileURLToPath } from "node:url";

const origin = "https://scan.example.test";
const bundle = await build({
  entryPoints: [fileURLToPath(new URL("../../portal/src/index.js", import.meta.url))],
  bundle: true, write: false, format: "esm", platform: "browser",
});

for (const scenario of ["success", "invalid-grant", "token-redirect", "api-redirect", "install-required"]) {
  test(`Workers runtime OAuth: ${scenario}`, async () => {
    const calls = [];
    const mf = new Miniflare({
      modules: true, script: bundle.outputFiles[0].text,
      compatibilityDate: "2026-08-01",
      bindings: {
        PUBLIC_ORIGIN: origin, GITHUB_CLIENT_ID: "fake-client",
        GITHUB_CLIENT_SECRET: "fake-secret", GITHUB_APP_ID: "123",
        GITHUB_APP_SLUG: "tridelphi-test", PAID_ENTITLEMENTS: "{}",
      },
      durableObjects: { PORTAL_STATE: { className: "PortalState", useSQLite: true } },
      ratelimits: { RATE_LIMITER: { namespace_id: "1001", simple: { limit: 30, period: 60 } } },
      outboundService: async request => {
        calls.push(request.url);
        if (request.url === "https://github.com/login/oauth/access_token") {
          assert.equal(request.method, "POST");
          const body = await request.json();
          assert.equal(body.client_secret, "fake-secret");
          assert.match(body.code_verifier, /^[a-f0-9]{64}$/);
          if (scenario === "token-redirect") return Response.redirect("https://untrusted.example/", 307);
          if (scenario === "invalid-grant") return Response.json({ error: "bad_verification_code" });
          return Response.json({ access_token: "ghu_fakeToken", expires_in: 3600 });
        }
        assert.equal(request.headers.get("authorization"), "Bearer ghu_fakeToken");
        if (request.url === "https://api.github.com/user") {
          if (scenario === "api-redirect") return Response.redirect("https://untrusted.example/", 302);
          return Response.json({ id: 7, login: "builder" });
        }
        if (request.url === "https://api.github.com/user/installations?per_page=100&page=1") {
          return Response.json({ installations: scenario === "install-required" ? [] : [{ app_id: 123, suspended_at: null }] });
        }
        assert.fail("Unexpected outbound destination; redirects must not be followed");
      },
    });
    try {
      const worker = await mf.getWorker();
      const headers = { "CF-Connecting-IP": "192.0.2.1" };
      const login = await worker.fetch(origin + "/auth/login", { headers, redirect: "manual" });
      assert.equal(login.status, 303);
      const state = new URL(login.headers.get("location")).searchParams.get("state");
      const callbackUrl = origin + `/auth/callback?state=${state}&code=fake-code`;
      const callbackHeaders = { ...headers, Cookie: login.headers.get("set-cookie").split(";")[0] };
      const response = await worker.fetch(callbackUrl, { headers: callbackHeaders, redirect: "manual" });
      assert.equal(response.status, ["success", "install-required"].includes(scenario) ? 303 : scenario === "api-redirect" ? 403 : 401);
      assert.equal(response.headers.get("cache-control"), "no-store");
      if (scenario === "success") {
        assert.equal(response.headers.get("location"), origin + "/");
        const cookies = response.headers.get("set-cookie");
        assert.match(cookies, /__Host-tridelphi-session=/);
        assert.ok(!cookies.includes("ghu_fakeToken"));
        const sessionCookie = cookies.match(/__Host-tridelphi-session=[a-f0-9]{64}/)[0];
        const session = await worker.fetch(origin + "/api/session", { headers: { ...headers, Cookie: sessionCookie } });
        assert.equal(session.status, 200);
        assert.deepEqual(await session.json(), { login: "builder", tier: "free", paidScanningAvailable: false });
      } else if (scenario === "install-required") {
        assert.equal(response.headers.get("location"), "https://github.com/apps/tridelphi-test/installations/new");
        assert.ok(!response.headers.get("set-cookie").includes("ghu_fakeToken"));
        assert.equal(calls.length, 3);
        const installed = await worker.fetch(origin + "/auth/installed?installation_id=999&returnTo=https://untrusted.example", { headers, redirect: "manual" });
        assert.equal(installed.status, 303);
        assert.equal(installed.headers.get("location"), origin + "/auth/login");
        assert.equal(installed.headers.get("set-cookie"), null);
        const anonymous = await worker.fetch(origin + "/api/session", { headers });
        assert.equal(anonymous.status, 401);
      } else {
        assert.equal(response.headers.get("set-cookie"), null);
        assert.ok(!(await response.text()).includes("fake-secret"));
        assert.equal(calls.length, scenario === "api-redirect" ? 2 : 1);
      }
      const replay = await worker.fetch(callbackUrl, { headers: callbackHeaders, redirect: "manual" });
      assert.equal(replay.status, 401);
      assert.equal(calls.filter(url => url.includes("access_token")).length, 1);
    } finally { await mf.dispose(); }
  });
}
