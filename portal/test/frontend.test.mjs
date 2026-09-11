import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

function page(signedIn = false, workspaceUrl = "https://test-workspace.github.dev/", hostname = "scan.tridelphi.com") {
  const elements = new Map(); const calls = [];
  const element = id => {
    if (!elements.has(id)) elements.set(id, { hidden: false, checked: false, disabled: true, textContent: "", attributes: {},
      classList: { add() {}, toggle() {} }, setAttribute(k, v) { this.attributes[k] = v; },
      querySelector: () => element("connect-link"),
      addEventListener(k, v) { this[k] = v; } });
    return elements.get(id);
  };
  runInNewContext(readFileSync(new URL("../public/app.js", import.meta.url), "utf8"), {
    document: { getElementById: element, querySelectorAll: () => [] }, URL, location: { hostname },
    fetch: async (path, init) => {
      calls.push({ path, init });
      if (path === "/api/config") return Response.json({ installUrl: "https://github.com/apps/tridelphi-security/installations/new" });
      if (path === "/api/session") return signedIn ? Response.json({ login: "builder", tier: "free" }) : Response.json({ error: "Sign in with the TriDelPhi GitHub App to continue." }, { status: 401 });
      if (path === "/api/codespaces") return Response.json({ url: workspaceUrl, message: "Preparing workspace" });
      throw new Error("Unexpected route");
    },
  });
  return { element, calls, ready: () => new Promise(resolve => setImmediate(resolve)) };
}
test("static localhost preview makes no API calls and points sign-in to production", async () => {
  const p = page(false, undefined, "127.0.0.1"); await p.ready();
  assert.equal(p.calls.length, 0);
  assert.match(p.element("status").textContent, /Design preview/);
  assert.equal(p.element("connect-link").href, "https://scan.tridelphi.com/");
  p.element("billing").checked = true; await p.element("codespaces").click();
  assert.equal(p.calls.length, 0);
});
test("local option works anonymously; loading and switching never create compute", async () => {
  const p = page(); await p.ready();
  p.element("choose-local").click();
  assert.equal(p.element("local-panel").hidden, false);
  assert.equal(p.element("cloud-panel").hidden, true);
  assert.equal(p.element("choose-local").attributes["aria-pressed"], "true");
  assert.equal(p.element("billing").disabled, true);
  assert.ok(p.calls.every(c => c.path !== "/api/codespaces"));
});
test("creation requires confirmation; duplicate clicks send one request", async () => {
  const p = page(true); await p.ready();
  await p.element("codespaces").click();
  assert.ok(p.calls.every(c => c.path !== "/api/codespaces"));
  p.element("billing").checked = true;
  await Promise.all([p.element("codespaces").click(), p.element("codespaces").click()]);
  const requests = p.calls.filter(c => c.path === "/api/codespaces");
  assert.equal(requests.length, 1);
  assert.deepEqual(JSON.parse(requests[0].init.body), { acceptGitHubBilling: true, createWorkspace: true });
  assert.equal(p.element("launch").href, "https://test-workspace.github.dev/");
});
test("untrusted workspace URLs never become launch links", async () => {
  const p = page(true, "https://test.github.dev.attacker.example/"); await p.ready();
  p.element("billing").checked = true; await p.element("codespaces").click();
  assert.equal(p.element("launch").hidden, true);
  assert.match(p.element("status").textContent, /could not be verified/);
});
