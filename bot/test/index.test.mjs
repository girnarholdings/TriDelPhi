// Request-boundary tests for the Worker handler. No network and no Wrangler.

import assert from "node:assert";
import { createHmac, randomUUID } from "node:crypto";
import worker from "../src/index.js";

let passed = 0;
async function test(name, fn) {
  await fn();
  passed++;
  console.log(`  ok  ${name}`);
}

const SECRET = "test-webhook-secret";
const payload = JSON.stringify({
  action: "opened",
  repository: {
    id: 1,
    name: "demo",
    full_name: "acme/demo",
    default_branch: "main",
    owner: { login: "acme" },
  },
  pull_request: {
    number: 7,
    draft: false,
    base: { ref: "main" },
    head: { repo: { id: 1, full_name: "acme/demo" } },
  },
});

const signature = (body) => `sha256=${createHmac("sha256", SECRET).update(body).digest("hex")}`;
const request = (body = payload, headers = {}) => new Request("https://bot.invalid/", {
  method: "POST",
  headers: {
    "content-type": "application/json",
    "x-github-delivery": randomUUID(),
    "x-github-event": "pull_request",
    "x-hub-signature-256": signature(body),
    ...headers,
  },
  body,
});
const env = { GITHUB_WEBHOOK_SECRET: SECRET, ALLOWED_REPOS: "acme/demo" };

await test("accepts a bounded signed JSON delivery", async () => {
  const response = await worker.fetch(request(), env);
  assert.equal(response.status, 200);
  assert.match(await response.text(), /acknowledged scan/);
});

await test("requires GitHub's JSON content type", async () => {
  const response = await worker.fetch(request(payload, { "content-type": "text/plain" }), env);
  assert.equal(response.status, 415);
});

await test("rejects media types that merely start with application/json", async () => {
  const response = await worker.fetch(request(payload, { "content-type": "application/json-malformed" }), env);
  assert.equal(response.status, 415);
});

await test("rejects an oversized body before parsing", async () => {
  const body = JSON.stringify({ padding: "x".repeat(1024 * 1024) });
  const response = await worker.fetch(request(body), env);
  assert.equal(response.status, 413);
});

await test("makes a delivery id single use", async () => {
  const delivery = randomUUID();
  const first = await worker.fetch(request(payload, { "x-github-delivery": delivery }), env);
  const second = await worker.fetch(request(payload, { "x-github-delivery": delivery }), env);
  assert.equal(first.status, 200);
  assert.equal(second.status, 409);
});

await test("rejects malformed delivery identifiers", async () => {
  const response = await worker.fetch(request(payload, { "x-github-delivery": "../bad" }), env);
  assert.equal(response.status, 400);
});

await test("fails closed if a dispatch token has no global state guard", async () => {
  const response = await worker.fetch(
    request(),
    { ...env, GITHUB_DISPATCH_TOKEN: "credential-present" },
  );
  assert.equal(response.status, 503);
  assert.match(await response.text(), /REPLAY_GUARD/);
});

await test("bounds and contains a failed GitHub dispatch response", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response("x".repeat(2 * 1024 * 1024), { status: 500 });
  const replayGuard = {
    idFromName: () => "state",
    get: () => ({
      fetch: async () => new Response(JSON.stringify({ allowed: true, reason: "ok" }), {
        headers: { "content-type": "application/json" },
      }),
    }),
  };
  try {
    const response = await worker.fetch(request(), {
      ...env,
      GITHUB_DISPATCH_TOKEN: "credential-present",
      REPLAY_GUARD: replayGuard,
    });
    assert.equal(response.status, 502);
    assert.ok((await response.text()).length < 500);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

console.log(`\n${passed} tests passed`);
