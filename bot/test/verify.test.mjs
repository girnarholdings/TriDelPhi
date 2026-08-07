// Unit tests for the webhook signature check. Runs under plain Node (uses the
// same global WebCrypto the Worker uses), so `node test/verify.test.mjs` works
// with no wrangler and no network. The signature check is the security boundary
// of the whole bot, so it is the thing most worth testing.

import assert from "node:assert";
import { createHmac } from "node:crypto";
import { verifySignature, timingSafeEqual } from "../src/verify.js";

function githubSignature(secret, body) {
  return "sha256=" + createHmac("sha256", secret).update(body).digest("hex");
}

let passed = 0;
async function test(name, fn) {
  await fn();
  passed++;
  console.log(`  ok  ${name}`);
}

const SECRET = "it's-a-secret";
const BODY = JSON.stringify({ action: "opened", pull_request: { number: 7 } });

await test("accepts a correctly signed body", async () => {
  const sig = githubSignature(SECRET, BODY);
  assert.equal(await verifySignature(SECRET, BODY, sig), true);
});

await test("rejects a body tampered after signing", async () => {
  const sig = githubSignature(SECRET, BODY);
  const tampered = BODY.replace('"number":7', '"number":9');
  assert.equal(await verifySignature(SECRET, tampered, sig), false);
});

await test("rejects the wrong secret", async () => {
  const sig = githubSignature("attacker-guess", BODY);
  assert.equal(await verifySignature(SECRET, BODY, sig), false);
});

await test("rejects a missing signature", async () => {
  assert.equal(await verifySignature(SECRET, BODY, null), false);
  assert.equal(await verifySignature(SECRET, BODY, ""), false);
});

await test("rejects a non-sha256 scheme", async () => {
  const sha1 = "sha1=" + createHmac("sha1", SECRET).update(BODY).digest("hex");
  assert.equal(await verifySignature(SECRET, BODY, sha1), false);
});

await test("rejects when no secret is configured", async () => {
  const sig = githubSignature(SECRET, BODY);
  assert.equal(await verifySignature("", BODY, sig), false);
  assert.equal(await verifySignature(undefined, BODY, sig), false);
});

await test("signature is case-insensitive on the hex digest", async () => {
  const sig = githubSignature(SECRET, BODY).toUpperCase().replace("SHA256", "sha256");
  assert.equal(await verifySignature(SECRET, BODY, sig), true);
});

await test("timingSafeEqual basics", () => {
  assert.equal(timingSafeEqual("abc", "abc"), true);
  assert.equal(timingSafeEqual("abc", "abd"), false);
  assert.equal(timingSafeEqual("abc", "abcd"), false);
});

console.log(`\n${passed} tests passed`);
