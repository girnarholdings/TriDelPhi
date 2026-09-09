// Durable Object replay/rate semantics without a Cloudflare account.

import assert from "node:assert";
import { ReplayGuard } from "../src/state.js";

class FakeStorage {
  constructor() {
    this.values = new Map();
    this.alarm = null;
    this.queue = Promise.resolve();
  }

  async transaction(fn) {
    let release;
    const previous = this.queue;
    this.queue = new Promise((resolve) => { release = resolve; });
    await previous;
    try {
      return await fn(this);
    } finally {
      release();
    }
  }

  get(key) { return this.values.get(key); }
  put(key, value) { this.values.set(key, value); }
  delete(keys) {
    for (const key of Array.isArray(keys) ? keys : [keys]) this.values.delete(key);
  }
  list() { return new Map(this.values); }
  getAlarm() { return this.alarm; }
  setAlarm(value) { this.alarm = value; }
}

const storage = new FakeStorage();
const guard = new ReplayGuard({ storage });
const call = async (kind, key, now) => {
  const response = await guard.fetch(new Request("https://state.invalid/guard", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ kind, key, now }),
  }));
  return { status: response.status, body: await response.json() };
};

const now = 2_000_000_000_000;
const concurrent = await Promise.all([
  call("delivery", "delivery_12345678", now),
  call("delivery", "delivery_12345678", now),
]);
assert.equal(concurrent.filter((result) => result.body.allowed).length, 1);
assert.equal(concurrent.filter((result) => !result.body.allowed).length, 1);

const afterTtl = await call("delivery", "delivery_12345678", now + 10 * 60 * 1000 + 1);
assert.equal(afterTtl.body.allowed, true);

for (let index = 0; index < 30; index++) {
  assert.equal((await call("rate", "acme/demo", now + index)).body.allowed, true);
}
assert.equal((await call("rate", "acme/demo", now + 31)).body.allowed, false);
assert.equal((await call("rate", "acme/demo", now + 60 * 1000 + 1)).body.allowed, true);

assert.equal((await call("delivery", "../bad", now)).status, 400);
console.log("\n5 Durable Object state tests passed");
