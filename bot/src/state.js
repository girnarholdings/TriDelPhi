// Globally consistent replay and dispatch-rate guard.
//
// A module-level Map is per Worker isolate and therefore cannot defend a real
// deployment. Every request is routed to one named Durable Object; storage
// transactions make duplicate-delivery reservation and per-repository counters
// atomic across Cloudflare locations.

import { validRepo } from "./route.js";

const DELIVERY_TTL_MS = 10 * 60 * 1000;
const RATE_WINDOW_MS = 60 * 1000;
const MAX_DISPATCHES_PER_REPO = 30;
const MAX_ACTIVE_DELIVERIES = 10_000;
const ACTIVE_DELIVERIES_KEY = "meta:active-deliveries";
const DELIVERY_ID = /^[A-Za-z0-9_-]{8,128}$/;

function validKey(kind, key) {
  if (kind === "delivery") return DELIVERY_ID.test(key || "");
  if (kind !== "rate" || typeof key !== "string") return false;
  const parts = key.split("/");
  return parts.length === 2 && validRepo(parts[0], parts[1]);
}

const json = (value, status = 200) => new Response(JSON.stringify(value), {
  status,
  headers: { "content-type": "application/json", "cache-control": "no-store" },
});

export class ReplayGuard {
  constructor(ctx) {
    this.ctx = ctx;
  }

  async fetch(request) {
    if (request.method !== "POST") return json({ allowed: false, reason: "method" }, 405);
    let input;
    try {
      input = await request.json();
    } catch {
      return json({ allowed: false, reason: "bad state request" }, 400);
    }
    const { kind, key } = input || {};
    const now = Number(input?.now);
    if (!validKey(kind, key) || !Number.isSafeInteger(now) || now <= 0) {
      return json({ allowed: false, reason: "bad state key" }, 400);
    }
    if (kind === "delivery") return json(await this.reserveDelivery(key, now));
    if (kind === "rate") return json(await this.takeRateSlot(key, now));
    return json({ allowed: false, reason: "bad state kind" }, 400);
  }

  async reserveDelivery(delivery, now) {
    const result = await this.ctx.storage.transaction(async (txn) => {
      const storageKey = `delivery:${delivery}`;
      const stored = await txn.get(storageKey);
      const expires = Number(stored || 0);
      if (expires > now) return { allowed: false, reason: "replayed delivery id" };
      const active = Number(await txn.get(ACTIVE_DELIVERIES_KEY) || 0);
      if (stored === undefined && active >= MAX_ACTIVE_DELIVERIES) {
        return { allowed: false, reason: "delivery cache capacity exceeded" };
      }
      await txn.put(storageKey, now + DELIVERY_TTL_MS);
      if (stored === undefined) await txn.put(ACTIVE_DELIVERIES_KEY, active + 1);
      return { allowed: true, reason: "delivery reserved" };
    });
    if (result.allowed) await this.scheduleCleanup(now);
    return result;
  }

  async takeRateSlot(repo, now) {
    const result = await this.ctx.storage.transaction(async (txn) => {
      const storageKey = `rate:${repo}`;
      const state = await txn.get(storageKey);
      const current = state && Number(state.started) + RATE_WINDOW_MS > now
        ? state
        : { started: now, count: 0 };
      if (current.count >= MAX_DISPATCHES_PER_REPO) {
        return { allowed: false, reason: "dispatch rate exceeded" };
      }
      await txn.put(storageKey, { started: current.started, count: current.count + 1 });
      return { allowed: true, reason: "dispatch rate slot reserved" };
    });
    if (result.allowed) await this.scheduleCleanup(now);
    return result;
  }

  async scheduleCleanup(now) {
    if (!(await this.ctx.storage.getAlarm())) {
      await this.ctx.storage.setAlarm(now + DELIVERY_TTL_MS);
    }
  }

  async alarm() {
    const now = Date.now();
    const next = await this.ctx.storage.transaction(async (txn) => {
      const values = await txn.list();
      const expired = [];
      let expiredDeliveries = 0;
      let nextExpiry = 0;
      for (const [key, value] of values) {
        if (key === ACTIVE_DELIVERIES_KEY) continue;
        const delivery = key.startsWith("delivery:");
        const expires = delivery
          ? Number(value)
          : Number(value?.started || 0) + RATE_WINDOW_MS;
        if (!expires || expires <= now) {
          expired.push(key);
          if (delivery) expiredDeliveries++;
        } else {
          nextExpiry = nextExpiry ? Math.min(nextExpiry, expires) : expires;
        }
      }
      if (expired.length) await txn.delete(expired);
      if (expiredDeliveries) {
        const active = Number(await txn.get(ACTIVE_DELIVERIES_KEY) || 0);
        await txn.put(ACTIVE_DELIVERIES_KEY, Math.max(0, active - expiredDeliveries));
      }
      return nextExpiry;
    });
    if (next) await this.ctx.storage.setAlarm(next);
  }
}
