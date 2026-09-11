// Private Durable Object binding only. No public routing to storage operations.
// Records contain short-lived login/session metadata, never repository source.
export class PortalState {
  constructor(ctx) { this.ctx = ctx; }

  async fetch(request) {
    const { op, record } = await request.json();
    const now = Date.now();
    if (op === "reserve") {
      if (!record || !Number.isSafeInteger(record.expires) ||
          record.expires <= now || record.expires > now + 30 * 60_000) {
        return new Response(null, { status: 400 });
      }
      // Per-user creation lock. Persist atomically before any external POST.
      return Response.json(await this.ctx.storage.transaction(async txn => {
        const previous = await txn.get("record");
        if (previous?.expires > now) return { acquired: false, record: previous };
        await txn.setAlarm(record.expires);
        await txn.put("record", record);
        return { acquired: true };
      }));
    }
    if (op === "put") {
      if (!record || !Number.isSafeInteger(record.expires) ||
          record.expires <= now || record.expires > now + 30 * 60_000) {
        return new Response(null, { status: 400 });
      }
      // Commit expiry and data together, including updates to creation slots.
      await this.ctx.storage.transaction(async txn => {
        await txn.setAlarm(record.expires);
        await txn.put("record", record);
      });
      return Response.json({ ok: true });
    }
    if (op === "delete") {
      await this.ctx.storage.transaction(async txn => {
        await txn.delete("record");
        await txn.deleteAlarm();
      });
      return Response.json({ ok: true });
    }
    if (op !== "get" && op !== "take") return new Response(null, { status: 400 });
    const value = await this.ctx.storage.transaction(async txn => {
      const value = await txn.get("record");
      if (op === "take" || value?.expires <= now) {
        await txn.delete("record");
        await txn.deleteAlarm();
      }
      return value?.expires > now ? value : null;
    });
    return Response.json(value);
  }

  async alarm() {
    // An old alarm may run after an expired slot has been reserved again.
    // Never erase a live replacement lock/session or enable duplicate creation.
    await this.ctx.storage.transaction(async txn => {
      const record = await txn.get("record");
      if (record?.expires > Date.now()) {
        await txn.setAlarm(record.expires);
      } else {
        await txn.delete("record");
        await txn.deleteAlarm();
      }
    });
  }
}
