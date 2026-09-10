// Private Durable Object binding only. No public routing to storage operations.
// Records contain short-lived login/session metadata, never repository source.
export class PortalState {
  constructor(ctx) { this.ctx = ctx; }

  async fetch(request) {
    const { op, record } = await request.json();
    const now = Date.now();
    if (op === "put") {
      if (!record || !Number.isSafeInteger(record.expires) ||
          record.expires <= now || record.expires > now + 30 * 60_000) {
        return new Response(null, { status: 400 });
      }
      // Schedule deletion first: a failure between writes must not strand a token
      // in storage without an alarm. Each random object ID is written only once.
      await this.ctx.storage.setAlarm(record.expires);
      await this.ctx.storage.put("record", record);
      return Response.json({ ok: true });
    }
    if (op === "delete") {
      await this.ctx.storage.deleteAll();
      return Response.json({ ok: true });
    }
    if (op !== "get" && op !== "take") return new Response(null, { status: 400 });
    const value = await this.ctx.storage.transaction(async txn => {
      const value = await txn.get("record");
      if (op === "take" || value?.expires <= now) await txn.delete("record");
      return value?.expires > now ? value : null;
    });
    return Response.json(value);
  }

  async alarm() { await this.ctx.storage.deleteAll(); }
}
