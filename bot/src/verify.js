// GitHub webhook signature verification — the security-critical half of the bot.
//
// GitHub signs every webhook delivery with HMAC-SHA256 over the raw body, in the
// `X-Hub-Signature-256: sha256=<hex>` header. A receiver that skips this check
// will act on forged events — which for a security bot is the whole ballgame.
// Kept in its own module, pure and dependency-free, so it is unit-testable under
// plain Node as well as in the Worker runtime.

const encoder = new TextEncoder();

function bodyBytes(rawBody) {
  if (typeof rawBody === "string") return encoder.encode(rawBody);
  if (rawBody instanceof ArrayBuffer) return new Uint8Array(rawBody);
  if (ArrayBuffer.isView(rawBody)) {
    return new Uint8Array(rawBody.buffer, rawBody.byteOffset, rawBody.byteLength);
  }
  return null;
}

// Verify `X-Hub-Signature-256` against the raw request body. `rawBody` must be
// the exact bytes GitHub signed — never a re-serialized parsed object, or
// whitespace and key order changes will break the digest.
export async function verifySignature(secret, rawBody, signatureHeader) {
  if (!secret || !signatureHeader) return false;
  if (typeof signatureHeader !== "string" || signatureHeader.length !== 71 || !/^sha256=[0-9a-fA-F]{64}$/.test(signatureHeader)) return false;
  const provided = signatureHeader.slice(7);
  const bytes = bodyBytes(rawBody);
  if (!bytes) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const signature = Uint8Array.from(provided.match(/../g), (pair) => parseInt(pair, 16));
  // Delegate authentication to WebCrypto; JavaScript comparison loops do not
  // carry a constant-time guarantee through every runtime/JIT.
  return crypto.subtle.verify("HMAC", key, signature, bytes);
}
