// GitHub webhook signature verification — the security-critical half of the bot.
//
// GitHub signs every webhook delivery with HMAC-SHA256 over the raw body, in the
// `X-Hub-Signature-256: sha256=<hex>` header. A receiver that skips this check
// will act on forged events — which for a security bot is the whole ballgame.
// Kept in its own module, pure and dependency-free, so it is unit-testable under
// plain Node as well as in the Worker runtime.

const encoder = new TextEncoder();

// Constant-time comparison. A byte-by-byte `===` on the hex digests leaks timing
// and is itself a bypass primitive; compare fixed-length buffers with XOR.
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function toHex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Verify `X-Hub-Signature-256` against the raw request body. `rawBody` must be
// the exact bytes GitHub signed — never a re-serialized parsed object, or
// whitespace and key order changes will break the digest.
export async function verifySignature(secret, rawBody, signatureHeader) {
  if (!secret || !signatureHeader) return false;
  const [scheme, provided] = String(signatureHeader).split("=");
  if (scheme !== "sha256" || !provided) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign("HMAC", key, encoder.encode(rawBody));
  const expected = toHex(mac);
  return timingSafeEqual(expected, provided.toLowerCase());
}

export { timingSafeEqual };
