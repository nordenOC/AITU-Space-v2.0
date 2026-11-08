// QR token = bookingId.exp.nonce.signature   (all URL-safe)
//   bookingId : booking UUID
//   exp       : unix seconds (decided by the DATABASE clock, 60 s after issue)
//   nonce     : UUID, row key in qr_tokens (single-use tracking)
//   signature : base64url(HMAC-SHA256(secret, "bookingId.exp.nonce"))
// Uses only WebCrypto, so it runs in Deno (Edge Functions) and Node (tests).

const enc = new TextEncoder();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export const QR_TTL_SECONDS = 60;

function b64urlEncode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(str: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(str)) return null;
  const pad = str.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((str.length + 3) % 4);
  try {
    const bin = atob(pad);
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

function key(secret: string, usage: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, usage);
}

export async function signQr(secret: string, bookingId: string, exp: number, nonce: string): Promise<string> {
  const payload = `${bookingId}.${exp}.${nonce}`;
  const sig = await crypto.subtle.sign("HMAC", await key(secret, ["sign"]), enc.encode(payload));
  return `${payload}.${b64urlEncode(new Uint8Array(sig))}`;
}

export type QrParts = { bookingId: string; exp: number; nonce: string };
export type QrResult =
  | { ok: true; parts: QrParts }
  | { ok: false; reason: "malformed" | "bad_signature" | "expired" };

/** Verifies format, signature (constant time via crypto.subtle.verify) and expiry. */
export async function verifyQr(secret: string, token: unknown, nowMs = Date.now()): Promise<QrResult> {
  if (typeof token !== "string" || token.length > 256) return { ok: false, reason: "malformed" };
  const p = token.split(".");
  if (p.length !== 4) return { ok: false, reason: "malformed" };
  const [bookingId, expStr, nonce, sigStr] = p;
  if (!UUID.test(bookingId) || !UUID.test(nonce) || !/^\d{1,12}$/.test(expStr)) {
    return { ok: false, reason: "malformed" };
  }
  const sig = b64urlDecode(sigStr);
  if (!sig || sig.length !== 32) return { ok: false, reason: "malformed" };

  const valid = await crypto.subtle.verify(
    "HMAC", await key(secret, ["verify"]), sig as BufferSource, enc.encode(`${bookingId}.${expStr}.${nonce}`),
  );
  if (!valid) return { ok: false, reason: "bad_signature" };

  const exp = Number(expStr);
  if (exp * 1000 <= nowMs) return { ok: false, reason: "expired" };
  return { ok: true, parts: { bookingId, exp, nonce } };
}

