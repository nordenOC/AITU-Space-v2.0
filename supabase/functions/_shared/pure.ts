// Pure helpers (no Deno/Node APIs) so they are unit-testable under Vitest.

const INSTITUTIONAL = /^[a-z0-9._%+-]+@astanait\.edu\.kz$/;

export function normalizeEmail(email: unknown): string | null {
  if (typeof email !== "string") return null;
  const e = email.normalize("NFKC").trim().toLowerCase();
  if (e.length === 0 || e.length > 254) return null;
  return e;
}

/** Strict check: exactly the astanait.edu.kz domain (no subdomains, no lookalikes). */
export function isInstitutionalEmail(email: unknown): boolean {
  const e = normalizeEmail(email);
  return e !== null && INSTITUTIONAL.test(e);
}

/**
 * Picks the client IP from X-Forwarded-For using the number of TRUSTED proxy
 * hops: with N trusted hops, the entry N from the right was written by our own
 * infrastructure; anything left of it is client-controlled and ignored.
 * Returns "unknown" (one shared, stricter bucket) when it cannot be trusted.
 */
export function pickClientIp(xff: string | null, trustedHops = 1): string {
  if (!xff || trustedHops < 1) return "unknown";
  const parts = xff.split(",").map((s) => s.trim()).filter(Boolean);
  const idx = parts.length - trustedHops;
  if (idx < 0) return "unknown";
  const ip = parts[idx];
  const v4 = /^(\d{1,3})(\.\d{1,3}){3}$/.test(ip);
  const v6 = /^[0-9a-f:]{2,45}$/i.test(ip) && ip.includes(":");
  return v4 || v6 ? ip.toLowerCase() : "unknown";
}

/** CORS: echo the origin only if it is on the allow-list. */
export function allowedOrigin(origin: string | null, allowList: string): string | null {
  if (!origin) return null;
  const list = allowList.split(",").map((s) => s.trim()).filter(Boolean);
  return list.includes(origin) ? origin : null;
}
