// Common request pipeline for every protected Edge Function.
//
//  1. CORS (explicit allow-list from ALLOWED_ORIGINS, never "*")
//  2. POST only, small JSON body
//  3. Rate limit by hashed client IP + global bucket  (BEFORE any auth/DB work)
//  4. Verify the Supabase JWT with the Auth server; identity comes ONLY from it
//  5. Require a verified @astanait.edu.kz email
//  6. Rate limit by user id
//  7. Run the operation; errors are mapped to safe, generic messages
//
// Functions are deployed with verify_jwt = false (see supabase/config.toml) so that
// step 3 also covers unauthenticated traffic; step 4 does the real verification.
import { createClient, type SupabaseClient, type User } from "npm:@supabase/supabase-js@2";
import { allowedOrigin, isInstitutionalEmail, pickClientIp } from "./pure.ts";

declare const Deno: { env: { get(k: string): string | undefined } };

export type Ctx = {
  admin: SupabaseClient;
  user: User;
  body: Record<string, unknown>;
  isStaff: boolean;
};

const SAFE_MESSAGES: Record<string, string> = {
  UNAUTHENTICATED: "Please sign in again.",
  NOT_INSTITUTIONAL: "Only @astanait.edu.kz accounts can use AITU Space.",
  RATE_LIMITED: "Too many requests. Please wait a moment and try again.",
  INVALID_INPUT: "That request was not valid.",
  ACTIVE_BOOKING_EXISTS: "You already have an active booking. Cancel it before booking another table.",
  SLOT_TAKEN: "That table is already booked for this time. Please pick another slot.",
  SLOT_PAST: "That time slot has already ended.",
  NOT_FOUND: "Booking not found.",
  NOT_ELIGIBLE: "This booking can no longer be confirmed.",
  QR_INVALID: "This code is not valid.",
  QR_EXPIRED: "This code has expired. A new one will be shown.",
  QR_USED: "This code was already used.",
  FORBIDDEN: "You are not allowed to do that.",
  SERVER_ERROR: "Something went wrong. Please try again.",
};

const STATUS: Record<string, number> = {
  UNAUTHENTICATED: 401, NOT_INSTITUTIONAL: 403, FORBIDDEN: 403, RATE_LIMITED: 429,
  INVALID_INPUT: 400, ACTIVE_BOOKING_EXISTS: 409, SLOT_TAKEN: 409, SLOT_PAST: 409,
  NOT_FOUND: 404, NOT_ELIGIBLE: 409, QR_INVALID: 400, QR_EXPIRED: 410, QR_USED: 409,
  SERVER_ERROR: 500,
};

export class ApiError extends Error {
  constructor(public code: string, public retryAfter?: number) { super(code); }
}

function json(status: number, body: unknown, headers: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status, headers: { ...headers, "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

export function fail(code: string, headers: Record<string, string>, retryAfter?: number): Response {
  const h = { ...headers };
  if (code === "RATE_LIMITED") h["Retry-After"] = String(Math.max(1, retryAfter ?? 1));
  return json(STATUS[code] ?? 500, { error: { code, message: SAFE_MESSAGES[code] ?? SAFE_MESSAGES.SERVER_ERROR } }, h);
}

export function ok(data: unknown, headers: Record<string, string>): Response {
  return json(200, data, headers);
}

async function hashIp(ip: string, salt: string): Promise<string> {
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(salt), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(ip)));
  return Array.from(sig.slice(0, 16), (b) => b.toString(16).padStart(2, "0")).join("");
}

export function serve(run: (ctx: Ctx, headers: Record<string, string>) => Promise<Response>) {
  return async (req: Request): Promise<Response> => {
    const origin = allowedOrigin(req.headers.get("origin"), Deno.env.get("ALLOWED_ORIGINS") ?? "");
    const cors: Record<string, string> = {
      "Vary": "Origin",
      "Access-Control-Allow-Headers": "authorization, content-type, apikey",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Max-Age": "600",
    };
    if (origin) cors["Access-Control-Allow-Origin"] = origin;

    // A browser request from an origin that is not allow-listed gets no CORS grant.
    if (req.headers.get("origin") && !origin) return fail("FORBIDDEN", cors);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (req.method !== "POST") return fail("INVALID_INPUT", cors);

    try {
      const url = Deno.env.get("SUPABASE_URL")!;
      const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
      const salt = Deno.env.get("IP_HASH_SALT");
      if (!url || !serviceKey || !salt) throw new Error("misconfigured");
      const admin = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });

      // 3. IP + global limits, before anything expensive. Fails CLOSED.
      const hops = Number(Deno.env.get("TRUSTED_PROXY_HOPS") ?? "1");
      const ip = await hashIp(pickClientIp(req.headers.get("x-forwarded-for"), hops), salt);
      const pre = await admin.rpc("rate_limit_check", { p_user: null, p_ip: ip });
      if (pre.error || !pre.data?.[0]) throw new Error("rate limiter unavailable");
      if (!pre.data[0].allowed) return fail("RATE_LIMITED", cors, pre.data[0].retry_after);

      // 4. JWT -> identity (never trust ids/emails from the body)
      const m = /^Bearer ([A-Za-z0-9._-]+)$/.exec(req.headers.get("authorization") ?? "");
      if (!m) return fail("UNAUTHENTICATED", cors);
      const { data, error } = await admin.auth.getUser(m[1]);
      if (error || !data.user) return fail("UNAUTHENTICATED", cors);
      const user = data.user;

      // 5. institutional + verified email
      if (!user.email_confirmed_at || !isInstitutionalEmail(user.email)) return fail("NOT_INSTITUTIONAL", cors);

      // 6. per-user limit
      const post = await admin.rpc("rate_limit_check", { p_user: user.id, p_ip: null });
      if (post.error || !post.data?.[0]) throw new Error("rate limiter unavailable");
      if (!post.data[0].allowed) return fail("RATE_LIMITED", cors, post.data[0].retry_after);

      // body
      const text = await req.text();
      if (text.length > 2048) return fail("INVALID_INPUT", cors);
      let body: Record<string, unknown> = {};
      if (text) {
        try {
          const parsed = JSON.parse(text);
          if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return fail("INVALID_INPUT", cors);
          body = parsed;
        } catch { return fail("INVALID_INPUT", cors); }
      }

      // app_metadata can only be set server-side, so it is safe to read a role from it.
      const isStaff = user.app_metadata?.role === "staff";
      return await run({ admin, user, body, isStaff }, cors);
    } catch (e) {
      if (e instanceof ApiError) return fail(e.code, cors, e.retryAfter);
      console.error("function error", e instanceof Error ? e.message : "unknown"); // never log payloads
      return fail("SERVER_ERROR", cors);
    }
  };
}
