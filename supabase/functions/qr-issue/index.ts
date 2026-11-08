import { serve as denoServe } from "https://deno.land/std@0.224.0/http/server.ts";
import { serve, ok, fail } from "../_shared/handler.ts";
import { signQr } from "../_shared/qr.ts";

declare const Deno: { env: { get(k: string): string | undefined } };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// POST { booking_id } -> signed QR (valid 60 s) for the caller's own 'held' booking.
denoServe(serve(async ({ admin, user, body }, cors) => {
  const id = body.booking_id;
  if (typeof id !== "string" || !UUID.test(id)) return fail("INVALID_INPUT", cors);
  const secret = Deno.env.get("QR_HMAC_SECRET");
  if (!secret || secret.length < 32) throw new Error("misconfigured");

  const nonce = crypto.randomUUID();
  const { data, error } = await admin.rpc("qr_issue", { p_user: user.id, p_booking: id, p_nonce: nonce });
  if (error) throw new Error("db");
  if (!data.ok) return fail(data.code, cors);

  const qr = await signQr(secret, id, data.exp, nonce); // signed server-side only
  return ok({ qr, expires_at: new Date(data.exp * 1000).toISOString() }, cors);
}));
