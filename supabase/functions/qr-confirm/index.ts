import { serve as denoServe } from "https://deno.land/std@0.224.0/http/server.ts";
import { serve, ok, fail } from "../_shared/handler.ts";
import { verifyQr } from "../_shared/qr.ts";

declare const Deno: { env: { get(k: string): string | undefined } };

// POST { qr } -> verifies signature + expiry, then consumes the token exactly once
// and marks the booking 'confirmed'. Allowed for the booking owner or app_metadata.role = 'staff'.
denoServe(serve(async ({ admin, user, body, isStaff }, cors) => {
  const secret = Deno.env.get("QR_HMAC_SECRET");
  if (!secret || secret.length < 32) throw new Error("misconfigured");

  const v = await verifyQr(secret, body.qr);
  if (!v.ok) return fail(v.reason === "expired" ? "QR_EXPIRED" : "QR_INVALID", cors);

  const { data, error } = await admin.rpc("qr_consume", {
    p_actor: user.id, p_actor_is_staff: isStaff,
    p_booking: v.parts.bookingId, p_nonce: v.parts.nonce, p_exp: v.parts.exp,
  });
  if (error) throw new Error("db");
  if (!data.ok) {
    const map: Record<string, string> = { INVALID: "QR_INVALID", USED: "QR_USED", EXPIRED: "QR_EXPIRED" };
    return fail(map[data.code] ?? data.code, cors);
  }
  return ok({ booking: data.booking }, cors);
}));
