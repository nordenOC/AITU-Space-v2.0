import { serve as denoServe } from "https://deno.land/std@0.224.0/http/server.ts";
import { serve, ok, fail } from "../_shared/handler.ts";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// POST { booking_id } -> cancels the caller's own active booking.
denoServe(serve(async ({ admin, user, body }, cors) => {
  const id = body.booking_id;
  if (typeof id !== "string" || !UUID.test(id)) return fail("INVALID_INPUT", cors);
  const { data, error } = await admin.rpc("cancel_booking", { p_user: user.id, p_booking: id });
  if (error) throw new Error("db");
  if (!data.ok) return fail(data.code, cors);
  return ok({ ok: true }, cors);
}));
