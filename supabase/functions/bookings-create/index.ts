import { serve as denoServe } from "https://deno.land/std@0.224.0/http/server.ts";
import { serve, ok, fail } from "../_shared/handler.ts";

// POST { table_id: "A1", slot: 0..4 } -> creates a 'held' booking for the JWT's user.
denoServe(serve(async ({ admin, user, body }, cors) => {
  const table = body.table_id, slot = body.slot;
  if (typeof table !== "string" || !/^[A-D][1-9]$/.test(table) || !Number.isInteger(slot)) {
    return fail("INVALID_INPUT", cors);
  }
  const { data, error } = await admin.rpc("create_booking", { p_user: user.id, p_table: table, p_slot: slot });
  if (error) throw new Error("db");
  if (!data.ok) return fail(data.code, cors);
  return ok({ booking: data.booking }, cors);
}));
