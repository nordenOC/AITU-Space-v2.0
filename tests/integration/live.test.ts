/**
 * Live-stack tests (NOT run in CI by default). They talk to real Edge Functions.
 *
 * Setup:  supabase start && supabase db reset
 *         supabase functions serve --env-file supabase/functions/.env   (see README)
 * Env:    SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY, FUNCTIONS_ORIGIN (allowed origin)
 * Run:    npm run test:integration
 */
import { createClient } from "@supabase/supabase-js";
import { beforeAll, describe, expect, it } from "vitest";

const URL_ = process.env.SUPABASE_URL, ANON = process.env.SUPABASE_ANON_KEY, SVC = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ORIGIN = process.env.FUNCTIONS_ORIGIN ?? "http://localhost:5173";
const live = !!(URL_ && ANON && SVC);
const d = live ? describe : describe.skip;

async function call(fn: string, body: unknown, token?: string) {
  const res = await fetch(`${URL_}/functions/v1/${fn}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: ORIGIN, ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body),
  });
  return { status: res.status, headers: res.headers, json: await res.json().catch(() => null) };
}

d("live Edge Functions", () => {
  const admin = live ? createClient(URL_!, SVC!, { auth: { persistSession: false } }) : (null as never);
  const mk = async (email: string, confirm = true) => {
    const password = crypto.randomUUID();
    const { error } = await admin.auth.admin.createUser({ email, password, email_confirm: confirm });
    if (error) throw error;
    const c = createClient(URL_!, ANON!, { auth: { persistSession: false } });
    const { data, error: e2 } = await c.auth.signInWithPassword({ email, password });
    if (e2) throw e2;
    return { token: data.session!.access_token, id: data.user!.id, client: c };
  };
  let a: Awaited<ReturnType<typeof mk>>, b: Awaited<ReturnType<typeof mk>>;
  const rnd = () => Math.random().toString(36).slice(2, 8);

  beforeAll(async () => {
    a = await mk(`a.${rnd()}@astanait.edu.kz`);
    b = await mk(`b.${rnd()}@astanait.edu.kz`);
  });

  it("rejects unauthenticated requests", async () => {
    expect((await call("bookings-create", { table_id: "A1", slot: 4 })).status).toBe(401);
    expect((await call("bookings-create", { table_id: "A1", slot: 4 }, "garbage")).status).toBe(401);
  });

  it("refuses non-institutional sign-ups and unverified institutional accounts", async () => {
    await expect(mk(`x.${rnd()}@gmail.com`)).rejects.toBeTruthy();
    const u = await mk(`unv.${rnd()}@astanait.edu.kz`, false).catch(() => null);
    if (u) expect((await call("bookings-create", { table_id: "A1", slot: 4 }, u.token)).status).toBe(403);
  });

  it("books, blocks a second active booking, and blocks double-booking", async () => {
    const first = await call("bookings-create", { table_id: "D2", slot: 4 }, a.token);
    expect([200, 409]).toContain(first.status); // 409 SLOT_PAST if run after 17:00 Almaty
    if (first.status !== 200) return;
    expect((await call("bookings-create", { table_id: "D1", slot: 3 }, a.token)).json.error.code).toBe("ACTIVE_BOOKING_EXISTS");
    expect((await call("bookings-create", { table_id: "D2", slot: 4 }, b.token)).json.error.code).toBe("SLOT_TAKEN");
  });

  it("direct table access respects RLS", async () => {
    const { data } = await b.client.from("bookings").select("user_id");
    expect((data ?? []).every((r) => r.user_id === b.id)).toBe(true);
    const upd = await b.client.from("bookings").update({ status: "confirmed" }).eq("user_id", a.id);
    expect(upd.error).toBeTruthy();
    const rpc = await b.client.rpc("create_booking", { p_user: b.id, p_table: "A1", p_slot: 0 });
    expect(rpc.error).toBeTruthy();
  });

  it("QR: issue, confirm once, replay rejected, forged rejected, stranger rejected", async () => {
    const { data: row } = await a.client.from("bookings").select("id,status").in("status", ["held"]).maybeSingle();
    if (!row) return;
    const q = await call("qr-issue", { booking_id: row.id }, a.token);
    expect(q.status).toBe(200);
    const forged = q.json.qr.slice(0, -2) + (q.json.qr.endsWith("AA") ? "BB" : "AA");
    expect((await call("qr-confirm", { qr: forged }, a.token)).status).toBe(400);
    expect((await call("qr-confirm", { qr: q.json.qr }, b.token)).status).toBe(403);
    const results = await Promise.all([1, 2, 3].map(() => call("qr-confirm", { qr: q.json.qr }, a.token)));
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    expect((await call("qr-confirm", { qr: q.json.qr }, a.token)).json.error.code).toBe("QR_USED");
  });

  it("returns 429 with Retry-After under a burst", async () => {
    const burst = await Promise.all(Array.from({ length: 40 }, () => call("bookings-cancel", { booking_id: crypto.randomUUID() }, b.token)));
    const limited = burst.find((r) => r.status === 429);
    expect(limited).toBeTruthy();
    expect(Number(limited!.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
  });

  it("does not grant CORS to unknown origins", async () => {
    const res = await fetch(`${URL_}/functions/v1/bookings-create`, { method: "OPTIONS", headers: { Origin: "https://evil.example" } });
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
  });
});
