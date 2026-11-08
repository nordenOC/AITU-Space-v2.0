import { beforeAll, describe, expect, it } from "vitest";
import type { PGlite } from "@electric-sql/pglite";
import { as, jwt, makeDb, OUTSIDER, U1, U2, U3 } from "./harness";

let db: PGlite;
const svc = <T = any>(sql: string, p: unknown[] = []) => as<T>(db, "service_role", null, sql, p);
const book = async (u: string, t: string, s: number) =>
  (await svc(`select public.create_booking($1,$2,$3) r`, [u, t, s]))[0].r;
let n = 0;
const newUser = async () => {
  const id = `aaaaaaaa-0000-4000-8000-${String(++n).padStart(12, "0")}`;
  await db.query(`insert into auth.users(id,email) values ($1,$2)`, [id, `u${n}@astanait.edu.kz`]);
  return id;
};
const resetRl = () => db.exec(`delete from rate_limit_buckets; update rate_limit_state set shield_until=null, traffic_count=0, traffic_window_start=now()`);
const rl = async (user: string | null, ip: string | null) =>
  (await svc(`select * from public.rate_limit_check($1,$2)`, [user, ip]))[0] as { allowed: boolean; retry_after: number };

beforeAll(async () => {
  db = await makeDb();
  // Deterministic slots: use TOMORROW's slots so tests pass at any time of day.
  await db.exec(`create or replace function public.slot_bounds(p_slot int)
    returns table (slot_start timestamptz, slot_end timestamptz) language sql stable set search_path = '' as $$
    select ((now() at time zone 'Asia/Almaty')::date + 1 + make_interval(hours => 12 + p_slot)) at time zone 'Asia/Almaty',
           ((now() at time zone 'Asia/Almaty')::date + 1 + make_interval(hours => 13 + p_slot)) at time zone 'Asia/Almaty' $$;`);
});

describe("email restriction (DB layer)", () => {
  it("rejects non-institutional and look-alike sign-ups", async () => {
    for (const e of ["x@gmail.com", "a@astanait.edu.kz.evil.com", "a@evilastanait.edu.kz", "A@astanait.edu.kz\n@x.com"]) {
      await expect(db.query(`insert into auth.users(email) values ($1)`, [e])).rejects.toThrow(/institutional/i);
    }
  });
  it("accepts a mixed-case institutional address", async () => {
    await db.query(`insert into auth.users(email) values ('  Someone@AstanaIT.edu.kz ')`);
  });
});

describe("bookings", () => {
  it("valid user can book; second active booking is rejected; same slot by another user is rejected", async () => {
    const a = await book(U1, "A1", 0);
    expect(a.ok).toBe(true);
    expect(a.booking.status).toBe("held");
    expect((await book(U1, "B2", 1)).code).toBe("ACTIVE_BOOKING_EXISTS");
    expect((await book(U2, "A1", 0)).code).toBe("SLOT_TAKEN");
    expect((await book(U2, "A1", 1)).ok).toBe(true); // other slot, same table is fine
  });

  it("overlapping requests for one user create exactly one active booking", async () => {
    const u = await newUser();
    const res = await Promise.all(["B1", "B2", "C1", "D1", "D2"].map((t, i) => book(u, t, i)));
    expect(res.filter((r) => r.ok)).toHaveLength(1);
    const { rows } = await db.query(`select count(*)::int c from bookings where user_id=$1 and status in ('held','confirmed')`, [u]);
    expect(rows[0]).toEqual({ c: 1 });
  });

  it("overlapping requests from two users for the same table/slot produce one winner", async () => {
    const [a, b] = [await newUser(), await newUser()];
    const res = await Promise.all([book(a, "D1", 3), book(b, "D1", 3)]);
    expect(res.filter((r) => r.ok)).toHaveLength(1);
    expect(res.find((r) => !r.ok).code).toBe("SLOT_TAKEN");
  });

  it("validates input and past slots", async () => {
    const u = await newUser();
    for (const [t, s] of [["Z9", 0], ["A1", 5], ["A1", -1]] as const) expect((await book(u, t, s)).code).toBe("INVALID_INPUT");
    await db.exec(`create or replace function public.slot_bounds(p_slot int) returns table (slot_start timestamptz, slot_end timestamptz)
      language sql stable set search_path='' as $$ select now()-interval '3 hours', now()-interval '2 hours' $$`);
    expect((await book(u, "A1", 0)).code).toBe("SLOT_PAST");
    await db.exec(`create or replace function public.slot_bounds(p_slot int) returns table (slot_start timestamptz, slot_end timestamptz)
      language sql stable set search_path='' as $$ select ((now() at time zone 'Asia/Almaty')::date + 1 + make_interval(hours => 12 + p_slot)) at time zone 'Asia/Almaty',
      ((now() at time zone 'Asia/Almaty')::date + 1 + make_interval(hours => 13 + p_slot)) at time zone 'Asia/Almaty' $$`);
  });

  it("cancel: only the owner can cancel; slot and user are freed afterwards", async () => {
    const [a, b] = [await newUser(), await newUser()];
    const bk = (await book(a, "C1", 2)).booking;
    expect((await svc(`select public.cancel_booking($1,$2) r`, [b, bk.id]))[0].r.code).toBe("NOT_FOUND");
    expect((await svc(`select public.cancel_booking($1,$2) r`, [a, bk.id]))[0].r.ok).toBe(true);
    expect((await book(b, "C1", 2)).ok).toBe(true);
    expect((await book(a, "D2", 0)).ok).toBe(true);
  });

  it("a stale hold is released lazily and does not block the table or the user", async () => {
    const [a, b] = [await newUser(), await newUser()];
    const bk = (await book(a, "A3", 4)).booking;
    await db.query(`update bookings set hold_expires_at = now() - interval '1 second' where id=$1`, [bk.id]);
    expect((await book(b, "A3", 4)).ok).toBe(true);
    expect((await book(a, "C1", 4)).ok).toBe(true);
    expect((await db.query(`select status from bookings where id=$1`, [bk.id])).rows[0]).toEqual({ status: "expired" });
  });
});

describe("RLS and direct API access", () => {
  it("a user reads only their own bookings", async () => {
    const rows = await as(db, "authenticated", jwt(U1, "one@astanait.edu.kz"), `select user_id from bookings`);
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.every((r: any) => r.user_id === U1)).toBe(true);
  });
  it("direct insert / update / delete on bookings is denied", async () => {
    const c = jwt(U1, "one@astanait.edu.kz");
    await expect(as(db, "authenticated", c, `insert into bookings(user_id,table_id,slot_start,slot_end,hold_expires_at)
      values ('${U1}','D1',now(),now()+interval '1 hour',now())`)).rejects.toThrow(/permission denied/i);
    await expect(as(db, "authenticated", c, `update bookings set status='confirmed'`)).rejects.toThrow(/permission denied/i);
    await expect(as(db, "authenticated", c, `delete from bookings`)).rejects.toThrow(/permission denied/i);
  });
  it("cannot read or modify another user's booking", async () => {
    const other = (await db.query<{ id: string }>(`select id from bookings where user_id=$1 limit 1`, [U1])).rows[0]?.id;
    const c = jwt(U2, "two@astanait.edu.kz");
    expect(await as(db, "authenticated", c, `select id from bookings where id=$1`, [other])).toHaveLength(0);
    await expect(as(db, "authenticated", c, `update bookings set status='cancelled' where id='${other}'`)).rejects.toThrow(/permission denied/i);
  });
  it("a non-institutional JWT sees nothing; anon is denied outright", async () => {
    expect(await as(db, "authenticated", jwt(U1, "one@gmail.com"), `select * from bookings`)).toHaveLength(0);
    expect(await as(db, "authenticated", jwt(U1, "one@gmail.com"), `select * from study_tables`)).toHaveLength(0);
    await expect(as(db, "anon", null, `select * from bookings`)).rejects.toThrow(/permission denied/i);
  });
  it("study_tables are readable (8 tables A1-D2) but read-only", async () => {
    const c = jwt(U1, "one@astanait.edu.kz");
    expect(await as(db, "authenticated", c, `select id from study_tables order by id`)).toHaveLength(8);
    await expect(as(db, "authenticated", c, `update study_tables set seats=6`)).rejects.toThrow(/permission denied/i);
  });
  it("rate-limit and QR tables are not reachable by clients", async () => {
    const c = jwt(U1, "one@astanait.edu.kz");
    for (const t of ["rate_limit_buckets", "rate_limit_state", "qr_tokens"]) {
      await expect(as(db, "authenticated", c, `select * from ${t}`)).rejects.toThrow(/permission denied/i);
      await expect(as(db, "anon", null, `select * from ${t}`)).rejects.toThrow(/permission denied/i);
    }
  });
  it("privileged functions cannot be called by anon/authenticated", async () => {
    const c = jwt(U1, "one@astanait.edu.kz");
    for (const q of [
      `select public.create_booking('${U1}','D2',0)`, `select public.cancel_booking('${U1}', gen_random_uuid())`,
      `select * from public.rate_limit_check(null,'x')`, `select public.cleanup_expired(1)`,
      `select public.qr_issue('${U1}', gen_random_uuid(), gen_random_uuid())`,
      `select public.qr_consume('${U1}', true, gen_random_uuid(), gen_random_uuid(), 1)`,
    ]) {
      await expect(as(db, "authenticated", c, q)).rejects.toThrow(/permission denied/i);
      await expect(as(db, "anon", null, q)).rejects.toThrow(/permission denied/i);
    }
  });
  it("get_availability works for institutional users only", async () => {
    await as(db, "authenticated", jwt(U1, "one@astanait.edu.kz"), `select * from public.get_availability()`);
    await expect(as(db, "authenticated", jwt(U1, "one@gmail.com"), `select * from public.get_availability()`)).rejects.toThrow(/not allowed/);
    await expect(as(db, "anon", null, `select * from public.get_availability()`)).rejects.toThrow(/permission denied/i);
  });
});

describe("rate limiter", () => {
  it("per-IP bucket allows its capacity (60) then denies with retry_after", async () => {
    await resetRl();
    const ip = "ip-cap";
    let allowed = 0;
    for (let i = 0; i < 70; i++) if ((await rl(null, ip)).allowed) allowed++;
    expect(allowed).toBeGreaterThanOrEqual(60);
    expect(allowed).toBeLessThanOrEqual(61); // + tokens refilled while the loop ran
    const denied = await rl(null, ip);
    expect(denied.allowed).toBe(false);
    expect(denied.retry_after).toBeGreaterThanOrEqual(1);
  });

  it("per-user bucket holds under concurrent requests (cap 10)", async () => {
    await resetRl();
    const res = await Promise.all(Array.from({ length: 60 }, () => rl(U1, null)));
    const ok = res.filter((r) => r.allowed).length;
    expect(ok).toBeGreaterThanOrEqual(10);
    expect(ok).toBeLessThanOrEqual(11);
  });

  it("5 violations ban the identity for 10 minutes, then the ban expires", async () => {
    await resetRl();
    for (let i = 0; i < 10; i++) await rl(U2, null); // drain
    let last = await rl(U2, null);
    for (let i = 0; i < 6 && last.retry_after < 600; i++) last = await rl(U2, null);
    expect(last.allowed).toBe(false);
    expect(last.retry_after).toBe(600);
    const row = (await db.query<{ s: number }>(`select extract(epoch from banned_until-now())::int s from rate_limit_buckets where key=$1`, ["user:" + U2])).rows[0];
    expect(row.s).toBeGreaterThan(590);
    expect(row.s).toBeLessThanOrEqual(600);
    // still blocked even though tokens would have refilled
    await db.query(`update rate_limit_buckets set updated_at = now() - interval '5 minutes' where key=$1`, ["user:" + U2]);
    expect((await rl(U2, null)).allowed).toBe(false);
    // ban over
    await db.query(`update rate_limit_buckets set banned_until = now() - interval '1 second' where key=$1`, ["user:" + U2]);
    expect((await rl(U2, null)).allowed).toBe(true);
  });

  it("shield mode: 3-token allowance, 1 token/s refill, ~5 s window", async () => {
    await resetRl();
    await db.query(`update rate_limit_state set shield_until = now() + interval '5 seconds' where id=1`);
    const ip = "ip-shield";
    const first = [await rl(null, ip), await rl(null, ip), await rl(null, ip), await rl(null, ip)];
    expect(first.map((r) => r.allowed)).toEqual([true, true, true, false]);
    expect(first[3].retry_after).toBe(1);
    // 2.5 s later two more tokens exist (1 token/s), not 60
    await db.query(`update rate_limit_buckets set updated_at = now() - interval '2500 milliseconds' where key=$1`, ["ip:" + ip]);
    expect([await rl(null, ip), await rl(null, ip), await rl(null, ip)].map((r) => r.allowed)).toEqual([true, true, false]);
    // user scope is clamped too
    expect([await rl(U3, null), await rl(U3, null), await rl(U3, null), await rl(U3, null)].map((r) => r.allowed)).toEqual([true, true, true, false]);
    // after the window the normal limits are back
    await db.query(`update rate_limit_state set shield_until = now() - interval '1 second' where id=1`);
    await db.query(`delete from rate_limit_buckets where key = $1`, ["ip:ip-normal"]);
    let ok = 0;
    for (let i = 0; i < 20; i++) if ((await rl(null, "ip-normal")).allowed) ok++;
    expect(ok).toBe(20);
  });

  it("a traffic spike (>150 req/s) arms shield mode for about 5 seconds", async () => {
    await resetRl();
    await db.query(`update rate_limit_state set traffic_count = 150, traffic_window_start = now() where id=1`);
    await rl(null, "ip-spike");
    const s = (await db.query<{ s: number }>(`select extract(epoch from shield_until-now())::float8 s from rate_limit_state`)).rows[0].s;
    expect(s).toBeGreaterThan(4);
    expect(s).toBeLessThanOrEqual(5);
  });
});

describe("QR tokens", () => {
  beforeAll(async () => { await db.exec('delete from bookings'); });
  const issue = async (u: string, booking: string) => {
    const nonce = (await db.query<{ n: string }>(`select gen_random_uuid() n`)).rows[0].n;
    const r = (await svc(`select public.qr_issue($1,$2,$3) r`, [u, booking, nonce]))[0].r;
    return { r, nonce, exp: r.exp as number };
  };
  const consume = async (actor: string, staff: boolean, booking: string, nonce: string, exp: number) =>
    (await svc(`select public.qr_consume($1,$2,$3,$4,$5) r`, [actor, staff, booking, nonce, exp]))[0].r;
  const heldFor = async (slot: number, table = "B1") => {
    const u = await newUser();
    const bk = (await book(u, table, slot)).booking;
    return { u, id: bk.id as string };
  };

  it("valid QR confirms the booking once; replay is rejected", async () => {
    const { u, id } = await heldFor(0);
    const q = await issue(u, id);
    expect(q.r.ok).toBe(true);
    expect(q.exp * 1000 - Date.now()).toBeLessThanOrEqual(60_000);
    const first = await consume(u, false, id, q.nonce, q.exp);
    expect(first.ok).toBe(true);
    expect((await db.query(`select status from bookings where id=$1`, [id])).rows[0]).toEqual({ status: "confirmed" });
    expect((await consume(u, false, id, q.nonce, q.exp)).code).toBe("USED");
  });

  it("two simultaneous scans of one QR: exactly one succeeds", async () => {
    const { u, id } = await heldFor(1);
    const q = await issue(u, id);
    const res = await Promise.all(Array.from({ length: 6 }, () => consume(u, false, id, q.nonce, q.exp)));
    expect(res.filter((r) => r.ok)).toHaveLength(1);
    expect(res.filter((r) => !r.ok).every((r) => r.code === "USED")).toBe(true);
  });

  it("expired QR is rejected", async () => {
    const { u, id } = await heldFor(2);
    const q = await issue(u, id);
    await db.query(`update qr_tokens set expires_at = date_trunc('second', now() - interval '5 seconds') where nonce=$1`, [q.nonce]);
    const exp = (await db.query<{ e: number }>(`select extract(epoch from expires_at)::bigint e from qr_tokens where nonce=$1`, [q.nonce])).rows[0].e;
    expect((await consume(u, false, id, q.nonce, Number(exp))).code).toBe("EXPIRED");
  });

  it("altered exp / nonce / booking is rejected", async () => {
    const { u, id } = await heldFor(3);
    const other = await heldFor(3, "C1");
    const q = await issue(u, id);
    expect((await consume(u, false, id, q.nonce, q.exp + 600)).code).toBe("INVALID");
    expect((await consume(u, false, id, "00000000-0000-4000-8000-000000000000", q.exp)).code).toBe("INVALID");
    expect((await consume(other.u, false, other.id, q.nonce, q.exp)).code).toBe("INVALID");
    expect((await db.query(`select status from bookings where id=$1`, [id])).rows[0]).toEqual({ status: "held" });
  });

  it("another user cannot confirm (and cannot burn the QR); staff can", async () => {
    const { u, id } = await heldFor(4);
    const stranger = await newUser();
    const q = await issue(u, id);
    expect((await consume(stranger, false, id, q.nonce, q.exp)).code).toBe("FORBIDDEN");
    expect((await db.query(`select consumed_at from qr_tokens where nonce=$1`, [q.nonce])).rows[0]).toEqual({ consumed_at: null });
    expect((await consume(stranger, true, id, q.nonce, q.exp)).ok).toBe(true); // staff workflow
  });

  it("QR can only be issued to the owner of an eligible (held) booking", async () => {
    const { u, id } = await heldFor(0, "D1");
    const stranger = await newUser();
    expect((await issue(stranger, id)).r.code).toBe("NOT_ELIGIBLE");
    await svc(`select public.cancel_booking($1,$2)`, [u, id]);
    expect((await issue(u, id)).r.code).toBe("NOT_ELIGIBLE");
  });

  it("issuing a new QR supersedes the previous one; cancelling kills outstanding QRs", async () => {
    const { u, id } = await heldFor(1, "D1");
    const q1 = await issue(u, id);
    const q2 = await issue(u, id);
    expect((await consume(u, false, id, q1.nonce, q1.exp)).ok).toBe(false);
    await svc(`select public.cancel_booking($1,$2)`, [u, id]);
    expect((await consume(u, false, id, q2.nonce, q2.exp)).ok).toBe(false);
  });
});

describe("cleanup", () => {
  it("removes only eligible records, never bookings, and is idempotent", async () => {
    await resetRl();
    const [a, b, c, d] = [await newUser(), await newUser(), await newUser(), await newUser()];
    await db.exec(`
      insert into rate_limit_buckets(key,tokens,updated_at) values ('old-idle',1,now()-interval '2 hours'), ('fresh',1,now());
      insert into rate_limit_buckets(key,tokens,updated_at,banned_until) values ('old-banned',0,now()-interval '2 hours', now()+interval '5 minutes');`);
    const bks = await db.query<{ id: string }>(`
      insert into bookings(user_id,table_id,slot_start,slot_end,status,hold_expires_at) values
        ('${a}','A1',now()-interval '5 hours',now()-interval '4 hours','held',now()-interval '4 hours'),
        ('${b}','A2',now()-interval '5 hours',now()-interval '4 hours','confirmed',now()-interval '4 hours'),
        ('${c}','B1',now()+interval '30 days',now()+interval '30 days 1 hour','held',now()+interval '5 minutes'),
        ('${d}','B2',now()-interval '9 hours',now()-interval '8 hours','cancelled',now()-interval '8 hours') returning id`);
    const [hStale, , hLive] = bks.rows.map((r) => r.id);
    await db.query(`insert into qr_tokens(nonce,booking_id,issued_to,expires_at,consumed_at) values
      (gen_random_uuid(),$1,$2,now()-interval '2 hours',null),
      (gen_random_uuid(),$3,$2,now()+interval '1 minute',null),
      (gen_random_uuid(),$3,$2,now()-interval '8 days',now()-interval '8 days'),
      (gen_random_uuid(),$3,$2,now()-interval '1 day',now()-interval '1 day')`, [hStale, c, hLive]);

    const before = (await db.query(`select count(*)::int n from bookings`)).rows[0] as { n: number };
    const r1 = (await svc(`select public.cleanup_expired(1000) r`))[0].r;
    expect(r1.rate_limit_buckets_deleted).toBe(1);               // only 'old-idle'
    expect(r1.qr_tokens_deleted).toBe(2);                        // expired-unconsumed (2h) + consumed (8d)
    expect(r1.holds_expired).toBeGreaterThanOrEqual(1);
    expect(r1.bookings_completed).toBeGreaterThanOrEqual(1);
    const keys = (await db.query<{ key: string }>(`select key from rate_limit_buckets`)).rows.map((x) => x.key);
    expect(keys).toEqual(expect.arrayContaining(["fresh", "old-banned"]));
    expect(keys).not.toContain("old-idle");
    expect((await db.query(`select count(*)::int n from qr_tokens where booking_id=$1`, [hLive])).rows[0]).toEqual({ n: 2 });
    expect((await db.query(`select count(*)::int n from bookings`)).rows[0]).toEqual(before); // nothing deleted
    expect((await db.query(`select status from bookings where id=$1`, [hLive])).rows[0]).toEqual({ status: "held" });
    expect((await db.query(`select status from bookings where id=$1`, [hStale])).rows[0]).toEqual({ status: "expired" });

    const r2 = (await svc(`select public.cleanup_expired(1000) r`))[0].r;
    expect(r2).toEqual({ rate_limit_buckets_deleted: 0, qr_tokens_deleted: 0, holds_expired: 0, bookings_completed: 0 });
  });

  it("respects the batch size", async () => {
    await db.exec(`insert into rate_limit_buckets(key,tokens,updated_at) select 'bulk'||g,1,now()-interval '3 hours' from generate_series(1,5) g`);
    const r = (await svc(`select public.cleanup_expired(2) r`))[0].r;
    expect(r.rate_limit_buckets_deleted).toBe(2);
  });
});

void OUTSIDER;

