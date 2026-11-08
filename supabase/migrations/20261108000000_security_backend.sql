-- =====================================================================
-- AITU Space: secure booking backend
-- Tables, constraints, RLS, rate limiter, QR token state, cleanup.
--
-- Security model in one paragraph
--   * Browsers talk to Edge Functions (JWT verified there) and may only READ
--     their own bookings + static table data through RLS.
--   * Every write goes through SECURITY DEFINER functions that are executable
--     ONLY by service_role (i.e. only from Edge Functions). anon/authenticated
--     cannot call them through PostgREST /rpc.
--   * Concurrency safety comes from the database itself: a partial unique
--     index (one active booking per user), an exclusion constraint (no
--     overlapping bookings on one table), row locks (rate limiter, QR use).
-- =====================================================================

create extension if not exists btree_gist with schema extensions;

-- ---------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------

-- True when the caller's JWT carries an @astanait.edu.kz address.
-- Used by RLS policies as defence in depth; Edge Functions enforce it too
-- (and additionally require a verified email).
create or replace function public.is_institutional()
returns boolean
language sql
stable
set search_path = ''
as $$
  select lower(btrim(coalesce(auth.jwt() ->> 'email', ''))) ~ '^[a-z0-9._%+-]+@astanait\.edu\.kz$'
$$;

-- Block sign-ups / email changes to non-institutional addresses at the source.
create or replace function public.enforce_institutional_email()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if lower(btrim(coalesce(new.email, ''))) !~ '^[a-z0-9._%+-]+@astanait\.edu\.kz$' then
    raise exception 'Only institutional accounts are allowed' using errcode = 'P0001';
  end if;
  return new;
end $$;

drop trigger if exists enforce_institutional_email on auth.users;
create trigger enforce_institutional_email
  before insert or update of email on auth.users
  for each row execute function public.enforce_institutional_email();

-- ---------------------------------------------------------------------
-- study_tables: static floor-plan data (A1..D2)
-- RLS ON; authenticated institutional users may read, nobody may write.
-- ---------------------------------------------------------------------
create table if not exists public.study_tables (
  id          text primary key check (id ~ '^[A-D][1-9]$'),
  seats       int  not null check (seats in (2, 4, 6)),
  power       text not null check (power in ('active', 'faulty', 'none')),
  near_window boolean not null,
  power_note  text,
  plan_x      text not null,
  plan_y      text not null
);
alter table public.study_tables enable row level security;

insert into public.study_tables (id, seats, power, near_window, power_note, plan_x, plan_y) values
  ('A1', 2, 'active', true,  'today, 09:10',        '9%',  '12%'),
  ('A2', 4, 'active', true,  'today, 09:10',        '39%', '15%'),
  ('A3', 2, 'faulty', true,  'reported 2 days ago', '75%', '12%'),
  ('B1', 4, 'none',   false, null,                  '10%', '43%'),
  ('B2', 4, 'active', false, 'today, 09:12',        '66%', '40%'),
  ('C1', 4, 'none',   false, null,                  '38%', '68%'),
  ('D1', 6, 'active', false, 'today, 09:12',        '6%',  '74%'),
  ('D2', 2, 'active', false, 'today, 09:15',        '76%', '72%')
on conflict (id) do nothing;

drop policy if exists study_tables_read on public.study_tables;
create policy study_tables_read on public.study_tables
  for select to authenticated using (public.is_institutional());

-- ---------------------------------------------------------------------
-- bookings
-- status: held       reserved, waiting for QR confirmation (10 min hold)
--         confirmed  QR consumed, student is at the table
--         cancelled | expired | completed   (terminal, kept for audit)
-- "Active" = held or confirmed.
-- ---------------------------------------------------------------------
create table if not exists public.bookings (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid not null references auth.users (id) on delete cascade,
  table_id        text not null references public.study_tables (id),
  slot_start      timestamptz not null,
  slot_end        timestamptz not null,
  status          text not null default 'held'
                  check (status in ('held', 'confirmed', 'cancelled', 'expired', 'completed')),
  hold_expires_at timestamptz not null,
  created_at      timestamptz not null default now(),
  confirmed_at    timestamptz,
  cancelled_at    timestamptz,
  check (slot_end > slot_start)
);
alter table public.bookings enable row level security;

-- Rule: at most ONE active booking per user (race-proof: enforced by the index).
create unique index if not exists bookings_one_active_per_user
  on public.bookings (user_id) where status in ('held', 'confirmed');

-- Rule: no two active bookings may overlap on the same table.
alter table public.bookings drop constraint if exists bookings_no_overlap;
alter table public.bookings add constraint bookings_no_overlap
  exclude using gist (table_id with =, tstzrange(slot_start, slot_end) with &&)
  where (status in ('held', 'confirmed'));

create index if not exists bookings_user_idx on public.bookings (user_id, created_at desc);
create index if not exists bookings_hold_idx on public.bookings (hold_expires_at) where status = 'held';
create index if not exists bookings_slot_end_idx on public.bookings (slot_end) where status = 'confirmed';

-- Users may only READ their own rows. No insert/update/delete policy exists,
-- so those operations are denied for anon/authenticated (and not granted).
drop policy if exists bookings_select_own on public.bookings;
create policy bookings_select_own on public.bookings
  for select to authenticated
  using (user_id = (select auth.uid()) and public.is_institutional());

-- ---------------------------------------------------------------------
-- Rate limiter state (RLS ON, no policies, no grants => service_role only)
-- ---------------------------------------------------------------------
create table if not exists public.rate_limit_buckets (
  key                 text primary key,           -- 'global' | 'ip:<hash>' | 'user:<uuid>'
  tokens              double precision not null,
  updated_at          timestamptz not null default now(),
  strikes             int not null default 0,     -- violations inside the strike window
  strike_window_start timestamptz,
  banned_until        timestamptz
);
create index if not exists rate_limit_buckets_updated_idx on public.rate_limit_buckets (updated_at);
alter table public.rate_limit_buckets enable row level security;

-- Single row holding traffic counter + shield-mode expiry.
create table if not exists public.rate_limit_state (
  id                   int primary key check (id = 1),
  shield_until         timestamptz,
  traffic_window_start timestamptz not null default now(),
  traffic_count        int not null default 0
);
insert into public.rate_limit_state (id) values (1) on conflict do nothing;
alter table public.rate_limit_state enable row level security;

-- ---------------------------------------------------------------------
-- QR token state (RLS ON, no policies, no grants => service_role only)
-- One row per issued QR. Consumption is a locked UPDATE => single use.
-- The HMAC secret is NEVER stored here (Edge Function secret only).
-- ---------------------------------------------------------------------
create table if not exists public.qr_tokens (
  nonce       uuid primary key,
  booking_id  uuid not null references public.bookings (id) on delete cascade,
  issued_to   uuid not null,
  expires_at  timestamptz not null,
  consumed_at timestamptz,
  consumed_by uuid,
  created_at  timestamptz not null default now()
);
create index if not exists qr_tokens_booking_idx on public.qr_tokens (booking_id);
create index if not exists qr_tokens_expires_idx on public.qr_tokens (expires_at);
alter table public.qr_tokens enable row level security;

-- =====================================================================
-- RATE LIMITER
--
-- Algorithm: token bucket per key. A bucket holds up to `cap` tokens and
-- refills `rate` tokens/second (computed lazily from elapsed time). One
-- request costs 1 token. The bucket row is locked with SELECT ... FOR UPDATE,
-- so concurrent requests on the same key are serialised and cannot both
-- spend the same token.
--
-- Scopes / limits (chosen for a campus app; many students share one NAT IP):
--   global  cap 300, 100 tokens/s   application-wide protection
--   ip      cap  60,   5 tokens/s   per hashed client IP
--   user    cap  10, 0.5 tokens/s   per authenticated user (about 30 req/min sustained)
--
-- Penalty: every denied request is a violation. 5 violations within a
-- 60-second window ban that key (ip or user) for 10 minutes (banned_until).
--
-- Shield mode: triggered when more than 150 requests arrive within one
-- second, or when the global bucket is exhausted. It lasts 5 seconds from
-- the LAST trigger (re-triggering extends it). While active, ip and user
-- buckets are clamped to cap 3 and refill 1 token/s: a bucket holding more
-- than 3 tokens is cut to 3, and then regains 1 token per second. So after a
-- burst of 3 requests, one more is allowed per second until the window ends;
-- afterwards the normal cap/rate apply again (starting from the clamped level).
-- =====================================================================

create or replace function public.rl_take(
  p_key text, p_cap double precision, p_rate double precision, p_shield boolean
) returns int
language plpgsql
security definer
set search_path = ''
as $$
declare
  r         public.rate_limit_buckets;
  v_now     timestamptz := clock_timestamp();
  v_cap     double precision := case when p_shield then least(p_cap, 3) else p_cap end;
  v_rate    double precision := case when p_shield then least(p_rate, 1) else p_rate end;
  v_tokens  double precision;
  v_reset   boolean;
  v_strikes int;
begin
  insert into public.rate_limit_buckets (key, tokens, updated_at)
  values (p_key, p_cap, v_now)
  on conflict (key) do nothing;

  select * into r from public.rate_limit_buckets where key = p_key for update;

  -- Active ban: reject without touching anything else.
  if r.banned_until is not null and r.banned_until > v_now then
    return greatest(1, ceil(extract(epoch from r.banned_until - v_now))::int);
  end if;

  v_tokens := least(v_cap,
                    least(r.tokens, v_cap)
                    + greatest(0, extract(epoch from v_now - r.updated_at)) * v_rate);

  if v_tokens >= 1 then
    update public.rate_limit_buckets
       set tokens = v_tokens - 1, updated_at = v_now, banned_until = null
     where key = p_key;
    return 0;
  end if;

  -- Violation
  v_reset := r.strike_window_start is null or r.strike_window_start < v_now - interval '60 seconds';
  v_strikes := case when v_reset then 1 else r.strikes + 1 end;

  if v_strikes >= 5 then
    update public.rate_limit_buckets
       set tokens = v_tokens, updated_at = v_now, strikes = 0, strike_window_start = null,
           banned_until = v_now + interval '10 minutes'
     where key = p_key;
    return 600;
  end if;

  update public.rate_limit_buckets
     set tokens = v_tokens, updated_at = v_now, strikes = v_strikes,
         strike_window_start = case when v_reset then v_now else r.strike_window_start end
   where key = p_key;
  return greatest(1, ceil((1 - v_tokens) / v_rate)::int);
end $$;

-- Entry point used by Edge Functions.
--   Pre-auth stage : rate_limit_check(null, '<ip hash>')  -> counts traffic, checks global + ip
--   Post-auth stage: rate_limit_check('<uuid>', null)     -> checks user bucket only
-- Returns allowed + retry_after (seconds). No other internal state is revealed.
create or replace function public.rate_limit_check(p_user uuid, p_ip text)
returns table (allowed boolean, retry_after int)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now    timestamptz := clock_timestamp();
  v_shield boolean := false;
  v_count  int;
  v_until  timestamptz;
  v_wait   int := 0;
  v_one    int;
begin
  if p_ip is not null then
    -- Traffic counter (one-second window) drives shield mode.
    update public.rate_limit_state s
       set traffic_count = case when v_now - s.traffic_window_start >= interval '1 second'
                                then 1 else s.traffic_count + 1 end,
           traffic_window_start = case when v_now - s.traffic_window_start >= interval '1 second'
                                       then v_now else s.traffic_window_start end
     where s.id = 1
    returning s.traffic_count, s.shield_until into v_count, v_until;

    if v_count > 150 then
      v_until := v_now + interval '5 seconds';
      update public.rate_limit_state set shield_until = v_until where id = 1;
    end if;
    v_shield := v_until is not null and v_until > v_now;

    v_one := public.rl_take('global', 300, 100, false);
    if v_one > 0 then
      -- Global exhaustion also arms shield mode for the next 5 seconds.
      update public.rate_limit_state set shield_until = v_now + interval '5 seconds' where id = 1;
      v_wait := greatest(v_wait, v_one);
    end if;

    v_one := public.rl_take('ip:' || p_ip, 60, 5, v_shield);
    v_wait := greatest(v_wait, v_one);
  end if;

  if p_user is not null then
    select coalesce(s.shield_until > v_now, false) into v_shield
      from public.rate_limit_state s where s.id = 1;
    v_one := public.rl_take('user:' || p_user::text, 10, 0.5, coalesce(v_shield, false));
    v_wait := greatest(v_wait, v_one);
  end if;

  return query select v_wait = 0, v_wait;
end $$;

-- =====================================================================
-- BOOKING FUNCTIONS (service_role only)
-- Slots: five one-hour slots 12:00-17:00 today, Asia/Almaty (index 0..4).
-- =====================================================================

create or replace function public.slot_bounds(p_slot int)
returns table (slot_start timestamptz, slot_end timestamptz)
language sql
stable
set search_path = ''
as $$
  select ((now() at time zone 'Asia/Almaty')::date + make_interval(hours => 12 + p_slot)) at time zone 'Asia/Almaty',
         ((now() at time zone 'Asia/Almaty')::date + make_interval(hours => 13 + p_slot)) at time zone 'Asia/Almaty'
$$;

create or replace function public.create_booking(p_user uuid, p_table text, p_slot int)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_start timestamptz;
  v_end   timestamptz;
  v_id    uuid;
  v_hold  timestamptz;
  v_con   text;
begin
  if p_user is null then
    return jsonb_build_object('ok', false, 'code', 'UNAUTHENTICATED');
  end if;
  if p_slot is null or p_slot < 0 or p_slot > 4 or p_table is null
     or not exists (select 1 from public.study_tables where id = p_table) then
    return jsonb_build_object('ok', false, 'code', 'INVALID_INPUT');
  end if;

  select b.slot_start, b.slot_end into v_start, v_end from public.slot_bounds(p_slot) b;
  if v_end <= now() then
    return jsonb_build_object('ok', false, 'code', 'SLOT_PAST');
  end if;

  -- Release stale holds / finished bookings that would otherwise block this request.
  update public.bookings set status = 'expired'
   where status = 'held' and hold_expires_at <= now() and (user_id = p_user or table_id = p_table);
  update public.bookings set status = 'completed'
   where status = 'confirmed' and slot_end <= now() and user_id = p_user;

  v_hold := least(now() + interval '10 minutes', v_end);

  insert into public.bookings (user_id, table_id, slot_start, slot_end, hold_expires_at)
  values (p_user, p_table, v_start, v_end, v_hold)
  returning id into v_id;

  return jsonb_build_object('ok', true, 'booking', jsonb_build_object(
    'id', v_id, 'table_id', p_table, 'slot_index', p_slot, 'slot_start', v_start,
    'slot_end', v_end, 'status', 'held', 'hold_expires_at', v_hold));
exception
  when unique_violation or exclusion_violation then
    get stacked diagnostics v_con = constraint_name;
    if v_con = 'bookings_one_active_per_user' then
      return jsonb_build_object('ok', false, 'code', 'ACTIVE_BOOKING_EXISTS');
    end if;
    return jsonb_build_object('ok', false, 'code', 'SLOT_TAKEN');
end $$;

create or replace function public.cancel_booking(p_user uuid, p_booking uuid)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare v_id uuid;
begin
  update public.bookings
     set status = 'cancelled', cancelled_at = now()
   where id = p_booking and user_id = p_user and status in ('held', 'confirmed')
  returning id into v_id;
  if v_id is null then
    return jsonb_build_object('ok', false, 'code', 'NOT_FOUND');
  end if;
  -- Kill any outstanding QR for this booking.
  update public.qr_tokens set expires_at = least(expires_at, now())
   where booking_id = v_id and consumed_at is null;
  return jsonb_build_object('ok', true);
end $$;

-- Slot occupancy for today (no user identifiers). Requires an institutional JWT.
-- Granted to `authenticated`; read-only.
create or replace function public.get_availability()
returns table (table_id text, slot_index int)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null or not public.is_institutional() then
    raise exception 'not allowed' using errcode = '42501';
  end if;
  return query
    select b.table_id,
           (extract(hour from b.slot_start at time zone 'Asia/Almaty'))::int - 12
      from public.bookings b
     where b.slot_end > now()
       and b.slot_start < ((now() at time zone 'Asia/Almaty')::date + 1) at time zone 'Asia/Almaty'
       and (b.status = 'confirmed' or (b.status = 'held' and b.hold_expires_at > now()));
end $$;

-- =====================================================================
-- QR FUNCTIONS (service_role only)
-- Token = bookingId.exp.nonce.signature  (HMAC is made in the Edge Function)
-- DB owns the clock: exp = now() + 60s, taken from this function.
-- =====================================================================

create or replace function public.qr_issue(p_user uuid, p_booking uuid, p_nonce uuid)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_exp timestamptz := date_trunc('second', now()) + interval '60 seconds';
  v_ok  uuid;
begin
  select id into v_ok from public.bookings
   where id = p_booking and user_id = p_user and status = 'held' and hold_expires_at > now();
  if v_ok is null then
    return jsonb_build_object('ok', false, 'code', 'NOT_ELIGIBLE');
  end if;

  -- A newly issued QR supersedes older unconsumed ones.
  update public.qr_tokens set expires_at = least(expires_at, now())
   where booking_id = p_booking and consumed_at is null and expires_at > now();

  insert into public.qr_tokens (nonce, booking_id, issued_to, expires_at)
  values (p_nonce, p_booking, p_user, v_exp);

  return jsonb_build_object('ok', true, 'exp', extract(epoch from v_exp)::bigint);
end $$;

create or replace function public.qr_consume(
  p_actor uuid, p_actor_is_staff boolean, p_booking uuid, p_nonce uuid, p_exp bigint
) returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  t public.qr_tokens;
  b public.bookings;
begin
  -- Row lock: two simultaneous scans of the same QR serialise here;
  -- the second one sees consumed_at set and fails with USED.
  select * into t from public.qr_tokens
   where nonce = p_nonce and booking_id = p_booking and expires_at = to_timestamp(p_exp)
   for update;
  if not found then
    return jsonb_build_object('ok', false, 'code', 'INVALID');
  end if;

  select * into b from public.bookings where id = p_booking for update;
  if not found then
    return jsonb_build_object('ok', false, 'code', 'INVALID');
  end if;

  -- Authorisation first, so a stranger cannot burn the owner's QR.
  if p_actor is null or (b.user_id <> p_actor and not coalesce(p_actor_is_staff, false)) then
    return jsonb_build_object('ok', false, 'code', 'FORBIDDEN');
  end if;
  if t.consumed_at is not null then
    return jsonb_build_object('ok', false, 'code', 'USED');
  end if;
  if t.expires_at <= now() then
    return jsonb_build_object('ok', false, 'code', 'EXPIRED');
  end if;
  if b.status <> 'held' or b.hold_expires_at <= now() then
    return jsonb_build_object('ok', false, 'code', 'NOT_ELIGIBLE');
  end if;

  update public.qr_tokens set consumed_at = now(), consumed_by = p_actor where nonce = p_nonce;
  update public.bookings set status = 'confirmed', confirmed_at = now() where id = p_booking;

  return jsonb_build_object('ok', true, 'booking', jsonb_build_object(
    'id', b.id, 'table_id', b.table_id, 'slot_start', b.slot_start,
    'slot_end', b.slot_end, 'status', 'confirmed'));
end $$;

-- =====================================================================
-- CLEANUP (idempotent, bounded)
-- * deletes idle rate-limit buckets (full buckets carry no information) unless banned
-- * deletes unconsumed QR tokens expired > 1 hour ago, consumed ones > 7 days ago
-- * moves stale holds to 'expired' and finished confirmed bookings to 'completed'
-- Bookings themselves are NEVER deleted. Each step handles at most p_batch rows.
-- =====================================================================
create or replace function public.cleanup_expired(p_batch int default 1000)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  n_rl int; n_qr int; n_exp int; n_done int;
  v_batch int := least(greatest(coalesce(p_batch, 1000), 1), 10000);
begin
  with d as (
    select key from public.rate_limit_buckets
     where updated_at < now() - interval '1 hour'
       and (banned_until is null or banned_until < now())
     limit v_batch for update skip locked)
  delete from public.rate_limit_buckets r using d where r.key = d.key;
  get diagnostics n_rl = row_count;

  with d as (
    select nonce from public.qr_tokens
     where (consumed_at is null and expires_at < now() - interval '1 hour')
        or (consumed_at is not null and consumed_at < now() - interval '7 days')
     limit v_batch for update skip locked)
  delete from public.qr_tokens q using d where q.nonce = d.nonce;
  get diagnostics n_qr = row_count;

  with d as (
    select id from public.bookings where status = 'held' and hold_expires_at <= now()
     limit v_batch for update skip locked)
  update public.bookings b set status = 'expired' from d where b.id = d.id;
  get diagnostics n_exp = row_count;

  with d as (
    select id from public.bookings where status = 'confirmed' and slot_end <= now()
     limit v_batch for update skip locked)
  update public.bookings b set status = 'completed' from d where b.id = d.id;
  get diagnostics n_done = row_count;

  return jsonb_build_object('rate_limit_buckets_deleted', n_rl, 'qr_tokens_deleted', n_qr,
                            'holds_expired', n_exp, 'bookings_completed', n_done);
end $$;

-- Schedule with pg_cron every 5 minutes if the extension is available.
do $$
begin
  create extension if not exists pg_cron;
  perform cron.unschedule('aitu-space-cleanup')
    where exists (select 1 from cron.job where jobname = 'aitu-space-cleanup');
  perform cron.schedule('aitu-space-cleanup', '*/5 * * * *', 'select public.cleanup_expired(1000)');
exception when others then
  raise notice 'pg_cron not scheduled (%). Enable the pg_cron extension and re-run this block.', sqlerrm;
end $$;

-- =====================================================================
-- PRIVILEGES: least privilege, deny by default.
-- =====================================================================
revoke all on public.study_tables, public.bookings, public.rate_limit_buckets,
              public.rate_limit_state, public.qr_tokens from anon, authenticated;
grant select on public.study_tables, public.bookings to authenticated;

revoke execute on function
  public.rl_take(text, double precision, double precision, boolean),
  public.rate_limit_check(uuid, text),
  public.slot_bounds(int),
  public.create_booking(uuid, text, int),
  public.cancel_booking(uuid, uuid),
  public.qr_issue(uuid, uuid, uuid),
  public.qr_consume(uuid, boolean, uuid, uuid, bigint),
  public.cleanup_expired(int),
  public.get_availability(),
  public.is_institutional(),
  public.enforce_institutional_email()
from public, anon, authenticated;

grant execute on function
  public.rl_take(text, double precision, double precision, boolean),
  public.rate_limit_check(uuid, text),
  public.slot_bounds(int),
  public.create_booking(uuid, text, int),
  public.cancel_booking(uuid, uuid),
  public.qr_issue(uuid, uuid, uuid),
  public.qr_consume(uuid, boolean, uuid, uuid, bigint),
  public.cleanup_expired(int)
to service_role;

-- Needed by RLS policies / the read-only availability RPC for signed-in users.
grant execute on function public.is_institutional() to authenticated, service_role;
grant execute on function public.get_availability() to authenticated, service_role;
