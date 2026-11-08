# AITU Space

Student table-booking app (floor plan A1–D2, power/seat filters, hourly slots, QR confirmation) with a
Supabase backend: Auth, PostgreSQL (RLS, constraints, rate limiter), Edge Functions.
Stack: Vite + React + TypeScript. No Cloudflare dependency.

## Layout
| Path | Purpose |
|---|---|
| `src/` | UI ported from the approved prototype (`aitu-space-improved-v2.html`), `/security` page |
| `supabase/migrations/20261108000000_security_backend.sql` | tables, RLS, constraints, rate limiter, QR state, cleanup, grants |
| `supabase/functions/` | `bookings-create`, `bookings-cancel`, `qr-issue`, `qr-confirm` + `_shared/` |
| `tests/unit`, `tests/db` | run anywhere: `npm test` (db tests use real Postgres via PGlite) |
| `tests/integration` | live-stack tests, `npm run test:integration` |

## Deploy (all manual steps)
1. `supabase link --project-ref <ref>` then `supabase db push` (applies the migration).
2. Enable the **pg_cron** extension (Dashboard → Database → Extensions), then re-run the last `do $$ … cron.schedule …` block
   of the migration (or `supabase db push` again after enabling). Verify: `select * from cron.job where jobname='aitu-space-cleanup';`
   and `select * from cron.job_run_details order by start_time desc limit 5;`
3. Secrets (values are never committed):
   ```
   supabase secrets set QR_HMAC_SECRET=$(openssl rand -base64 48) IP_HASH_SALT=$(openssl rand -base64 32) \
     ALLOWED_ORIGINS=https://aitu-space.lovable.app TRUSTED_PROXY_HOPS=1
   ```
   `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are injected by Supabase automatically.
4. `supabase functions deploy bookings-create bookings-cancel qr-issue qr-confirm --no-verify-jwt`
5. Auth: enable Email provider with OTP, and make the "Magic Link"/"Confirm signup" email templates show `{{ .Token }}` (6-digit code).
   Optionally add `Site URL`/redirects for your origin. Staff accounts: set `app_metadata.role = "staff"` via the service role only.
6. Frontend env (`.env`, publishable key only): `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY`. Configure SPA fallback so `/security` serves `index.html`.
7. Check `TRUSTED_PROXY_HOPS`: log/inspect the `x-forwarded-for` your deployment really receives once and set the number of
   trusted proxies. A wrong value only affects IP bucketing (falls back to one shared, stricter bucket).

## Local live testing
```
supabase start && supabase db reset
printf "QR_HMAC_SECRET=...48+ chars...\nIP_HASH_SALT=...\nALLOWED_ORIGINS=http://localhost:5173\n" > supabase/functions/.env
supabase functions serve --no-verify-jwt --env-file supabase/functions/.env
SUPABASE_URL=http://127.0.0.1:54321 SUPABASE_ANON_KEY=... SUPABASE_SERVICE_ROLE_KEY=... npm run test:integration
```

## Rate limits
| Scope | Capacity | Refill | Notes |
|---|---|---|---|
| global | 300 | 100/s | not clamped by shield |
| ip (hashed) | 60 | 5/s | campus NAT friendly |
| user | 10 | 0.5/s | |

* 5 denials within 60 s → that key is banned for 10 min (`banned_until`).
* Shield mode: armed by >150 req/s or global exhaustion; lasts 5 s after the last trigger; ip/user buckets are clamped to capacity 3
  and refill 1 token/s while active, then normal limits resume.
* Denied requests get HTTP 429 + `Retry-After`.

## QR
`bookingId.exp.nonce.signature`; signature = base64url(HMAC-SHA256(secret, "bookingId.exp.nonce")). `exp` = DB time + 60 s.
Verified in constant time, then consumed with a row-locked UPDATE on `qr_tokens` (single use). Owner or `staff` role only.
