import { PGlite } from "@electric-sql/pglite";
import { btree_gist } from "@electric-sql/pglite/contrib/btree_gist";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Real PostgreSQL (WASM) with minimal Supabase stand-ins: roles, auth.users,
 * auth.uid()/auth.jwt() reading request.jwt.claims, and Supabase's default
 * privileges (new tables/functions are open to anon/authenticated/service_role),
 * so the migration's REVOKEs are genuinely exercised.
 */
const PREAMBLE = `
  create role anon nologin;
  create role authenticated nologin;
  create role service_role nologin bypassrls;
  create schema auth;
  create schema extensions;
  create table auth.users (id uuid primary key default gen_random_uuid(), email text);
  create function auth.jwt() returns jsonb language sql stable as
    $$ select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb $$;
  create function auth.uid() returns uuid language sql stable as
    $$ select nullif(auth.jwt() ->> 'sub', '')::uuid $$;
  grant usage on schema public, auth, extensions to anon, authenticated, service_role;
  grant execute on all functions in schema auth to anon, authenticated, service_role;
  alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
  alter default privileges in schema public grant all on functions to anon, authenticated, service_role;
`;

export const U1 = "11111111-1111-1111-1111-111111111111";
export const U2 = "22222222-2222-2222-2222-222222222222";
export const U3 = "33333333-3333-3333-3333-333333333333";
export const OUTSIDER = "44444444-4444-4444-4444-444444444444";

export async function makeDb(): Promise<PGlite> {
  const db = new PGlite({ extensions: { btree_gist } });
  await db.exec(PREAMBLE);
  await db.exec(readFileSync(join(__dirname, "../../supabase/migrations/20261108000000_security_backend.sql"), "utf8"));
  await db.exec(`
    insert into auth.users (id, email) values
      ('${U1}', 'one@astanait.edu.kz'), ('${U2}', 'two@astanait.edu.kz'), ('${U3}', 'three@astanait.edu.kz');`);
  // NOTE: OUTSIDER is intentionally not inserted: the sign-up trigger rejects non-institutional emails.
  return db;
}

/** Run SQL as a role with JWT claims, like PostgREST does. */
export async function as<T = any>(
  db: PGlite, role: "anon" | "authenticated" | "service_role", claims: Record<string, unknown> | null, sql: string,
  params: unknown[] = [],
): Promise<T[]> {
  await db.exec(`set role ${role}`);
  await db.query(`select set_config('request.jwt.claims', $1, false)`, [claims ? JSON.stringify(claims) : ""]);
  try {
    return (await db.query<T>(sql, params)).rows;
  } finally {
    await db.exec(`reset role`);
  }
}

export const jwt = (sub: string, email: string) => ({ sub, email, role: "authenticated" });
