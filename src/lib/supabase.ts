import { createClient } from "@supabase/supabase-js";

const url = import.meta.env.VITE_SUPABASE_URL as string | undefined;
const anon = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;

export const configured = Boolean(url && anon);
// Only the public (anon/publishable) key ever reaches the browser.
export const supabase = createClient(url ?? "http://localhost:54321", anon ?? "missing", {
  auth: { persistSession: true, autoRefreshToken: true },
});
export const FUNCTIONS_URL = `${url ?? ""}/functions/v1`;
