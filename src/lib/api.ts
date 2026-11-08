import { FUNCTIONS_URL, supabase } from "./supabase";

export type Booking = {
  id: string; table_id: string; slot_index?: number; slot_start: string; slot_end: string;
  status: "held" | "confirmed" | "cancelled" | "expired" | "completed"; hold_expires_at: string;
};

export class ApiFailure extends Error {
  constructor(public code: string, message: string, public retryAfter?: number) { super(message); }
}

// Friendly copy per server error code. Anything unknown becomes a generic message,
// so internals never reach the UI.
const MESSAGES: Record<string, string> = {
  ACTIVE_BOOKING_EXISTS: "You already have an active booking. Cancel it before booking another table.",
  SLOT_TAKEN: "Someone just booked that time. Please choose another slot.",
  SLOT_PAST: "That time slot has already ended.",
  RATE_LIMITED: "You're going a bit fast. Please wait a moment and try again.",
  QR_EXPIRED: "This code expired. A fresh one is on its way.",
  QR_USED: "This code was already used.",
  QR_INVALID: "This code isn't valid.",
  NOT_ELIGIBLE: "This booking can no longer be confirmed. Please book again.",
  NOT_FOUND: "We couldn't find that booking.",
  NOT_INSTITUTIONAL: "Only @astanait.edu.kz accounts can use AITU Space.",
  UNAUTHENTICATED: "Your session ended. Please sign in again.",
  FORBIDDEN: "You are not allowed to do that.",
  INVALID_INPUT: "Something about that request wasn't right. Please try again.",
};

async function call<T>(fn: string, body: Record<string, unknown>): Promise<T> {
  const { data } = await supabase.auth.getSession();
  const token = data.session?.access_token;
  if (!token) throw new ApiFailure("UNAUTHENTICATED", MESSAGES.UNAUTHENTICATED);
  let res: Response;
  try {
    res = await fetch(`${FUNCTIONS_URL}/${fn}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
  } catch {
    throw new ApiFailure("NETWORK", "Can't reach the server. Check your connection and try again.");
  }
  const json = await res.json().catch(() => null);
  if (!res.ok) {
    const code: string = json?.error?.code ?? "SERVER_ERROR";
    const retry = Number(res.headers.get("Retry-After")) || undefined;
    throw new ApiFailure(code, MESSAGES[code] ?? "Something went wrong. Please try again.", retry);
  }
  return json as T;
}

export const createBooking = (table_id: string, slot: number) =>
  call<{ booking: Booking }>("bookings-create", { table_id, slot }).then((r) => r.booking);
export const cancelBooking = (booking_id: string) => call<{ ok: true }>("bookings-cancel", { booking_id });
export const issueQr = (booking_id: string) => call<{ qr: string; expires_at: string }>("qr-issue", { booking_id });
export const confirmQr = (qr: string) => call<{ booking: Booking }>("qr-confirm", { qr }).then((r) => r.booking);

// ---- reads (protected by RLS / institutional check in the database) ----
export type StudyTable = {
  id: string; seats: number; power: "active" | "faulty" | "none"; near_window: boolean;
  power_note: string | null; plan_x: string; plan_y: string;
};

export async function loadTables(): Promise<StudyTable[]> {
  const { data, error } = await supabase.from("study_tables").select("*").order("id");
  if (error) throw new ApiFailure("SERVER_ERROR", "Couldn't load the floor plan.");
  return data as StudyTable[];
}

/** slot indexes taken today, per table */
export async function loadTaken(): Promise<Record<string, number[]>> {
  const { data, error } = await supabase.rpc("get_availability");
  if (error) throw new ApiFailure("SERVER_ERROR", "Couldn't load availability.");
  const out: Record<string, number[]> = {};
  for (const r of (data ?? []) as { table_id: string; slot_index: number }[]) (out[r.table_id] ??= []).push(r.slot_index);
  return out;
}

export async function loadActiveBooking(): Promise<Booking | null> {
  const { data, error } = await supabase
    .from("bookings").select("id,table_id,slot_start,slot_end,status,hold_expires_at")
    .in("status", ["held", "confirmed"]).gt("slot_end", new Date().toISOString()).limit(1);
  if (error) throw new ApiFailure("SERVER_ERROR", "Couldn't load your booking.");
  const b = (data?.[0] ?? null) as Booking | null;
  if (b && b.status === "held" && new Date(b.hold_expires_at) <= new Date()) return null;
  return b;
}
