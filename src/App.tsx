import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import QRCode from "qrcode";
import { Link } from "react-router-dom";
import { I } from "./lib/icons";
import { configured, supabase } from "./lib/supabase";
import {
  ApiFailure, cancelBooking, confirmQr, createBooking, issueQr, loadActiveBooking, loadTables, loadTaken,
  type Booking, type StudyTable,
} from "./lib/api";

type Screen = "home" | "map" | "slots" | "confirm" | "success" | "error";
const SLOTS = ["12:00 â€“ 13:00", "13:00 â€“ 14:00", "14:00 â€“ 15:00", "15:00 â€“ 16:00", "16:00 â€“ 17:00"];
const CAPACITIES = [2, 4, 6];
const DOMAIN = "@astanait.edu.kz";
const TZ = "Asia/Almaty";
const QR_REFRESH_MS = 45_000; // server QR lives 60 s; refresh well before it dies

const Icon = ({ svg, className }: { svg: string; className?: string }) =>
  <span className={className} style={{ display: "contents" }} dangerouslySetInnerHTML={{ __html: svg }} />;

const almatyHour = () => Number(new Intl.DateTimeFormat("en-GB", { hour: "numeric", hourCycle: "h23", timeZone: TZ }).format(new Date()));
const now = new Date();
const shortDate = new Intl.DateTimeFormat("en", { month: "long", day: "numeric", timeZone: TZ }).format(now);
const fmt = (s: number) => String(Math.floor(s / 60)).padStart(2, "0") + ":" + String(s % 60).padStart(2, "0");
const powerLabel = (t: StudyTable) => t.power === "active" ? "Working socket" : t.power === "faulty" ? "Socket out of order" : "No socket";
const slotLabel = (b: Booking) => {
  const h = (d: string) => new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", hourCycle: "h23", timeZone: TZ }).format(new Date(d));
  return `${h(b.slot_start)} â€“ ${h(b.slot_end)}`;
};

/* ---------------- login (institutional email, one-time code) ---------------- */
function Login() {
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [step, setStep] = useState<"email" | "code">("email");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const normalized = email.trim().toLowerCase();
  const okDomain = normalized.endsWith(DOMAIN) && normalized.length > DOMAIN.length;

  async function send(e: React.FormEvent) {
    e.preventDefault();
    if (!okDomain) { setMsg(`Use your ${DOMAIN} address.`); return; } // convenience only; the server enforces it
    setBusy(true); setMsg(null);
    const { error } = await supabase.auth.signInWithOtp({ email: normalized, options: { shouldCreateUser: true } });
    setBusy(false);
    if (error) setMsg("We couldn't send a code. Check the address and try again in a minute.");
    else setStep("code");
  }
  async function verify(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setMsg(null);
    const { error } = await supabase.auth.verifyOtp({ email: normalized, token: code.trim(), type: "email" });
    setBusy(false);
    if (error) setMsg("That code didn't work. Check it and try again.");
  }

  return (
    <form onSubmit={step === "email" ? send : verify} style={{ display: "flex", flexDirection: "column", flex: 1 }}>
      <h1 className="home-title">Sign in to book.</h1>
      <p className="lede">AITU Space is for Astana IT University students. Use your {DOMAIN} email; we'll send you a one-time code.</p>
      {step === "email" ? (
        <div className="field">
          <label htmlFor="email">University email</label>
          <input id="email" className="input" type="email" inputMode="email" autoComplete="email" required
            placeholder={`name${DOMAIN}`} value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
      ) : (
        <div className="field">
          <label htmlFor="code">6-digit code sent to {normalized}</label>
          <input id="code" className="input code" inputMode="numeric" autoComplete="one-time-code" maxLength={8} required
            value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} />
        </div>
      )}
      {msg && <div className="notice err" role="alert">{msg}</div>}
      <div className="home-cta mt-auto">
        <button className="btn btn-primary" disabled={busy || (step === "email" ? !email : code.length < 6)}>
          {busy ? <span className="spinner" /> : null}{step === "email" ? "Send code" : "Verify and continue"}
        </button>
        {step === "code" && <button type="button" className="btn btn-ghost" onClick={() => { setStep("email"); setCode(""); setMsg(null); }}>Use a different email</button>}
      </div>
      <Link className="footlink" to="/security">How we keep bookings secure</Link>
    </form>
  );
}

/* ---------------- confirm screen: server-signed QR + hold timer ---------------- */
function ConfirmScreen({ booking, onConfirmed, onCancelled, onExpired }: {
  booking: Booking; onConfirmed: (b: Booking) => void; onCancelled: () => void; onExpired: () => void;
}) {
  const holdMs = new Date(booking.hold_expires_at).getTime();
  const total = useRef(Math.max(1, Math.ceil((holdMs - Date.now()) / 1000))).current;
  const [seconds, setSeconds] = useState(() => Math.max(0, Math.ceil((holdMs - Date.now()) / 1000)));
  const [qrText, setQrText] = useState<string | null>(null);
  const [qrImg, setQrImg] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<"confirm" | "cancel" | null>(null);
  const qrRef = useRef<string | null>(null);
  const expiredRef = useRef(false);

  const refreshQr = useCallback(async () => {
    try {
      const r = await issueQr(booking.id);
      qrRef.current = r.qr; setQrText(r.qr);
      setQrImg(await QRCode.toDataURL(r.qr, { margin: 1, width: 384, errorCorrectionLevel: "M" }));
      setNotice(null);
    } catch (e) {
      const f = e as ApiFailure;
      if (f.code === "NOT_ELIGIBLE") { if (!expiredRef.current) { expiredRef.current = true; onExpired(); } return; }
      setNotice(f.message);
    }
  }, [booking.id, onExpired]);

  useEffect(() => {
    refreshQr();
    const id = setInterval(refreshQr, QR_REFRESH_MS);
    return () => clearInterval(id);
  }, [refreshQr]);

  useEffect(() => {
    const id = setInterval(() => {
      const s = Math.max(0, Math.ceil((holdMs - Date.now()) / 1000));
      setSeconds(s);
      if (s <= 0 && !expiredRef.current) { expiredRef.current = true; onExpired(); }
    }, 1000);
    return () => clearInterval(id);
  }, [holdMs, onExpired]);

  async function confirm() {
    if (!qrRef.current) return;
    setBusy("confirm"); setNotice(null);
    try { onConfirmed(await confirmQr(qrRef.current)); }
    catch (e) {
      const f = e as ApiFailure;
      setNotice(f.message);
      if (f.code === "QR_EXPIRED") refreshQr();
      if (f.code === "NOT_ELIGIBLE") onExpired();
      setBusy(null);
    }
  }
  async function cancel() {
    setBusy("cancel"); setNotice(null);
    try { await cancelBooking(booking.id); onCancelled(); }
    catch (e) { setNotice((e as ApiFailure).message); setBusy(null); }
  }

  return (
    <div className="center" style={{ display: "flex", flexDirection: "column", flex: 1 }}>
      <div className="steps" style={{ width: "100%" }} aria-hidden="true"><span className="on" /><span className="on" /></div>
      <h1 style={{ fontSize: "1.9rem" }}>Confirm at the table</h1>
      <p className="muted" style={{ marginTop: ".4rem", fontSize: ".95rem" }}>Scan the code on table {booking.table_id}, or confirm below.</p>
      <div className="qrbox">
        {qrImg ? <img src={qrImg} alt="Booking QR code" width={176} height={176} style={{ width: "11rem", height: "11rem" }} />
          : <div className="loading"><span className="spinner" aria-label="Loading code" /></div>}
      </div>
      <div className="timerbar"><div className="row"><div><span className="muted" style={{ fontSize: ".78rem" }}>Held for you</span><div className="t" id="timer">{fmt(seconds)}</div></div>
        <div style={{ textAlign: "right", fontSize: ".85rem" }}><strong>{booking.table_id}</strong><br /><span className="muted">{slotLabel(booking)}</span></div></div>
        <div className="track"><i style={{ width: `${Math.min(100, (seconds / total) * 100)}%` }} /></div></div>
      {notice && <div className="notice err" role="alert" style={{ width: "100%", textAlign: "left" }}>{notice}</div>}
      <div className="actions mt-auto">
        <button className="btn btn-ghost" disabled={busy !== null} onClick={cancel}>
          {busy === "cancel" ? <span className="spinner" /> : <Icon svg={I.x} />}Cancel</button>
        <button className="btn btn-primary" disabled={busy !== null || !qrText} onClick={confirm}>
          {busy === "confirm" ? <span className="spinner" /> : <Icon svg={I.check} />}Confirm</button>
      </div>
    </div>
  );
}

/* ---------------- main app ---------------- */
export default function App() {
  const [session, setSession] = useState<Session | null | undefined>(undefined);
  const [screen, setScreen] = useState<Screen>("home");
  const [tables, setTables] = useState<StudyTable[]>([]);
  const [taken, setTaken] = useState<Record<string, number[]>>({});
  const [active, setActive] = useState<Booking | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selectedTable, setSelectedTable] = useState<string | null>(null);
  const [selectedSlot, setSelectedSlot] = useState<number | null>(null);
  const [filters, setFilters] = useState<{ power: boolean; seats: number | null }>({ power: false, seats: null });
  const [justToggledPower, setJustToggledPower] = useState(false);
  const [booking, setBooking] = useState<Booking | null>(null);
  const [booked, setBooked] = useState<Booking | null>(null);
  const [errorReason, setErrorReason] = useState<"cancelled" | "timeout" | "failed">("cancelled");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [slotError, setSlotError] = useState<string | null>(null);
  const screenRef = useRef<HTMLElement>(null);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => setSession(data.session));
    const { data } = supabase.auth.onAuthStateChange((_e, s) => setSession(s));
    return () => data.subscription.unsubscribe();
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true); setLoadError(null);
    try {
      const [t, tk, a] = await Promise.all([loadTables(), loadTaken(), loadActiveBooking()]);
      setTables(t); setTaken(tk); setActive(a);
    } catch (e) { setLoadError((e as ApiFailure).message); }
    setLoading(false);
  }, []);
  useEffect(() => { if (session) refresh(); }, [session, refresh]);

  const hour = almatyHour();
  const slotPast = (i: number) => hour >= 13 + i;
  const view = useMemo(() => tables.map((t) => {
    const tk = taken[t.id] ?? [];
    const open = SLOTS.map((_, i) => i).filter((i) => !slotPast(i) && !tk.includes(i));
    return { ...t, status: open.length === 0 ? "occupied" as const : "available" as const };
  }), [tables, taken, hour]); // eslint-disable-line react-hooks/exhaustive-deps
  const T = (id: string) => view.find((t) => t.id === id)!;
  const free = () => view.filter((t) => t.status === "available");
  const matches = (t: (typeof view)[number]) => t.status === "available" && (!filters.power || t.power === "active") && (!filters.seats || t.seats === filters.seats);
  const hasFilters = filters.power || filters.seats;

  const go = (s: Screen) => { setScreen(s); screenRef.current?.classList.remove("enter"); void screenRef.current?.offsetWidth; screenRef.current?.classList.add("enter"); if (screenRef.current) screenRef.current.scrollTop = 0; };
  const restart = () => { setSelectedTable(null); setSelectedSlot(null); setFilters({ power: false, seats: null }); setBooking(null); setBooked(null); refresh(); go("home"); };
  const backTarget: Record<Screen, Screen> = { home: "home", map: "home", slots: "map", confirm: "slots", success: "home", error: "home" };

  async function book() {
    if (!selectedTable || selectedSlot === null) return;
    setSubmitting(true); setSlotError(null);
    try {
      const b = await createBooking(selectedTable, selectedSlot); // UI moves on only after the server says yes
      setBooking(b); go("confirm");
    } catch (e) {
      const f = e as ApiFailure;
      setSlotError(f.message);
      if (f.code === "SLOT_TAKEN" || f.code === "SLOT_PAST") { setSelectedSlot(null); loadTaken().then(setTaken).catch(() => {}); }
      if (f.code === "UNAUTHENTICATED") await supabase.auth.signOut();
    }
    setSubmitting(false);
  }

  const failTo = (reason: "cancelled" | "timeout" | "failed", msg: string | null = null) => { setErrorReason(reason); setErrorMsg(msg); refresh(); go("error"); };
  const onExpired = useCallback(() => { setErrorReason("timeout"); setErrorMsg(null); refresh(); setScreen("error"); }, [refresh]);

  useEffect(() => { if (justToggledPower) { const id = setTimeout(() => setJustToggledPower(false), 1000); return () => clearTimeout(id); } }, [justToggledPower]);

  /* ---- gate ---- */
  if (!configured) return <Shell><div className="notice err">The app isn't configured yet. Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY.</div></Shell>;
  if (session === undefined) return <Shell><div className="loadingpane"><span className="spinner" /></div></Shell>;
  if (!session) return <Shell><Login /></Shell>;

  const n = free().length, p = free().filter((t) => t.power === "active").length;

  const floorPlan = (preview: boolean) => (
    <div className={`plan ${justToggledPower ? "charging" : ""}`}>
      <div className="windows" /><span className="winlabel">Windows</span>
      <div className="void">Open atrium</div>
      {view.map((t) => {
        const ok = matches(t);
        const cls = t.status === "occupied" ? "busy" : selectedTable === t.id ? "free selected" : "free" + (ok ? "" : " dim");
        const disabled = preview || t.status === "occupied" || !ok;
        return (
          <button key={t.id} className={`table s${t.seats} ${cls}`} style={{ left: t.plan_x, top: t.plan_y }} disabled={disabled}
            aria-label={`Table ${t.id}, ${t.status === "occupied" ? "occupied" : "free"}, ${t.seats} seats, ${powerLabel(t).toLowerCase()}`}
            data-k={`t-${t.id}`} aria-pressed={selectedTable === t.id ? true : undefined} onClick={() => pickTable(t.id)}>
            <span>{t.id}<small>{t.seats}</small></span>
            {t.power === "active" && <span className="bolt" title="Working socket"><Icon svg={I.bolt} /></span>}
            {t.power === "faulty" && <span className="bolt off" title="Socket out of order"><Icon svg={I.bolt} /></span>}
          </button>
        );
      })}
      {!preview && free().filter(matches).length === 0 && (
        <div className="empty" role="status"><b>No free table matches</b>
          <span>Try another size or <button className="linkbtn" style={{ padding: 0 }} onClick={() => setFilters({ power: false, seats: null })}>clear the filters</button>.</span></div>
      )}
      <div className="entrance">Entrance</div>
    </div>
  );

  function pickTable(id: string) { const t = T(id); if (!t || t.status !== "available" || !matches(t)) return; setSelectedTable(id); setSelectedSlot(null); setSlotError(null); }
  const togglePower = () => { const v = !filters.power; setFilters({ ...filters, power: v }); setJustToggledPower(v); dropInvalid({ ...filters, power: v }); };
  const toggleSeats = (s: number) => { const f = { ...filters, seats: filters.seats === s ? null : s }; setFilters(f); dropInvalid(f); };
  function dropInvalid(f: typeof filters) {
    if (!selectedTable) return; const t = T(selectedTable);
    if (!(t.status === "available" && (!f.power || t.power === "active") && (!f.seats || t.seats === f.seats))) setSelectedTable(null);
  }
  const startWithPower = () => { setFilters({ ...filters, power: true }); setJustToggledPower(true); setSelectedTable(null); go("map"); };

  const detail = () => {
    const t = selectedTable ? T(selectedTable) : null;
    if (!t) return <div className="detail"><p className="hint">Tap a free table on the plan to see its details.</p></div>;
    const fresh = t.power === "active" ? `Socket checked ${t.power_note}.` : t.power === "faulty" ? `Maintenance ${t.power_note}. Pick another table if you need to charge.` : "";
    return (
      <div className="detail">
        <div className="row"><h2>Table {t.id}</h2><span className="muted" style={{ fontSize: ".85rem" }}>{t.near_window ? "By the windows" : "Near the atrium"}</span></div>
        <div className="tags"><span className="tag"><Icon svg={I.users} />{t.seats} seats</span>
          {t.power === "active" ? <span className="tag power"><Icon svg={I.bolt} />Working socket</span>
            : t.power === "faulty" ? <span className="tag warn"><Icon svg={I.bolt} />Socket out of order</span> : <span className="tag">No socket</span>}</div>
        {fresh && <p className="fresh">{fresh}</p>}
      </div>
    );
  };

  const header = screen === "home"
    ? <div className="brand"><div className="logo">A</div><div><b>AITU Space</b><small>Atrium, floor 1</small></div></div>
    : <button className="back" aria-label="Back" onClick={() => go(backTarget[screen])}><Icon svg={I.back} /></button>;

  let body: React.ReactNode;
  if (loading && tables.length === 0) body = <div className="loadingpane"><span className="spinner" /><span>Loading the atriumâ€¦</span></div>;
  else if (loadError && tables.length === 0) body = (
    <div className="loadingpane"><div><div className="notice err" role="alert">{loadError}</div>
      <button className="btn btn-ghost" style={{ marginTop: ".8rem" }} onClick={refresh}><Icon svg={I.retry} />Try again</button></div></div>);
  else if (screen === "home") body = (<>
    <h1 className="home-title">Find a table with power.</h1>
    <p className="lede">Study spots in the first-floor atrium, free for students. Filter by working sockets and group size, then book an hour.</p>
    {active && (
      <div className="activecard"><div className="row"><div><span className="muted" style={{ fontSize: ".78rem" }}>Your booking</span><br />
        <strong>Table {active.table_id}, {slotLabel(active)}</strong></div>
        <span className="tag">{active.status === "held" ? "Awaiting confirmation" : "Confirmed"}</span></div>
        <div className="row">
          {active.status === "held" && <button className="btn btn-primary small" onClick={() => { setBooking(active); go("confirm"); }}>Confirm now</button>}
          <button className="btn btn-ghost small" onClick={async () => { try { await cancelBooking(active.id); await refresh(); } catch (e) { setLoadError((e as ApiFailure).message); } }}>Cancel booking</button>
        </div></div>)}
    <div className="stats">
      <div className="stat"><b>{n}</b><span>free tables now</span></div>
      <div className="stat"><b>{p}<Icon svg={I.bolt} /></b><span>with a working socket</span></div>
    </div>
    <div className="home-plan">{floorPlan(true)}</div>
    <div className="home-cta mt-auto">
      <button className="btn btn-charge" disabled={!!active} onClick={startWithPower}><Icon svg={I.bolt} />Find a table with power</button>
      <button className="btn btn-ghost" disabled={!!active} onClick={() => go("map")}>Browse all tables</button>
      <button className="linkbtn" style={{ justifySelf: "center" }} onClick={() => supabase.auth.signOut()}>Sign out</button>
      <Link className="footlink" style={{ margin: 0 }} to="/security">How we keep bookings secure</Link>
    </div></>);
  else if (screen === "map") {
    const m = free().filter(matches).length;
    body = (<>
      <div className="steps" aria-hidden="true"><span className="on" /><span /></div>
      <div className="row"><h1 style={{ fontSize: "1.9rem" }}>Pick a table</h1></div>
      <div className="chips" role="group" aria-label="Filter tables">
        <button className="fchip power" data-k="f-power" aria-pressed={filters.power} onClick={togglePower}><Icon svg={I.bolt} />Power socket</button>
        {CAPACITIES.map((c) => <button key={c} className="fchip" data-k={`f-${c}`} aria-pressed={filters.seats === c} onClick={() => toggleSeats(c)}><Icon svg={I.users} />{c} seats</button>)}
      </div>
      <p className="result" role="status" aria-live="polite"><span><b>{m}</b> of {free().length} free tables {hasFilters ? "match" : "shown"}</span>
        {hasFilters && <button className="linkbtn" onClick={() => setFilters({ power: false, seats: null })}>Clear filters</button>}</p>
      {floorPlan(false)}
      <div className="legend">
        <span><i style={{ borderColor: "var(--free)" }} />Free</span>
        <span><i style={{ borderColor: "var(--busy)", background: "var(--busy-soft)" }} />Taken</span>
        <span><i className="lb"><Icon svg={I.bolt} /></i>Working socket</span>
      </div>
      {detail()}
      <button className="btn btn-primary mt-auto" disabled={!selectedTable} onClick={() => go("slots")}>
        {selectedTable ? `Choose a time for ${selectedTable}` : "Select a table first"}{selectedTable ? <Icon svg={I.arrow} /> : null}</button></>);
  } else if (screen === "slots" && selectedTable) {
    const t = T(selectedTable), tk = taken[selectedTable] ?? [];
    body = (<>
      <div className="steps" aria-hidden="true"><span className="on" /><span className="on" /></div>
      <h1 style={{ fontSize: "1.9rem" }}>Choose a time</h1>
      <p className="muted" style={{ marginTop: ".4rem", fontSize: ".95rem" }}>Table {t.id}, {shortDate}. One hour per booking.</p>
      <div className="slotlist" role="group" aria-label="Time slots">
        {SLOTS.map((s, i) => {
          const unavailable = tk.includes(i) || slotPast(i);
          return (
            <button key={s} className={`slot ${selectedSlot === i ? "on" : ""} ${unavailable ? "taken" : ""}`} disabled={unavailable || submitting}
              aria-pressed={selectedSlot === i} data-k={`s-${i}`} onClick={() => { setSelectedSlot(i); setSlotError(null); }}>
              <span>{s}<small>{tk.includes(i) ? "Already booked" : slotPast(i) ? "Ended" : "Free"}</small></span><span className="tick"><Icon svg={I.check} /></span></button>);
        })}
      </div>
      {slotError && <div className="notice err" role="alert">{slotError}</div>}
      <div className="summary"><span className="muted">Your booking</span><strong>Table {t.id}, {selectedSlot !== null ? SLOTS[selectedSlot] : "no time yet"}</strong></div>
      <button className="btn btn-primary mt-auto" disabled={selectedSlot === null || submitting} onClick={book}>
        {submitting ? <><span className="spinner" />Bookingâ€¦</> : "Book this table"}</button></>);
  } else if (screen === "confirm" && booking) {
    body = <ConfirmScreen key={booking.id} booking={booking}
      onConfirmed={(b) => { setBooked(b); refresh(); go("success"); }}
      onCancelled={() => failTo("cancelled")} onExpired={onExpired} />;
  } else if (screen === "success" && booked) {
    const t = view.find((x) => x.id === booked.table_id);
    body = (<>
      <div className="badge ok"><Icon svg={I.check} /></div>
      <h1 style={{ fontSize: "2.4rem", marginTop: "1rem" }}>Table booked.</h1>
      <p className="muted" style={{ marginTop: ".5rem", lineHeight: 1.5 }}>You're confirmed. Enjoy your hour in the atrium.</p>
      <div className="ticket">
        <div className="row"><div className="big">{booked.table_id}</div><span style={{ color: "var(--primary)" }}><Icon svg={I.pin.replace("<svg", "<svg width='26' height='26'")} /></span></div>
        {t && <div className="tags"><span className="tag"><Icon svg={I.users} />{t.seats} seats</span>{t.power === "active" && <span className="tag power"><Icon svg={I.bolt} />Working socket</span>}</div>}
        <div className="grid2"><div><span>When</span><strong>{shortDate}, {slotLabel(booked)}</strong></div><div><span>Where</span><strong>Atrium, floor 1</strong></div></div>
      </div>
      <button className="btn btn-primary mt-auto" onClick={restart}><Icon svg={I.home} />Back to home</button></>);
  } else {
    const to = errorReason === "timeout", failed = errorReason === "failed";
    body = (<>
      <div className="badge err"><Icon svg={I.x} /></div>
      <h1 style={{ fontSize: "2.4rem", marginTop: "1rem" }}>{failed ? "Something went wrong." : to ? "Time ran out." : "Booking cancelled."}</h1>
      <p className="muted" style={{ marginTop: ".5rem", lineHeight: 1.5, maxWidth: "21rem" }}>{errorMsg ?? (to
        ? `We released ${booking?.table_id ?? "your table"} so other students can use it. Pick a table and try again.`
        : `${booking?.table_id ?? "Your table"} is free again. Return to the plan when you're ready.`)}</p>
      <div className="ticket"><strong>Nothing was charged</strong><p className="muted" style={{ fontSize: ".85rem", marginTop: ".25rem" }}>Booking at AITU Space is free for students.</p></div>
      <div className="actions even mt-auto"><button className="btn btn-ghost" onClick={restart}><Icon svg={I.home} />Home</button>
        <button className="btn btn-primary" onClick={() => { setSelectedSlot(null); setBooking(null); refresh(); go("map"); }}><Icon svg={I.retry} />Try again</button></div></>);
  }

  return (
    <Shell live={`${n} free, ${p} with power`} header={header} screenRef={screenRef}>{body}</Shell>
  );
}

function Shell({ children, header, live, screenRef }: {
  children: React.ReactNode; header?: React.ReactNode; live?: string; screenRef?: React.RefObject<HTMLElement>;
}) {
  return (
    <div className="app">
      <header>
        <div id="hdr-left">{header ?? <div className="brand"><div className="logo">A</div><div><b>AITU Space</b><small>Atrium, floor 1</small></div></div>}</div>
        {live && <div className="live"><i /><span>{live}</span></div>}
      </header>
      <main id="screen" ref={screenRef as React.RefObject<HTMLElement>} className="enter">{children}</main>
    </div>
  );
}

