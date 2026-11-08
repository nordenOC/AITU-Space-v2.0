import { Link } from "react-router-dom";
import { I } from "../lib/icons";

// Every row below describes a control that exists in this repository
// (supabase/migrations/*.sql and supabase/functions/*). Keep it in sync with the code.
const ROWS: { risk: string; consequence: string; protection: string }[] = [
  {
    risk: "Unauthorized access / account impersonation",
    consequence: "Someone books, cancels or confirms on behalf of another student, or reads their bookings.",
    protection:
      "Every action goes through a server function that verifies the Supabase login token. The user identity is taken from that token only, never from the request body. Row Level Security lets each user read only their own bookings, and nobody can write to booking tables directly. Failed rate limits and repeated abuse are blocked.",
  },
  {
    risk: "Non-institutional email accounts",
    consequence: "People outside Astana IT University take tables meant for students.",
    protection:
      "Only verified @astanait.edu.kz addresses are accepted. The domain is checked on the server for every request, in database policies, and by a database trigger that rejects sign-ups and email changes to any other domain. Look-alike domains and subdomains are rejected.",
  },
  {
    risk: "Duplicate active bookings",
    consequence: "One student holds several tables at once and others cannot sit down.",
    protection:
      "A partial unique index allows at most one active (held or confirmed) booking per user. The database enforces it, so two simultaneous requests cannot both succeed.",
  },
  {
    risk: "Double booking of the same table/time slot",
    consequence: "Two students arrive at the same table for the same hour.",
    protection:
      "An exclusion constraint on (table, time range) rejects overlapping active bookings. The loser of a race gets a clear \"slot taken\" answer. Held bookings that are never confirmed are released after 10 minutes.",
  },
  {
    risk: "Automated abuse / excessive requests",
    consequence: "Bots grab every table or slow the service down for real students.",
    protection:
      "A token-bucket rate limiter in PostgreSQL runs before any work: per user, per client IP (stored hashed) and globally. Five violations ban that identity for 10 minutes. A short \"shield mode\" (3 requests, then 1 per second, for about 5 seconds) switches on during traffic spikes. Limited requests receive HTTP 429 with a Retry-After header.",
  },
  {
    risk: "QR forgery or tampering",
    consequence: "A fake or edited code confirms a booking that was never made, or someone else's.",
    protection:
      "QR codes are signed on the server with HMAC-SHA256 using a secret that never leaves server-side secret storage. Signatures are verified in constant time, and the booking, expiry and code identifier must all match the stored record. Only the booking owner (or staff) can confirm.",
  },
  {
    risk: "QR replay / reuse",
    consequence: "A photographed or shared code is used again.",
    protection:
      "Each code has a unique identifier stored in the database and consumed under a row lock, so it works exactly once, even when two scans arrive at the same moment. Issuing a new code or cancelling the booking invalidates older codes.",
  },
  {
    risk: "Expired QR codes",
    consequence: "An old code is used long after it was shown.",
    protection:
      "A code is valid for 60 seconds. Expiry is checked in the signed payload and again against the database clock. The app refreshes the code automatically while the booking is held.",
  },
  {
    risk: "Direct database/API access that bypasses the UI",
    consequence: "Someone calls the database API by hand to skip the checks in the app.",
    protection:
      "Browser keys have read-only access to the user's own bookings and the floor plan. Insert, update and delete are not granted. Booking, rate-limit and QR functions can only be executed by the server (service role). All rules are enforced in the database and server functions, and the front end checks are only for convenience.",
  },
  {
    risk: "Exposure of secrets or sensitive user data",
    consequence: "Leaked keys would let an attacker forge codes or read all data.",
    protection:
      "The QR signing secret, IP-hashing salt and service key exist only as server secrets and never reach the browser bundle. Rate-limit and QR tables have no client access at all. Errors shown to users are generic, and logs contain no QR payloads, signatures or secrets. Cross-origin access is limited to an allow-list of app origins.",
  },
];

export default function Security() {
  return (
    <main className="doc">
      <Link className="back-home" to="/"><span style={{ display: "contents" }} dangerouslySetInnerHTML={{ __html: I.back }} />Back to AITU Space</Link>
      <h1>How we keep bookings secure.</h1>
      <p className="lede muted">The risks we designed for, what each one would cost students, and the protection that is built into AITU Space today.</p>
      <div className="tablewrap">
        <table className="sec">
          <thead><tr><th scope="col">Risk</th><th scope="col">Consequence</th><th scope="col">Protection</th></tr></thead>
          <tbody>
            {ROWS.map((r) => (
              <tr key={r.risk}><td>{r.risk}</td><td>{r.consequence}</td><td>{r.protection}</td></tr>
            ))}
          </tbody>
        </table>
      </div>
    </main>
  );
}
