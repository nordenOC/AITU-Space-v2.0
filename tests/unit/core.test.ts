import { describe, expect, it } from "vitest";
import { signQr, verifyQr } from "../../supabase/functions/_shared/qr";
import { allowedOrigin, isInstitutionalEmail, normalizeEmail, pickClientIp } from "../../supabase/functions/_shared/pure";

const SECRET = "x".repeat(48);
const B = "11111111-1111-4111-8111-111111111111";
const N = "22222222-2222-4222-8222-222222222222";
const future = () => Math.floor(Date.now() / 1000) + 60;

describe("QR signing", () => {
  it("accepts a freshly signed token", async () => {
    const exp = future();
    const t = await signQr(SECRET, B, exp, N);
    const r = await verifyQr(SECRET, t);
    expect(r).toEqual({ ok: true, parts: { bookingId: B, exp, nonce: N } });
  });
  it("rejects a token signed with another secret", async () => {
    const t = await signQr("y".repeat(48), B, future(), N);
    expect(await verifyQr(SECRET, t)).toEqual({ ok: false, reason: "bad_signature" });
  });
  it("rejects any tampered field", async () => {
    const exp = future();
    const t = await signQr(SECRET, B, exp, N);
    const [b, e, n, s] = t.split(".");
    const other = "33333333-3333-4333-8333-333333333333";
    for (const forged of [`${other}.${e}.${n}.${s}`, `${b}.${exp + 600}.${n}.${s}`, `${b}.${e}.${other}.${s}`,
      `${b}.${e}.${n}.${s.slice(0, -1)}${s.endsWith("A") ? "B" : "A"}`]) {
      expect((await verifyQr(SECRET, forged)).ok).toBe(false);
    }
  });
  it("rejects expired tokens (signature valid, time passed)", async () => {
    const exp = future();
    const t = await signQr(SECRET, B, exp, N);
    expect(await verifyQr(SECRET, t, (exp + 1) * 1000)).toEqual({ ok: false, reason: "expired" });
  });
  it("rejects malformed input", async () => {
    for (const bad of [undefined, null, 42, "", "a.b.c", "a.b.c.d", `${B}.1.${N}.@@@`, "x".repeat(300), `${B}.1e9.${N}.AAAA`]) {
      expect((await verifyQr(SECRET, bad)).ok).toBe(false);
    }
  });
});

describe("email policy", () => {
  it("accepts only the institutional domain", () => {
    expect(isInstitutionalEmail("Student.Name@AstanaIT.edu.kz ")).toBe(true);
    for (const e of ["a@gmail.com", "a@astanait.edu.kz.evil.com", "a@sub.astanait.edu.kz", "a@astanait.edu.kz@x.com",
      "@astanait.edu.kz", "", null, undefined, 5, "a b@astanait.edu.kz", "a@astanait.edu.kz\n.evil"]) {
      expect(isInstitutionalEmail(e)).toBe(false);
    }
    expect(normalizeEmail("  A@B.C ")).toBe("a@b.c");
  });
});

describe("client IP and CORS", () => {
  it("uses the entry written by the trusted proxy, ignoring client-supplied values", () => {
    expect(pickClientIp("6.6.6.6, 203.0.113.9", 1)).toBe("203.0.113.9");
    expect(pickClientIp("203.0.113.9", 1)).toBe("203.0.113.9");
    expect(pickClientIp("1.1.1.1, 203.0.113.9, 10.0.0.1", 2)).toBe("203.0.113.9");
  });
  it("falls back to a shared bucket when it cannot be trusted", () => {
    expect(pickClientIp(null)).toBe("unknown");
    expect(pickClientIp("1.2.3.4", 2)).toBe("unknown");
    expect(pickClientIp("not-an-ip", 1)).toBe("unknown");
  });
  it("echoes only allow-listed origins", () => {
    const list = "https://aitu-space.lovable.app, http://localhost:5173";
    expect(allowedOrigin("https://aitu-space.lovable.app", list)).toBe("https://aitu-space.lovable.app");
    expect(allowedOrigin("https://evil.example", list)).toBeNull();
    expect(allowedOrigin(null, list)).toBeNull();
    expect(allowedOrigin("https://aitu-space.lovable.app", "")).toBeNull();
  });
});
