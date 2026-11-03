import { describe, expect, it } from "vitest";
import { decodeSecureToken, encodeSecureToken, tokenFresh } from "./card-token";
import { LIVE_WINDOW_S } from "./card-liveness";

describe("secure card token", () => {
  it("round-trips", () => {
    const t = { space: "alias" as const, handle: "le.na", window: 58_000_123, code: "AB12CD" };
    expect(decodeSecureToken(encodeSecureToken(t))).toEqual(t);
  });
  it("rejects tampered tokens", () => {
    expect(decodeSecureToken("v1.x.lena.abc.AB12CD")).toBeNull();
    expect(decodeSecureToken("v1.r.lena.abc.AB12C")).toBeNull();
    expect(decodeSecureToken("v1.r.le/na.abc.AB12CD")).toBeNull();
    expect(decodeSecureToken("v2.r.lena.abc.AB12CD")).toBeNull();
  });
  it("expires after the neighbouring window (max 90 s)", () => {
    const now = 1_800_000_000_000;
    const w = Math.floor(now / 1000 / LIVE_WINDOW_S);
    const t = { space: "root" as const, handle: "lena", window: w, code: "AB12CD" };
    expect(tokenFresh(t, now + LIVE_WINDOW_S * 1000)).toBe(true);
    expect(tokenFresh(t, now + 2 * LIVE_WINDOW_S * 1000)).toBe(false);
  });
});
