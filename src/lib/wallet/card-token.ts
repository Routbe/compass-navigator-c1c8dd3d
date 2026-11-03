/**
 * Secure QR token for the back of the ROUT Card. Pure, no I/O.
 *
 * Token = v1.<r|a>.<handle>.<window base36>.<live code>. The live code is the
 * HMAC from card-liveness, so the token cannot be forged without the server
 * key, and it expires with its 30 s window (one window of skew accepted).
 */
import { LIVE_CODE_LEN, LIVE_SKEW_WINDOWS, liveWindow } from "./card-liveness";

export type SecureToken = { space: "root" | "alias"; handle: string; window: number; code: string };

const HANDLE = /^[\w.-]{1,100}$/;
const CODE = new RegExp(`^[0-9A-HJKMNP-TV-Z]{${LIVE_CODE_LEN}}$`);

export function encodeSecureToken(t: SecureToken): string {
  if (!HANDLE.test(t.handle)) throw new Error("invalid handle");
  return `v1.${t.space === "alias" ? "a" : "r"}.${t.handle}.${t.window.toString(36)}.${t.code}`;
}

export function decodeSecureToken(raw: string): SecureToken | null {
  const parts = raw.trim().split(".");
  if (parts.length < 5 || parts[0] !== "v1") return null;
  const s = parts[1]!;
  const handle = parts.slice(2, -2).join(".");
  const [w, code] = parts.slice(-2) as [string, string];
  if ((s !== "r" && s !== "a") || !HANDLE.test(handle) || !CODE.test(code) || !/^[0-9a-z]{1,12}$/.test(w)) return null;
  const window = parseInt(w, 36);
  if (!Number.isSafeInteger(window)) return null;
  return { space: s === "a" ? "alias" : "root", handle, window, code };
}

/** True while the token's window is the current one or a direct neighbour. */
export function tokenFresh(t: SecureToken, nowMs: number): boolean {
  return Math.abs(liveWindow(nowMs) - t.window) <= LIVE_SKEW_WINDOWS;
}
