import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { optionalAuth } from "@/lib/auth/middleware";

/** Public: which wallets can issue passes right now (booleans only, never config values). */
export const getWalletStatus = createServerFn({ method: "GET" }).handler(async () => {
  const { walletStatus } = await import("./wallet-pass");
  const { isPlatformFeatureEnabled } = await import("@/lib/platform-features.server");
  // An admin pause switches both wallets off; the 3D card and vCard stay available.
  if (!(await isPlatformFeatureEnabled("wallet"))) return { apple: false, google: false };
  return walletStatus(process.env as Record<string, string | undefined>);
});

/** Public: the ROUT Card payload for the 3D card (public profile data only). */
export const getWalletCard = createServerFn({ method: "GET" })
  .inputValidator((d: unknown) => z.object({ handle: z.string().trim().min(1).max(100).regex(/^@?[\w.-]+$/), space: z.enum(["root", "alias"]).optional() }).parse(d))
  .handler(async ({ data }) => {
    const { generateWalletPayload, walletOrigin } = await import("./wallet-payload.server");
    const card = await generateWalletPayload(data.handle, { space: data.space });
    if (!card) return null;
    const base = walletOrigin();
    // Same-origin path for drawing the photo on a canvas without CORS taint.
    const avatarPath = card.heroImageUrl?.startsWith(base) ? card.heroImageUrl.slice(base.length) : null;
    const { pickCardView } = await import("./card-liveness");
    // Allowlist, not a spread: only public card fields ever leave the server here.
    return pickCardView({ ...card, avatarPath });
  });

const cardRef = z.object({ handle: z.string().trim().min(1).max(100).regex(/^@?[\w.-]+$/), space: z.enum(["root", "alias"]).optional() });

/**
 * Liveness for the 3D card. Everyone gets the per-window shader seed; only the
 * signed-in owner of this exact card gets the rotating live code.
 */
export const getCardLiveness = createServerFn({ method: "POST" })
  .middleware([optionalAuth])
  .inputValidator((d: unknown) => cardRef.parse(d))
  .handler(async ({ data, context }) => {
    const { generateWalletPayload } = await import("./wallet-payload.server");
    const { livenessKey } = await import("./card-liveness.server");
    const { liveCode, liveSeed, liveWindow, LIVE_WINDOW_S } = await import("./card-liveness");
    const card = await generateWalletPayload(data.handle, { space: data.space });
    if (!card) return null;
    const key = await livenessKey();
    const now = Date.now();
    const w = liveWindow(now);
    let owner = false;
    if (context.userId) {
      const own = await generateWalletPayload(context.userId, { space: card.space, allowAccountId: true });
      owner = own?.serial === card.serial;
    }
    return {
      window: w,
      expiresAt: (w + 1) * LIVE_WINDOW_S * 1000,
      serverNow: now,
      seed: await liveSeed(key, card.serial, w),
      code: owner ? await liveCode(key, card.serial, w) : null,
      secureUrl: owner ? await secureUrlFor(card.handle, card.space, w, await liveCode(key, card.serial, w)) : null,
    };
  });

async function secureUrlFor(handle: string, space: "root" | "alias", window: number, code: string): Promise<string> {
  const { walletOrigin } = await import("./wallet-payload.server");
  const { encodeSecureToken } = await import("./card-token");
  return `${walletOrigin()}/kaart/${encodeSecureToken({ handle: handle.replace(/^@/, ""), space, window, code })}`;
}

/** Public: check a secure QR from the back of a card. Expires with its window; rate limited. */
export const verifySecureCardToken = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ token: z.string().trim().min(10).max(200) }).parse(d))
  .handler(async ({ data }) => {
    const { decodeSecureToken, tokenFresh } = await import("./card-token");
    const t = decodeSecureToken(data.token);
    if (!t) return { status: "invalid" as const };
    const { getRequest } = await import("@tanstack/react-start/server");
    const { hitRateLimit, clientIp } = await import("@/lib/rate-limit-db.server");
    const limit = await hitRateLimit("card-secure-verify", clientIp(getRequest()), { limit: 20, windowSec: 300 }, { failClosed: true });
    if (!limit.ok) return { status: "limited" as const };
    if (!tokenFresh(t, Date.now())) return { status: "expired" as const };
    const { generateWalletPayload } = await import("./wallet-payload.server");
    const { livenessKey } = await import("./card-liveness.server");
    const { liveCode } = await import("./card-liveness");
    const card = await generateWalletPayload(t.handle, { space: t.space });
    if (!card) return { status: "invalid" as const };
    const expected = await liveCode(await livenessKey(), card.serial, t.window);
    let d = expected.length ^ t.code.length;
    for (let i = 0; i < expected.length; i++) d |= expected.charCodeAt(i) ^ (t.code.charCodeAt(i) || 0);
    if (d !== 0) return { status: "invalid" as const };
    return { status: "valid" as const, handle: card.handle, displayName: card.displayName, sovereignId: card.sovereignId, url: card.url };
  });

/** Public: check a code a card holder shows you. Rate limited per visitor. */
export const verifyCardLiveCode = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => cardRef.extend({ code: z.string().trim().min(4).max(12) }).parse(d))
  .handler(async ({ data }) => {
    const { getRequest } = await import("@tanstack/react-start/server");
    const { hitRateLimit, clientIp } = await import("@/lib/rate-limit-db.server");
    const limit = await hitRateLimit("card-live-verify", clientIp(getRequest()), { limit: 10, windowSec: 300 }, { failClosed: true });
    if (!limit.ok) return { valid: false, limited: true };
    const { generateWalletPayload } = await import("./wallet-payload.server");
    const { livenessKey } = await import("./card-liveness.server");
    const { verifyLiveCode } = await import("./card-liveness");
    const card = await generateWalletPayload(data.handle, { space: data.space });
    if (!card) return { valid: false, limited: false };
    return { valid: await verifyLiveCode(await livenessKey(), card.serial, data.code, Date.now()), limited: false };
  });
