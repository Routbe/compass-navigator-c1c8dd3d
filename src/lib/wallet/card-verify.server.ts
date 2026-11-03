/**
 * Shared secure-QR verification for the /kaart page and /api/card/verify.
 * Order: signature + 60 s TTL → card exists → freeze kill-switch → single-use
 * nonce. A success reveals only status, display name and avatar.
 */
export type SecureVerdict =
  | { status: "valid"; display_name: string; avatar_url: string | null; replay_protected: boolean }
  | { status: "invalid" | "expired" | "replayed" | "frozen" };

export function verdictHttpStatus(v: SecureVerdict): number {
  return v.status === "valid" ? 200 : v.status === "frozen" ? 403 : 401;
}

export async function verifySecureCardTokenCore(token: string): Promise<SecureVerdict> {
  const { livenessKey } = await import("./card-liveness.server");
  const { verifySecureToken } = await import("./card-token");
  const r = await verifySecureToken(await livenessKey(), token, Date.now());
  if (!r.ok) return { status: r.reason };
  const { generateWalletPayload } = await import("./wallet-payload.server");
  const card = await generateWalletPayload(r.payload.h, { space: r.payload.s === "a" ? "alias" : "root" });
  if (!card) return { status: "invalid" };
  const { cardStatus, useTokenNonce } = await import("./card-freeze.server");
  if ((await cardStatus(card.serial)) === "frozen") return { status: "frozen" };
  const first = await useTokenNonce(r.payload.n, r.payload.exp);
  if (first === false) return { status: "replayed" };
  return { status: "valid", display_name: card.displayName, avatar_url: card.heroImageUrl, replay_protected: first === true };
}
