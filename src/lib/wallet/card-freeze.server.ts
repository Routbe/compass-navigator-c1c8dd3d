/**
 * ROUT Card database access: freeze (db/0198), CMF designs, single-use secure
 * QR nonces, physical keys and challenges (db/0199). Until a migration is
 * applied by the database owner, reads degrade (`available: false`) and
 * writes throw a 503-style error, so the card keeps working without them.
 */
import { sql } from "@/lib/neon";

export function missingSchema(err: unknown): boolean {
  const s = String((err as { message?: string })?.message ?? err);
  return /42P01|42883|card_freezes|card_designs|card_token_uses|physical_keys|hardware_challenges|rout_card_|rout_hw_/.test(s);
}

function notReady(): Error {
  return Object.assign(new Error("Card storage is not set up yet"), { statusCode: 503 });
}

export async function cardFrozen(serial: string): Promise<{ frozen: boolean; available: boolean }> {
  try {
    const rows = await sql.query("select public.rout_card_frozen($1) as f", [serial]);
    return { frozen: rows[0]?.f === true, available: true };
  } catch (err) {
    if (missingSchema(err)) return { frozen: false, available: false };
    throw err;
  }
}

/** Card frozen, or any physical key linked to it frozen/revoked. */
export async function cardStatus(serial: string): Promise<"active" | "frozen"> {
  try {
    const rows = await sql.query("select public.rout_card_status_by_serial($1) as s", [serial]);
    return rows[0]?.s === "frozen" ? "frozen" : "active";
  } catch (err) {
    if (!missingSchema(err)) throw err;
    return (await cardFrozen(serial)).frozen ? "frozen" : "active";
  }
}

/** Runs inside requireAuth's DB context, so RLS pins user_id to the caller. */
export async function setCardFrozen(serial: string, userId: string, frozen: boolean): Promise<void> {
  try {
    if (frozen) {
      await sql.query("insert into public.card_freezes (serial, user_id) values ($1, $2::uuid) on conflict (serial) do nothing", [serial, userId]);
    } else {
      await sql.query("delete from public.card_freezes where serial = $1", [serial]);
    }
  } catch (err) {
    if (missingSchema(err)) throw notReady();
    throw err;
  }
  // Linked physical keys follow the card (revoked keys stay revoked).
  try {
    await sql.query(
      frozen
        ? "update public.physical_keys set status = 'frozen' where card_serial = $1 and status = 'active'"
        : "update public.physical_keys set status = 'active' where card_serial = $1 and status = 'frozen' and public_key is not null",
      [serial],
    );
  } catch (err) {
    if (!missingSchema(err)) throw err;
  }
}

export async function readCardDesign(serial: string): Promise<Record<string, unknown> | null> {
  try {
    const rows = await sql.query("select public.rout_card_design($1) as d", [serial]);
    const d = rows[0]?.d;
    return d && typeof d === "object" ? (d as Record<string, unknown>) : null;
  } catch (err) {
    if (missingSchema(err)) return null;
    throw err;
  }
}

export async function saveCardDesign(serial: string, userId: string, cmf: unknown): Promise<void> {
  try {
    await sql.query(
      `insert into public.card_designs (serial, user_id, cmf, updated_at) values ($1, $2::uuid, $3::jsonb, now())
       on conflict (serial) do update set cmf = excluded.cmf, updated_at = now() where card_designs.user_id = excluded.user_id`,
      [serial, userId, JSON.stringify(cmf)],
    );
  } catch (err) {
    if (missingSchema(err)) throw notReady();
    throw err;
  }
}

/** Records a secure-QR nonce. true = first use; false = replay; null = table missing. */
export async function useTokenNonce(nonce: string, expMs: number): Promise<boolean | null> {
  try {
    const rows = await sql.query("select public.rout_card_token_use($1, $2::timestamptz) as ok", [nonce, new Date(expMs).toISOString()]);
    return rows[0]?.ok === true;
  } catch (err) {
    if (missingSchema(err)) return null;
    throw err;
  }
}

export type PhysicalKey = {
  hardware_id: string;
  label: string | null;
  nfc_uid: string | null;
  status: "pending" | "active" | "frozen" | "revoked";
  key_alg: string | null;
  has_key: boolean;
  issued_at: string;
  last_scanned_at: string | null;
};

export async function listMyKeys(): Promise<{ keys: PhysicalKey[]; available: boolean }> {
  try {
    const rows = await sql.query(
      `select hardware_id, label, nfc_uid, status, key_alg, public_key is not null as has_key, issued_at, last_scanned_at
         from public.physical_keys where user_id = public.rout_current_user_id() order by issued_at desc limit 20`,
    );
    return { keys: rows as PhysicalKey[], available: true };
  } catch (err) {
    if (missingSchema(err)) return { keys: [], available: false };
    throw err;
  }
}

export async function addMyKey(userId: string, k: { serial: string; label: string | null; nfcUid: string | null; publicKey: string | null; keyAlg: string | null }): Promise<string> {
  try {
    const rows = await sql.query(
      `insert into public.physical_keys (user_id, card_serial, label, nfc_uid, public_key, key_alg)
       values ($1::uuid, $2, $3, $4, $5, $6) returning hardware_id`,
      [userId, k.serial, k.label, k.nfcUid, k.publicKey, k.keyAlg],
    );
    return String(rows[0]?.hardware_id);
  } catch (err) {
    if (missingSchema(err)) throw notReady();
    if (/23505/.test(String((err as Error)?.message))) throw Object.assign(new Error("This chip is already linked"), { statusCode: 409 });
    throw err;
  }
}

export async function setMyKeyStatus(hardwareId: string, status: "active" | "frozen" | "revoked"): Promise<boolean> {
  try {
    const rows = await sql.query(
      `update public.physical_keys set status = $2
        where hardware_id = $1::uuid and user_id = public.rout_current_user_id()
          and status <> 'revoked' and ($2 <> 'active' or public_key is not null)
        returning hardware_id`,
      [hardwareId, status],
    );
    return rows.length > 0;
  } catch (err) {
    if (missingSchema(err)) throw notReady();
    throw err;
  }
}

export async function issueChallenge(hardwareId: string, nonceHash: string): Promise<boolean | null> {
  try {
    const rows = await sql.query("select public.rout_hw_issue_challenge($1::uuid, $2) as ok", [hardwareId, nonceHash]);
    return rows[0]?.ok === true;
  } catch (err) {
    if (missingSchema(err)) return null;
    throw err;
  }
}

export async function consumeChallenge(hardwareId: string, nonceHash: string): Promise<{ public_key: string; key_alg: string; status: string } | null> {
  const rows = await sql.query("select * from public.rout_hw_consume_challenge($1::uuid, $2)", [hardwareId, nonceHash]);
  const r = rows[0];
  return r && r.public_key ? (r as { public_key: string; key_alg: string; status: string }) : null;
}

export async function recordScan(hardwareId: string, ok: boolean): Promise<void> {
  await sql.query("select public.rout_hw_record_scan($1::uuid, $2)", [hardwareId, ok]).catch(() => undefined);
}
