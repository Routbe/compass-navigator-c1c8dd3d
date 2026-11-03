/**
 * ROUT Card "Freeze" (db/0198). Until the migration is applied by the database
 * owner, reads report "not frozen" with `available: false` and freezing throws.
 */
import { sql } from "@/lib/neon";

function missing(err: unknown): boolean {
  const s = String((err as { message?: string })?.message ?? err);
  return /42P01|42883|card_freezes|rout_card_frozen/.test(s);
}

export async function cardFrozen(serial: string): Promise<{ frozen: boolean; available: boolean }> {
  try {
    const rows = await sql.query("select public.rout_card_frozen($1) as f", [serial]);
    return { frozen: rows[0]?.f === true, available: true };
  } catch (err) {
    if (missing(err)) return { frozen: false, available: false };
    throw err;
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
    if (missing(err)) throw Object.assign(new Error("Freeze is not set up yet"), { statusCode: 503 });
    throw err;
  }
}
