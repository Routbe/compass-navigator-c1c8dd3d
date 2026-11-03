import { useCallback, useEffect, useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { Loader2, Nfc } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { addMyPhysicalKey, listMyPhysicalKeys, setMyPhysicalKeyStatus } from "@/lib/wallet/wallet.functions";

type Keys = Awaited<ReturnType<typeof listMyPhysicalKeys>>;

/** NDEF record the card manufacturer writes with the secure element's public key. */
const KEY_RECORD = /^rout-pk:(Ed25519|P-256):([A-Za-z0-9_-]{40,200})$/;

type NdefReading = { serialNumber: string; message: { records: { recordType: string; data?: DataView; encoding?: string }[] } };
type NdefReaderLike = { scan: (o?: { signal?: AbortSignal }) => Promise<void>; onreading: ((e: NdefReading) => void) | null; onreadingerror: (() => void) | null };

/**
 * Physical ROUT keys: link a chip by tapping it (WebNFC on Android Chrome) or
 * by typing its UID (iOS has no WebNFC), then activate, freeze or revoke it.
 */
export function CardKeysPanel({ space }: { space?: "root" | "alias" }) {
  const list = useServerFn(listMyPhysicalKeys);
  const add = useServerFn(addMyPhysicalKey);
  const setStatus = useServerFn(setMyPhysicalKeyStatus);
  const [keys, setKeys] = useState<Keys | null>(null);
  const [scanning, setScanning] = useState(false);
  const [manual, setManual] = useState("");
  const [nfc, setNfc] = useState(false);

  const refresh = useCallback(() => {
    list().then(setKeys).catch(() => setKeys({ keys: [], available: false }));
  }, [list]);

  useEffect(() => {
    setNfc("NDEFReader" in window);
    refresh();
  }, [refresh]);

  const link = async (payload: { nfcUid: string; publicKey?: string; keyAlg?: "Ed25519" | "P-256" }) => {
    const r = await add({ data: { space, ...payload } });
    if (r.ok) {
      toast.success(payload.publicKey ? "Kaart gekoppeld. Activeer hem om te gebruiken." : "Chip gekoppeld (zonder beveiligde sleutel: alleen als ID-tag).");
      refresh();
    } else {
      toast.error(
        r.error === "duplicate" ? "Deze chip is al gekoppeld." : r.error === "unavailable" ? "Fysieke kaarten zijn nog niet ingesteld in de database." : r.error === "uid" ? "Ongeldige chip-ID." : "De chip gaf een ongeldige sleutel.",
      );
    }
  };

  const scan = async () => {
    const Reader = (window as unknown as { NDEFReader?: new () => NdefReaderLike }).NDEFReader;
    if (!Reader) return;
    const ctrl = new AbortController();
    setScanning(true);
    const stop = setTimeout(() => ctrl.abort(), 30_000);
    try {
      const reader = new Reader();
      reader.onreading = (e) => {
        ctrl.abort();
        let publicKey: string | undefined;
        let keyAlg: "Ed25519" | "P-256" | undefined;
        for (const rec of e.message.records) {
          if (rec.recordType !== "text" || !rec.data) continue;
          const m = KEY_RECORD.exec(new TextDecoder(rec.encoding || "utf-8").decode(rec.data));
          if (m) {
            keyAlg = m[1] as "Ed25519" | "P-256";
            publicKey = m[2];
          }
        }
        void link({ nfcUid: e.serialNumber, publicKey, keyAlg }).finally(() => setScanning(false));
      };
      reader.onreadingerror = () => toast.error("Kon de chip niet lezen. Houd de kaart stil tegen de achterkant van je telefoon.");
      await reader.scan({ signal: ctrl.signal });
    } catch {
      toast.error("NFC-toegang geweigerd of niet beschikbaar.");
      setScanning(false);
    } finally {
      clearTimeout(stop);
      ctrl.signal.addEventListener("abort", () => setScanning(false));
    }
  };

  const change = async (hardwareId: string, status: "active" | "frozen" | "revoked") => {
    if (status === "revoked" && !window.confirm("Definitief intrekken? Deze kaart kan daarna nooit meer gebruikt worden.")) return;
    const r = await setStatus({ data: { hardwareId, status } }).catch(() => ({ ok: false }));
    if (!r.ok) toast.error(status === "active" ? "Alleen een chip met beveiligde sleutel kan actief worden." : "Wijzigen lukt nu niet.");
    refresh();
  };

  return (
    <section className="grid gap-3 rounded-2xl border border-border p-3" aria-labelledby="rout-keys-title">
      <div className="flex items-center justify-between gap-2">
        <h3 id="rout-keys-title" className="flex items-center gap-1.5 text-sm font-semibold"><Nfc className="h-4 w-4" aria-hidden /> Fysieke kaarten</h3>
        {nfc && (
          <Button type="button" size="sm" variant="outline" onClick={() => void scan()} disabled={scanning || keys?.available === false}>
            {scanning ? <><Loader2 className="h-4 w-4 animate-spin" aria-hidden /> Tik je kaart…</> : "Nieuwe ROUT Card koppelen"}
          </Button>
        )}
      </div>
      {keys?.available === false && <p className="text-xs text-muted-foreground">Fysieke kaarten zijn nog niet ingesteld in de database.</p>}
      {keys?.available !== false && !nfc && (
        <form
          className="grid gap-1.5"
          onSubmit={(e) => {
            e.preventDefault();
            void link({ nfcUid: manual }).then(() => setManual(""));
          }}
        >
          <label htmlFor="rout-chip-uid" className="text-xs text-muted-foreground">Deze browser kan geen NFC lezen (bv. iPhone). Typ de chip-ID van het activatiebriefje:</label>
          <div className="flex gap-2">
            <Input id="rout-chip-uid" value={manual} onChange={(e) => setManual(e.target.value)} placeholder="04:A2:3B:1C:9D:80:00" className="h-9 font-mono text-xs" autoComplete="off" spellCheck={false} />
            <Button type="submit" size="sm" variant="outline" className="h-9" disabled={manual.replace(/[^0-9a-f]/gi, "").length < 8}>Koppel</Button>
          </div>
        </form>
      )}
      {keys === null ? (
        <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" aria-label="Laden" />
      ) : keys.keys.length > 0 ? (
        <ul className="grid gap-2">
          {keys.keys.map((k) => (
            <li key={k.hardware_id} className="flex items-center justify-between gap-2 rounded-xl border border-border p-2 text-xs">
              <span className="grid">
                <span className="font-mono">{k.nfc_uid ?? "—"}</span>
                <span className={cn("text-[11px]", k.status === "active" ? "text-primary" : k.status === "pending" ? "text-muted-foreground" : "text-destructive")}>
                  {{ pending: "Wacht op activatie", active: "Actief", frozen: "Bevroren", revoked: "Ingetrokken" }[k.status]}
                  {k.has_key ? ` · ${k.key_alg}` : " · geen sleutel"}
                </span>
              </span>
              {k.status !== "revoked" && (
                <span className="flex gap-1">
                  {k.status !== "active" && k.has_key && <Button type="button" size="sm" variant="outline" onClick={() => void change(k.hardware_id, "active")}>Activeer</Button>}
                  {k.status === "active" && <Button type="button" size="sm" variant="outline" onClick={() => void change(k.hardware_id, "frozen")}>Bevries</Button>}
                  <Button type="button" size="sm" variant="ghost" className="text-destructive" onClick={() => void change(k.hardware_id, "revoked")}>Intrekken</Button>
                </span>
              )}
            </li>
          ))}
        </ul>
      ) : (
        keys.available && <p className="text-xs text-muted-foreground">Nog geen fysieke kaart gekoppeld.</p>
      )}
    </section>
  );
}
