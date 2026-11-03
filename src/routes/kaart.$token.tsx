import { createFileRoute, Link } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useEffect, useState } from "react";
import { Loader2, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import { verifySecureCardToken } from "@/lib/wallet/wallet.functions";

export const Route = createFileRoute("/kaart/$token")({
  head: () => ({
    meta: [
      { title: "ROUT Card controle · ROUT" },
      { name: "description", content: "Controleer of een ROUT Card echt is en of de beveiligde QR-code nu geldig is." },
      { name: "robots", content: "noindex" },
      { property: "og:title", content: "ROUT Card controle" },
      { property: "og:description", content: "Echtheidscontrole van een beveiligde ROUT Card QR-code." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: VerifyCard,
});

type Result = Awaited<ReturnType<typeof verifySecureCardToken>>;

function VerifyCard() {
  const { token } = Route.useParams();
  const verify = useServerFn(verifySecureCardToken);
  const [r, setR] = useState<Result | null>(null);

  // Checked on open only (never during SSR), so a link preview cannot burn the window.
  useEffect(() => {
    verify({ data: { token } }).then(setR).catch(() => setR({ status: "invalid" }));
  }, [token, verify]);

  return (
    <main className="mx-auto flex min-h-[70vh] max-w-md flex-col items-center justify-center gap-4 p-6 text-center">
      {!r ? (
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" aria-label="Controleren" />
      ) : r.status === "valid" ? (
        <>
          <ShieldCheck className="h-14 w-14 text-primary" aria-hidden />
          <h1 className="text-2xl font-bold">Echte ROUT Card</h1>
          <p className="text-muted-foreground">Deze code is nu geldig en komt van de kaarthouder.</p>
          <div className="flex w-full items-center gap-3 rounded-2xl border border-border p-4 text-left">
            {r.avatar_url && <img src={r.avatar_url} alt="" className="h-12 w-12 rounded-full object-cover" />}
            <p className="text-lg font-semibold">{r.display_name}</p>
          </div>
        </>
      ) : r.status === "expired" || r.status === "replayed" ? (
        <>
          <ShieldAlert className="h-14 w-14 text-destructive" aria-hidden />
          <h1 className="text-2xl font-bold">{r.status === "replayed" ? "Code al gebruikt" : "Code verlopen"}</h1>
          <p className="text-muted-foreground">Deze beveiligde QR-code is ouder dan een minuut. Vraag de kaarthouder om de kaart opnieuw te tonen.</p>
        </>
      ) : r.status === "frozen" ? (
        <>
          <ShieldX className="h-14 w-14 text-destructive" aria-hidden />
          <h1 className="text-2xl font-bold">Kaart bevroren</h1>
          <p className="text-muted-foreground">De eigenaar heeft deze kaart geblokkeerd, bijvoorbeeld na verlies of diefstal. Vertrouw hem niet.</p>
        </>
      ) : r.status === "limited" ? (
        <>
          <ShieldAlert className="h-14 w-14 text-muted-foreground" aria-hidden />
          <h1 className="text-2xl font-bold">Even wachten</h1>
          <p className="text-muted-foreground">Te veel controles vanaf dit toestel. Probeer het over enkele minuten opnieuw.</p>
        </>
      ) : (
        <>
          <ShieldX className="h-14 w-14 text-destructive" aria-hidden />
          <h1 className="text-2xl font-bold">Niet echt</h1>
          <p className="text-muted-foreground">Deze code is ongeldig. De kaart kan nagemaakt of gekopieerd zijn.</p>
        </>
      )}
      <Link to="/" className="mt-4 text-xs text-muted-foreground hover:text-foreground">ROUT</Link>
    </main>
  );
}
