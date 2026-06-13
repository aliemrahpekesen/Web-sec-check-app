"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

type Profile = "PASSIVE" | "STANDARD" | "DEEP";

interface VerificationInfo {
  host: string;
  token: string;
  instructions: { dns: string; file: string };
}

const PROFILES: { id: Profile; label: string; desc: string }[] = [
  { id: "PASSIVE", label: "Pasif", desc: "Sadece başlık/TLS/çerez analizi · doğrulama gerekmez" },
  { id: "STANDARD", label: "Standart", desc: "Crawl + hafif aktif testler · doğrulama gerekir" },
  { id: "DEEP", label: "Derin", desc: "Geniş crawl + daha çok prob · doğrulama gerekir" },
];

export function ScanLauncher() {
  const router = useRouter();
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState<Profile>("STANDARD");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [verify, setVerify] = useState<VerificationInfo | null>(null);
  const [verifyMsg, setVerifyMsg] = useState<string | null>(null);

  async function launch(e?: React.FormEvent) {
    e?.preventDefault();
    setError(null);
    setVerify(null);
    setLoading(true);
    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, profile }),
      });
      const data = await res.json();
      if (res.status === 201) {
        router.push(`/scan/${data.id}`);
        return;
      }
      if (res.status === 412 && data.error === "verification_required") {
        // Fetch full token + instructions.
        const v = await fetch("/api/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ host: data.host }),
        }).then((r) => r.json());
        setVerify(v);
        return;
      }
      setError(data.message || data.error || "Tarama başlatılamadı.");
    } catch {
      setError("Ağ hatası. API erişilebilir mi?");
    } finally {
      setLoading(false);
    }
  }

  async function checkVerification() {
    if (!verify) return;
    setVerifyMsg("Doğrulanıyor…");
    const res = await fetch("/api/verify", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ host: verify.host }),
    }).then((r) => r.json());
    if (res.verified) {
      setVerifyMsg("✓ Doğrulandı! Tarama başlatılıyor…");
      setVerify(null);
      await launch();
    } else {
      setVerifyMsg(`✗ ${res.detail}`);
    }
  }

  return (
    <div className="w-full max-w-2xl">
      <form onSubmit={launch} className="glass rounded-xl p-5 shadow-glow">
        <label className="mb-2 block font-mono text-xs uppercase tracking-widest text-matrix-dim">
          Hedef URL
        </label>
        <div className="flex flex-col gap-3 sm:flex-row">
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://example.com"
            spellCheck={false}
            className="flex-1 rounded-lg border border-matrix/25 bg-black/40 px-4 py-3 font-mono text-matrix outline-none placeholder:text-matrix-dim/60 focus:border-matrix focus:shadow-glow"
          />
          <button
            type="submit"
            disabled={loading || target.trim().length < 3}
            className="rounded-lg border border-matrix bg-matrix/10 px-6 py-3 font-mono font-semibold uppercase tracking-wider text-matrix transition hover:bg-matrix/20 hover:shadow-glow-strong disabled:cursor-not-allowed disabled:opacity-40"
          >
            {loading ? "Başlatılıyor…" : "▶ Tara"}
          </button>
        </div>

        <div className="mt-4 grid grid-cols-1 gap-2 sm:grid-cols-3">
          {PROFILES.map((p) => (
            <button
              type="button"
              key={p.id}
              onClick={() => setProfile(p.id)}
              className={`rounded-lg border px-3 py-2 text-left transition ${
                profile === p.id
                  ? "border-matrix bg-matrix/10 shadow-glow"
                  : "border-matrix/15 bg-black/20 hover:border-matrix/40"
              }`}
            >
              <div className="font-mono text-sm font-semibold text-matrix">{p.label}</div>
              <div className="text-[11px] leading-tight text-matrix-dim">{p.desc}</div>
            </button>
          ))}
        </div>
      </form>

      {error && (
        <div className="mt-4 rounded-lg border border-sev-high/40 bg-sev-high/10 p-3 font-mono text-sm text-sev-high">
          {error}
        </div>
      )}

      {verify && (
        <div className="mt-4 animate-fade-in rounded-xl border border-sev-medium/40 bg-sev-medium/5 p-5">
          <div className="mb-2 font-mono text-sm font-semibold text-sev-medium">
            🔐 Alan adı sahipliği doğrulaması gerekiyor — {verify.host}
          </div>
          <p className="mb-3 text-sm text-matrix-dim">
            Aktif tarama yalnızca sahibi olduğunuz alan adlarında çalışır. Aşağıdaki kanıtlardan birini
            uygulayın, sonra «Doğrula» deyin. (Yerel testte{" "}
            <code className="text-matrix">SENTINEL_SKIP_VERIFICATION=true</code> ile atlayabilirsiniz.)
          </p>
          <div className="space-y-2 font-mono text-xs">
            <div className="rounded bg-black/40 p-3">
              <div className="text-matrix-dim">A) DNS TXT kaydı:</div>
              <div className="break-all text-matrix">{verify.instructions.dns}</div>
            </div>
            <div className="rounded bg-black/40 p-3">
              <div className="text-matrix-dim">B) Dosya yöntemi:</div>
              <div className="whitespace-pre-wrap break-all text-matrix">{verify.instructions.file}</div>
            </div>
          </div>
          <div className="mt-3 flex items-center gap-3">
            <button
              onClick={checkVerification}
              className="rounded-lg border border-matrix bg-matrix/10 px-4 py-2 font-mono text-sm text-matrix hover:bg-matrix/20"
            >
              Doğrula ve tara
            </button>
            <button
              onClick={() => {
                setProfile("PASSIVE");
                setVerify(null);
                setTimeout(() => launch(), 0);
              }}
              className="font-mono text-sm text-matrix-dim underline hover:text-matrix"
            >
              Bunun yerine PASSIVE tara
            </button>
            {verifyMsg && <span className="font-mono text-xs text-matrix-dim">{verifyMsg}</span>}
          </div>
        </div>
      )}
    </div>
  );
}
