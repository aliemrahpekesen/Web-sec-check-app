import { MatrixRain } from "@/components/MatrixRain";
import { ScanLauncher } from "@/components/ScanLauncher";
import { RecentScans } from "@/components/RecentScans";
import { aiEnabled } from "@/lib/env";

export const dynamic = "force-dynamic";

export default function HomePage() {
  const ai = aiEnabled();
  return (
    <main className="relative min-h-screen overflow-hidden grid-bg">
      <MatrixRain opacity={0.16} />

      <div className="relative z-10 mx-auto flex min-h-screen max-w-5xl flex-col items-center px-6 py-16">
        <div className="mb-2 font-mono text-xs uppercase tracking-[0.4em] text-matrix-dim">
          // SentinelScan
        </div>
        <h1 className="text-center text-4xl font-bold tracking-tight text-matrix text-glow sm:text-6xl">
          Web Güvenlik Denetleyici
        </h1>
        <p className="mt-4 max-w-2xl text-center text-matrix-dim">
          Bir web adresi verin; alt sayfaları, formları, arka uç API çağrılarını ve yapılandırmayı
          uçtan uca denetleyelim. Bulguları kritiklik seviyesi ve <em>nasıl düzeltileceği örnekleriyle</em>{" "}
          raporlayalım.
        </p>

        <div
          className={`mt-3 inline-flex items-center gap-2 rounded-full border px-3 py-1 font-mono text-xs ${
            ai
              ? "border-matrix/40 bg-matrix/10 text-matrix"
              : "border-sev-medium/40 bg-sev-medium/10 text-sev-medium"
          }`}
        >
          <span className="h-1.5 w-1.5 animate-flicker rounded-full bg-current" />
          {ai
            ? "Motor: Claude Opus 4.8 dinamik iş akışı — etkin"
            : "Motor: deterministik (ANTHROPIC_API_KEY ayarlayın → AI orkestratör)"}
        </div>

        <div className="mt-10 flex w-full flex-col items-center">
          <ScanLauncher />
          <RecentScans />
        </div>

        <div className="mt-16 grid w-full max-w-4xl grid-cols-1 gap-4 sm:grid-cols-3">
          {[
            {
              t: "Dinamik iş akışı",
              d: "Claude Opus 4.8, hedefte ne bulduğuna göre hangi testi çalıştıracağına kendisi karar verir.",
            },
            {
              t: "Canlı Matrix akışı",
              d: "Denetim arka planda job'larda koşar; ekrana anlamlı log akışı düşer.",
            },
            {
              t: "Eyleme dönük rapor",
              d: "Her bulgu için kritiklik, kanıt, CWE/OWASP ve örnekli düzeltme.",
            },
          ].map((c) => (
            <div key={c.t} className="glass rounded-xl p-4">
              <div className="font-mono text-sm font-semibold text-matrix">{c.t}</div>
              <div className="mt-1 text-sm text-matrix-dim">{c.d}</div>
            </div>
          ))}
        </div>

        <footer className="mt-auto pt-16 text-center font-mono text-xs text-matrix-dim/60">
          Yalnızca yetkili güvenlik testleri için. Sahibi olmadığınız sistemleri taramayın.
        </footer>
      </div>
    </main>
  );
}
