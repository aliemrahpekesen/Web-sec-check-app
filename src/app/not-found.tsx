import Link from "next/link";

export default function NotFound() {
  return (
    <main className="grid-bg flex min-h-screen flex-col items-center justify-center px-6 text-center">
      <div className="mb-2 font-mono text-xs uppercase tracking-[0.4em] text-matrix-dim">// 404</div>
      <h1 className="text-4xl font-bold text-matrix text-glow">Sayfa bulunamadı</h1>
      <p className="mt-3 font-mono text-sm text-matrix-dim">Aradığınız kaynak burada değil.</p>
      <Link
        href="/"
        className="mt-6 rounded-lg border border-matrix bg-matrix/10 px-5 py-2 font-mono text-sm text-matrix hover:bg-matrix/20"
      >
        ← Ana sayfa
      </Link>
    </main>
  );
}
