"use client";

import Link from "next/link";
import { useEffect } from "react";

export default function Error({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <main className="grid-bg flex min-h-screen flex-col items-center justify-center px-6 text-center">
      <div className="mb-2 font-mono text-xs uppercase tracking-[0.4em] text-sev-high">// hata</div>
      <h1 className="text-3xl font-bold text-matrix text-glow">Bir şeyler ters gitti</h1>
      <p className="mt-3 max-w-md font-mono text-sm text-matrix-dim">
        Beklenmeyen bir hata oluştu. Tekrar deneyebilir ya da ana sayfaya dönebilirsiniz.
      </p>
      <div className="mt-6 flex gap-3">
        <button
          onClick={reset}
          className="rounded-lg border border-matrix bg-matrix/10 px-5 py-2 font-mono text-sm text-matrix hover:bg-matrix/20"
        >
          Tekrar dene
        </button>
        <Link
          href="/"
          className="rounded-lg border border-matrix/30 px-5 py-2 font-mono text-sm text-matrix-dim hover:text-matrix"
        >
          Ana sayfa
        </Link>
      </div>
    </main>
  );
}
