// Zero-infrastructure local launcher for SentinelScan.
//
// Runs the app in *stateless* mode (SENTINEL_INLINE=true, no DATABASE_URL):
// every scan executes inside its own request and streams live — no PostgreSQL,
// no Redis, no separate worker process. This is the one-command way to run the
// product locally.
//
//   npm run dev:local     # hot-reload dev server  → http://localhost:3000
//   npm run start:local   # production build server (run `npm run build` first)
//
// Cross-platform: spawns Next's own bin with Node, so no shell-specific env
// syntax and no extra dependencies (works on Windows / macOS / Linux).
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { existsSync } from "node:fs";

const mode = process.argv[2] === "start" ? "start" : "dev";
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const nextBin = resolve(root, "node_modules", "next", "dist", "bin", "next");

if (!existsSync(nextBin)) {
  console.error("\n✗ Bağımlılıklar kurulu değil. Önce şunu çalıştırın:  npm install\n");
  process.exit(1);
}

// Force stateless mode. process.env values take precedence over .env files in
// Next's loader, so this cleanly overrides any DATABASE_URL a user may have set.
const env = { ...process.env, SENTINEL_INLINE: "true", DATABASE_URL: "" };

const ai = (process.env.ANTHROPIC_API_KEY ?? "").trim().length > 0;
const port = process.env.PORT || "3000";
console.log(
  [
    "",
    "  🛡️  SentinelScan — LOKAL (stateless) mod",
    "  ────────────────────────────────────────────",
    `  • URL:     http://localhost:${port}`,
    "  • Depolama: yok (DB/Redis/worker gerekmez — her tarama canlı akar)",
    `  • Motor:    ${ai ? "Claude Opus 4.8 (AI) — ANTHROPIC_API_KEY algılandı" : "deterministik (774 kontrol) — AI için ANTHROPIC_API_KEY set edin"}`,
    "  • İç ağ:    varsayılan kapalı (SENTINEL_ALLOW_PRIVATE_TARGETS=true ile localhost/iç hedef taranabilir)",
    "",
  ].join("\n"),
);

const child = spawn(process.execPath, [nextBin, mode], { stdio: "inherit", env, cwd: root });
child.on("exit", (code) => process.exit(code ?? 0));
child.on("error", (e) => {
  console.error("✗ Başlatılamadı:", e.message);
  process.exit(1);
});
