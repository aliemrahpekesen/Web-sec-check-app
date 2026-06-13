# CLAUDE.md — SentinelScan

Repo için yönlendirme notları (Claude Code ve katkıda bulunanlar için).

## Ne bu?

Claude Opus 4.8 dinamik iş akışlarıyla çalışan, SaaS web güvenlik tarayıcısı. URL girilir →
arka planda (BullMQ worker) güvenlik denetimi koşar → Matrix tarzı canlı log akar → kritiklik
ve örnekli düzeltme içeren rapor üretilir.

## Komutlar

- `npm run dev` — Next.js geliştirme sunucusu
- `npm run worker` — BullMQ worker (taramaları işler; web sunucusundan AYRI süreç)
- `npm run build` — `prisma generate` + `next build`
- `npm run typecheck` — `tsc --noEmit`
- `npm run prisma:migrate` / `npm run db:seed`
- Altyapı: `docker compose up -d` (Postgres + Redis)

## Mimari kuralları

- **Worker paylaşımlı kod `server-only` import ETMEMELİDIR.** `src/lib/*` modülleri hem Next
  runtime hem standalone worker (tsx) tarafından kullanılır; `server-only` worker'da hata verir.
  Bu yüzden `src/lib/db.ts`, `env.ts`, `redis.ts` vb. framework-neutral'dır.
- **`@/` alias yalnızca Next tarafında** (app/, components/) kullanılır. Worker'dan ulaşılan
  modüller (`src/lib/**`, `src/worker/**`, `src/lib/ai/**`) **göreli import** kullanır.
- **AI ile etkileşim**: `src/lib/ai/orchestrator.ts`. Model `claude-opus-4-8`, adaptive thinking,
  **manual agentic tool-use loop** (canlı log için her araç çağrısını yayınlamak ve bulguları
  kontrollü kaydetmek üzere auto tool-runner yerine elle döngü). Yeni güvenlik kontrolü eklerken:
  1) analizörü `src/lib/scanner/analyzers.ts`'e ekle,
  2) açık bilgisini (severity/CWE/OWASP/örnekli remediation) `src/lib/scanner/knowledge.ts`'e ekle,
  3) deterministik hatta (`deterministic.ts`) bağla,
  4) AI için bir tool olarak `orchestrator.ts`'e tanımla (hem deterministik hem AI motoru aynı
     analizörü paylaşmalı ki bulgular tutarlı olsun).
- **Canlı akış**: `src/lib/events.ts` her olayı hem Postgres'e yazar hem Redis kanalına yayınlar;
  `src/app/api/scans/[id]/stream/route.ts` SSE ile (geçmiş tekrarı + canlı kuyruk) sunar.

## Güvenlik

- Aktif tarama (STANDARD/DEEP) alan adı doğrulaması ister (`src/lib/verify.ts`). PASSIVE istemez.
- SSRF koruması: özel/iç IP'ler `src/lib/url.ts`'te reddedilir.
- Bu bir savunma/yetkili-test aracıdır; intrusive testler kasıtlı olarak hafif ve zararsızdır
  (XSS probu benzersiz bir işaretleyici yansımasını arar, veri bozmaz).

## Yapılmayanlar (v1 kapsam dışı, altyapı hazır)

- Kimlik doğrulama / kullanıcı yönetimi (şema multi-tenant; `src/lib/org.ts` tek demo org döndürür).
- Ücretlendirme (Organization.plan/quota alanları mevcut; ölçüm sayacı artıyor).
