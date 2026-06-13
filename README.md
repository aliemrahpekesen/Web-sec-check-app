# SentinelScan 🛡️

> Claude Opus 4.8 **dinamik iş akışlarıyla** çalışan, kurumsal SaaS web uygulaması güvenlik tarayıcısı.
> Bir web adresi verin; alt sayfaları, formları, arka uç API çağrılarını ve yapılandırmayı uçtan uca
> denetler, bulguları **kritiklik seviyesi + örnekli düzeltme** ile raporlar. Tüm denetim arka plandaki
> job/worker'larda koşar; ekrana **Matrix tarzı canlı log** akar.

---

## Mimari

```
 Tarayıcı (futuristic UI)
   │  POST /api/scans            ┌──────────────┐
   ▼                              │  PostgreSQL  │  scans · findings · logs · orgs · domains
 Next.js (App Router) ──────────▶│  (Prisma)    │
   │  enqueue (BullMQ)            └──────────────┘
   ▼
 Redis ──────────────────────────┐
   │  job                         │ pub/sub (canlı log)
   ▼                              │
 Worker (src/worker)              │
   └─ runScan()                   │
        ├─ AI motoru: Claude Opus 4.8 dinamik iş akışı (manual agentic tool-use loop)
        │     araçlar: crawl_site, fetch_url, analyze_headers, analyze_tls,
        │     check_https_redirect, check_cors, scan_sensitive_paths,
        │     scan_libraries, probe_xss, probe_open_redirect, report_finding
        └─ Fallback: deterministik motor (aynı analizörler, sabit sıra)
                                   │
 Tarayıcı  ◀── SSE /stream ───────┘   (geçmiş tekrarı + canlı kuyruk)
```

**Dinamik iş akışı (Opus 4.8):** Sabit bir test sırası yoktur. Claude, `client.messages.create`
ile **manual agentic tool-use loop** içinde çalışır; hedefte ne gördüğüne göre bir sonraki güvenlik
aracını kendisi seçer (crawl → API/form keşfi → ilgili uçlarda prob → özgün sorunlar için akıl yürütme).
Her araç çağrısı canlı loga düşer, her bulgu anında kaydedilir. `ANTHROPIC_API_KEY` yoksa sistem
deterministik motora düşer ve yine tam çalışır.

## Teknolojiler

- **Next.js 14** (App Router, TS) — UI + API
- **PostgreSQL + Prisma** — çok kiracılı (multi-tenant) kalıcılık, billing-ready şema
- **Redis + BullMQ** — iş kuyruğu + canlı log pub/sub
- **`@anthropic-ai/sdk`** — Claude **Opus 4.8** (`claude-opus-4-8`), adaptive thinking, tool use
- **Tailwind** — Matrix temalı futuristic arayüz

## Hızlı başlangıç

```bash
# 1) Altyapı (Postgres + Redis)
docker compose up -d

# 2) Bağımlılıklar + ortam
npm install
cp .env.example .env
#   .env içine isteğe bağlı ANTHROPIC_API_KEY ekleyin (AI motoru için)
#   Yerel test için aktif tarama doğrulamasını atlamak isterseniz:
#     SENTINEL_SKIP_VERIFICATION=true

# 3) Veritabanı şeması (repo başlangıç migration'ını içerir)
npm run prisma:deploy    # migration'ları uygular
npm run db:seed

# 4) İki süreç (iki terminal):
npm run dev              # Next.js  → http://localhost:3000
npm run worker           # BullMQ worker (taramaları işler)
```

> **Not:** Web sunucusu ve worker ayrı süreçlerdir. Yüksek trafik için worker'ı yatay
> ölçekleyin (`SENTINEL_WORKER_CONCURRENCY` ve birden çok worker süreci).

## Güvenlik & yetki modeli

Aktif tarama (STANDARD/DEEP profilleri) gerçek hedefe istek attığı için **alan adı sahipliği
doğrulaması** zorunludur:

- **DNS TXT:** `sentinel-site-verification=<token>`
- **Dosya:** `https://<host>/.well-known/sentinel-verification.txt` içinde token

Doğrulama akışı arayüzde otomatik sunulur. **PASSIVE** profil yalnızca verilen URL'nin
başlık/TLS/çerez analizini yaptığı için doğrulama gerektirmez. Özel/iç ağ adresleri (SSRF) reddedilir.
Yerel geliştirmede `SENTINEL_SKIP_VERIFICATION=true` veya `SENTINEL_SCAN_ALLOWLIST=host1,host2`
kullanın — yalnızca yetkili olduğunuz hedefler için.

## Denetlenen açıklar (özet)

Güvenlik başlıkları (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer/Permissions-Policy),
çerez bayrakları, HTTPS zorlaması, TLS/sertifika, karışık içerik, dizin listeleme, hassas dosya ifşası
(.env/.git/yedek), sunucu sürüm ifşası, tehlikeli CORS, yansıyan XSS, açık yönlendirme, eski/savunmasız
kütüphaneler. Her bulgu CWE + OWASP eşlemesi ve **örnekli düzeltme** içerir (bkz.
`src/lib/scanner/knowledge.ts`).

## SaaS / ücretlendirme altyapısı

`Organization` (plan, aylık kota, kullanım sayacı), `ApiKey` (hash'li), `VerifiedDomain` modelleri
gelecekteki kimlik doğrulama ve ölçümlü ücretlendirme için hazırdır; v1'de auth/ödeme yoktur ve tüm
etkinlik tek bir demo organizasyonuna atfedilir (`src/lib/org.ts`).

## Üretim notları

- Worker'ı `npm run worker:prod` ile çalıştırın; birden çok kopya başlatın.
- `riskScore`/`grade` tamamlanınca hesaplanır (`src/lib/scanner/scoring.ts`).
- SSE bağlantısı koparsa tarayıcı yeniden bağlanır; sunucu geçmişi tekrarlar ve `seq` ile tekilleştirir.
