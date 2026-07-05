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
başlık/TLS/çerez analizini yaptığı için doğrulama gerektirmez.

**Doğrulama token'ı** sunucu tarafı bir sırla (`SENTINEL_VERIFICATION_SECRET`) HMAC'lenir ve
sabit-zamanlı karşılaştırılır — genel girdilerden yeniden üretilemez. Prod'da bu sırrı mutlaka ayarlayın.

**SSRF koruması** (`src/lib/ssrf.ts`) her giden istekte uygulanır: host DNS ile çözülür ve çözülen
*tüm* IP'ler kontrol edilir; özel/iç aralıklar (RFC1918, loopback, link-local + bulut metadata
`169.254.169.254`, CGNAT, IPv6 ULA/mapped), ondalık/hex/oktal IP kodlamaları (`http://2130706433`)
ve **yönlendirme zincirinin her adımı** reddedilir. Stateless mod dahil tüm giriş noktaları bu kontrolü
çalıştırır.

**Kötüye kullanım kontrolü:** tarama/doğrulama uçlarında IP başına dakikalık **rate limit**
(`SENTINEL_RATE_LIMIT_PER_MIN`), her taramada istek + duvar-saati **zaman bütçesi** (serverless'ta
~55s içinde güvenle biter).

Yerel geliştirmede `SENTINEL_SKIP_VERIFICATION=true`, `SENTINEL_SCAN_ALLOWLIST=host1,host2` ya da
iç hedefler için `SENTINEL_ALLOW_PRIVATE_TARGETS=true` kullanın — yalnızca yetkili olduğunuz hedefler için.

## Kontrol Kataloğu (770+ kontrol)

Tarama motoru **katalog tabanlıdır** (`src/lib/scanner/checks/`): kanıt bir kez toplanır
(`evidence.ts` — kök yanıt, crawl, **derin TLS + protokol/şifre matris enumerasyonu**, DNS/e-posta,
**CNAME (subdomain takeover)**, HTTP metodları, CORS probu, **GraphQL introspection**, **robots.txt
madenciliği**, 470+ hassas-yol imzası ve 11 doğrulanmış aktif enjeksiyon probu), sonra **770'ten
fazla** bağımsız kontrol bu anlık görüntü üzerinde çalışır. Her kontrol:

- Yalnızca **somut kanıt** varsa bulgu üretir (yanlış-pozitif önleme testlerle güvence altında).
- **fail / pass / n-a** durumu döndürür; böylece rapor "kaç kontrol koştu, kaç geçti, kaç bulgu"
  **kapsamını** kategori kategori gösterir — kullanıcı raporun doğruluğuna güvenebilir.
- **Kanıt + güven seviyesi (confirmed/firm/tentative) + CWE/OWASP + referans bağlantıları** taşır.

Kategoriler: güvenlik başlıkları (70+), çerezler, TLS + **protokol/şifre matrisi**, kriptografi,
CSP kalitesi, CORS, bilgi/dosya ifşası (470+ yol imzası + robots.txt madenciliği), içerik & sır
sızıntısı, enjeksiyon (XSS/SQLi/NoSQLi/komut/LDAP/SSTI/LFI/CRLF/open-redirect/host-header/**SSRF-metadata**
— doğrulanmış), teknoloji parmak izi + sürüm CVE'leri, **subdomain takeover**, DNS & e-posta
(SPF/DKIM/DMARC/CAA/MTA-STS/TLS-RPT/BIMI), HTTP yapılandırması, kimlik/oturum, API yüzeyi +
**GraphQL introspection**, önbellek. Rapor **Markdown / JSON / HTML** olarak dışa aktarılır; kritiklik,
kategori ve metin filtreleriyle taranabilir. AI motoru (Opus 4.8) bu kataloğu **baz çizgi** olarak
koşturur, üzerine akıl yürütür — yani AI daima katalogun üst kümesidir.

## Denetlenen açıklar (özet)

Güvenlik başlıkları (HSTS, CSP + **CSP kalite analizi**, X-Frame-Options, X-Content-Type-Options,
Referrer/Permissions-Policy), çerez bayrakları (Secure/HttpOnly/SameSite + **SameSite=None-Secure**),
HTTPS zorlaması, TLS protokolü/sertifika süresi + **geçersiz/güvenilmeyen sertifika**, karışık içerik,
dizin listeleme, hassas dosya ifşası (.env/.git/yedek), sunucu sürüm ifşası, tehlikeli CORS, yansıyan XSS,
açık yönlendirme, eski/savunmasız kütüphaneler, **dış scriptlerde eksik SRI**, hassas yanıtta önbellek
kontrolü. Her bulgu CWE + OWASP eşlemesi ve **örnekli düzeltme** içerir (bkz. `src/lib/scanner/knowledge.ts`).

Uygulamanın kendisi de sıkı güvenlik header'ları uygular: nonce'lu CSP (`src/middleware.ts`) + HSTS,
X-Frame-Options, nosniff, Referrer/Permissions/COOP (`next.config.mjs`). Dogfood: `/.well-known/security.txt`.

## SaaS / ücretlendirme altyapısı

`Organization` (plan, aylık kota, kullanım sayacı), `ApiKey` (hash'li), `VerifiedDomain` modelleri
gelecekteki kimlik doğrulama ve ölçümlü ücretlendirme için hazırdır; v1'de auth/ödeme yoktur ve tüm
etkinlik tek bir demo organizasyonuna atfedilir (`src/lib/org.ts`).

## Dağıtım modları

SentinelScan iki modda çalışır:

- **Self-hosted (tam):** Postgres + Redis + ayrı worker. Kalıcı tarama geçmişi,
  çok kiracılı, ölçeklenebilir. Yukarıdaki "Hızlı başlangıç".
- **Stateless (serverless/Vercel):** Veritabanı/Redis/worker yok. Her tarama tek
  bir SSE isteğinin içinde koşar; loglar ve bulgular canlı akar, sonunda rapor
  üretilir; hiçbir şey kalıcılaştırılmaz. Vercel'de otomatik devreye girer
  (`VERCEL=1` + `DATABASE_URL` tanımsız). `ANTHROPIC_API_KEY` eklenirse AI motoru
  burada da çalışır. `SENTINEL_INLINE=true` ile zorlanabilir.

`.github/workflows/deploy.yml` her push'ta Vercel'e otomatik dağıtım yapar
(gerekli secret'lar dosyada belgelenmiştir).

## Test & CI

```bash
npm test        # Vitest birim testleri (SSRF, URL, analizörler, skorlama, doğrulama, rapor…)
npm run typecheck
npm run lint
```

`.github/workflows/ci.yml` her push/PR'da typecheck + lint + test + build çalıştırır.

## Rapor dışa aktarımı

Tarama sayfasında bulgular **Markdown** veya **JSON** olarak indirilebilir
(`src/lib/report.ts`; stateless modda tamamen istemci tarafında üretilir).

## Üretim notları

- Worker'ı `npm run worker:prod` ile çalıştırın; birden çok kopya başlatın.
- Sağlık kontrolü: `GET /api/health` (DB modlarında veritabanı bağlantısını da doğrular).
- `riskScore`/`grade` tamamlanınca hesaplanır (`src/lib/scanner/scoring.ts`).
- SSE bağlantısı koparsa tarayıcı yeniden bağlanır; sunucu geçmişi tekrarlar ve `seq` ile tekilleştirir.
