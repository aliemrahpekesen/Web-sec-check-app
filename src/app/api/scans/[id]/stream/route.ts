import { prisma } from "@/lib/db";
import { env, stateless } from "@/lib/env";
import { statelessEmitter } from "@/lib/events";
import { createSubscriber, scanChannel } from "@/lib/redis";
import { runScan, runScanStateless } from "@/lib/scanner/run";
import { decodeScanId } from "@/lib/scanid";
import { isLikelyPrivate } from "@/lib/url";
import { assertPublicHost } from "@/lib/ssrf";
import type { LiveEvent, LogLevel, ScanProfile } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
// Serverless: the scan runs inline inside this request, so give it room.
export const maxDuration = 60;

// GET /api/scans/:id/stream — Server-Sent Events feed of the live scan log.
// Replays persisted logs first (so late/reconnecting viewers see history), then:
//   • self-hosted: tails the Redis pub/sub channel until the scan finishes;
//   • serverless (Vercel): claims a QUEUED scan, runs it inline, and fans out
//     the log by polling Postgres (no Redis/worker).
export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const scanId = params.id;
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      let lastSeq = -1;
      const send = (event: Partial<LiveEvent>) => {
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
        } catch {
          /* controller closed */
        }
      };
      // ----- Stateless demo: decode id, run inline, stream directly -----
      if (stateless()) {
        const p = decodeScanId(scanId);
        if (!p) {
          send({ type: "done", status: "FAILED", message: "Geçersiz tarama kimliği" });
          controller.close();
          return;
        }
        // The scan id is attacker-controllable, so re-validate the target here
        // (the POST-time SSRF check is bypassed when the id is hand-crafted).
        if (isLikelyPrivate(p.host)) {
          send({ type: "done", status: "FAILED", message: "Özel/iç ağ adresleri taranamaz (SSRF koruması)." });
          controller.close();
          return;
        }
        try {
          await assertPublicHost(p.host);
        } catch (e) {
          send({ type: "done", status: "FAILED", message: e instanceof Error ? e.message : "Hedef doğrulanamadı" });
          controller.close();
          return;
        }
        const hb = setInterval(() => {
          try {
            controller.enqueue(encoder.encode(`: ping\n\n`));
          } catch {
            /* closed */
          }
        }, 15_000);
        const emit = statelessEmitter((e) => send(e));
        try {
          await runScanStateless(p.target, p.host, p.profile, emit);
        } finally {
          clearInterval(hb);
          try {
            controller.close();
          } catch {
            /* ignore */
          }
        }
        return;
      }

      const sendLog = (log: { seq: number; at: Date; level: string; message: string }) => {
        send({
          type: "log",
          seq: log.seq,
          at: log.at.toISOString(),
          level: log.level as LogLevel,
          message: log.message,
        });
        if (log.seq > lastSeq) lastSeq = log.seq;
      };

      // 1. Replay history.
      const scan = await prisma.scan.findUnique({
        where: { id: scanId },
        include: { logs: { orderBy: { seq: "asc" } } },
      });
      if (!scan) {
        send({ type: "done", status: "FAILED", message: "Tarama bulunamadı" });
        controller.close();
        return;
      }
      for (const log of scan.logs) sendLog(log);

      const terminal = (s: string) => ["COMPLETED", "FAILED", "CANCELLED"].includes(s);
      if (terminal(scan.status)) {
        send({
          type: "done",
          status: scan.status,
          riskScore: scan.riskScore ?? undefined,
          grade: scan.grade ?? undefined,
        });
        controller.close();
        return;
      }

      // ----- Serverless: run inline + poll Postgres -----
      if (env.serverless) {
        // Atomically claim a QUEUED scan so only one connection runs it.
        const claim = await prisma.scan.updateMany({
          where: { id: scanId, status: "QUEUED" },
          data: { status: "RUNNING", startedAt: new Date() },
        });
        if (claim.count === 1) {
          void runScan({
            scanId,
            target: scan.target,
            host: scan.host,
            profile: scan.profile as ScanProfile,
          });
        }

        let closed = false;
        const cleanup = () => {
          if (closed) return;
          closed = true;
          clearInterval(poll);
          clearInterval(heartbeat);
          try {
            controller.close();
          } catch {
            /* ignore */
          }
        };

        const poll = setInterval(async () => {
          try {
            const logs = await prisma.scanLog.findMany({
              where: { scanId, seq: { gt: lastSeq } },
              orderBy: { seq: "asc" },
            });
            for (const log of logs) sendLog(log);

            const fresh = await prisma.scan.findUnique({
              where: { id: scanId },
              select: { status: true, riskScore: true, grade: true },
            });
            if (fresh && terminal(fresh.status)) {
              send({
                type: "done",
                status: fresh.status,
                riskScore: fresh.riskScore ?? undefined,
                grade: fresh.grade ?? undefined,
              });
              cleanup();
            }
          } catch {
            /* transient DB hiccup; next tick retries */
          }
        }, 1000);

        const heartbeat = setInterval(() => {
          try {
            controller.enqueue(encoder.encode(`: ping\n\n`));
          } catch {
            cleanup();
          }
        }, 15_000);

        setTimeout(cleanup, (maxDuration - 2) * 1000);
        return;
      }

      // ----- Self-hosted: tail Redis pub/sub -----
      const sub = createSubscriber();
      let closed = false;
      const cleanup = async () => {
        if (closed) return;
        closed = true;
        try {
          await sub.unsubscribe(scanChannel(scanId));
        } catch {
          /* ignore */
        }
        sub.disconnect();
        try {
          controller.close();
        } catch {
          /* ignore */
        }
        clearInterval(heartbeat);
      };

      sub.on("message", (_channel, payload) => {
        try {
          const event = JSON.parse(payload) as LiveEvent;
          send(event);
          if (event.type === "done") void cleanup();
        } catch {
          /* skip malformed */
        }
      });
      await sub.subscribe(scanChannel(scanId));

      const heartbeat = setInterval(() => {
        try {
          controller.enqueue(encoder.encode(`: ping\n\n`));
        } catch {
          void cleanup();
        }
      }, 15_000);

      setTimeout(() => void cleanup(), 10 * 60 * 1000);
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
