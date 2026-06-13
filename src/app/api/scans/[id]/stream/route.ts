import { prisma } from "@/lib/db";
import { createSubscriber, scanChannel } from "@/lib/redis";
import type { LiveEvent } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// GET /api/scans/:id/stream — Server-Sent Events feed of the live scan log.
// Replays persisted logs first (so late/reconnecting viewers see history),
// then tails the Redis pub/sub channel until the scan finishes.
export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const scanId = params.id;
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const send = (event: Partial<LiveEvent>) => {
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
        } catch {
          /* controller closed */
        }
      };

      // 1. Replay history from the database.
      const scan = await prisma.scan.findUnique({
        where: { id: scanId },
        include: { logs: { orderBy: { seq: "asc" } } },
      });
      if (!scan) {
        send({ type: "done", status: "FAILED", message: "Tarama bulunamadı" });
        controller.close();
        return;
      }
      for (const log of scan.logs) {
        send({
          type: "log",
          seq: log.seq,
          at: log.at.toISOString(),
          level: log.level as LiveEvent["level"],
          message: log.message,
        });
      }

      // If the scan already finished, emit a terminal event and close.
      if (["COMPLETED", "FAILED", "CANCELLED"].includes(scan.status)) {
        send({
          type: "done",
          status: scan.status,
          riskScore: scan.riskScore ?? undefined,
          grade: scan.grade ?? undefined,
        });
        controller.close();
        return;
      }

      // 2. Tail live events from Redis.
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

      // Keep-alive comments so proxies don't drop the idle connection.
      const heartbeat = setInterval(() => {
        try {
          controller.enqueue(encoder.encode(`: ping\n\n`));
        } catch {
          void cleanup();
        }
      }, 15_000);

      // Safety net: never hang forever.
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
