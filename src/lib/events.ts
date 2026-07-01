// Live-event plumbing: every scan step is (1) persisted to Postgres (so a late
// viewer can replay the whole run) and (2) published to a Redis channel that
// the SSE route fans out to connected browsers — the "Matrix log stream".
import { Prisma } from "@prisma/client";
import { prisma } from "./db";
import { env } from "./env";
import { getPublisher, scanChannel } from "./redis";
import type { Emit, LiveEvent, Severity } from "./types";

export function createEmitter(scanId: string): { emit: Emit; seq: () => number } {
  let counter = 0;
  // In serverless mode there is no Redis; the SSE route fans out by polling
  // Postgres, so we only persist (below) and skip publishing.
  const pub = env.serverless ? null : getPublisher();

  const emit: Emit = async (partial) => {
    const seq = counter++;
    const event: LiveEvent = {
      ...partial,
      seq,
      at: new Date().toISOString(),
    };

    // Persist depending on the kind of event.
    try {
      if (event.type === "log" || event.type === "status") {
        await prisma.scanLog.create({
          data: {
            scanId,
            seq,
            level: event.level ?? (event.type === "status" ? "step" : "info"),
            message: event.message ?? event.status ?? "",
            meta: (event.meta ?? undefined) as Prisma.InputJsonValue | undefined,
          },
        });
      } else if (event.type === "finding" && event.finding) {
        const f = event.finding;
        await prisma.finding.create({
          data: {
            scanId,
            checkId: f.checkId,
            title: f.title,
            severity: f.severity as Severity,
            cwe: f.cwe,
            owasp: f.owasp,
            location: f.location,
            description: f.description,
            evidence: f.evidence,
            remediation: f.remediation,
            confidence: f.confidence ?? "firm",
          },
        });
        // Also drop a log line so the finding shows in the stream timeline.
        await prisma.scanLog.create({
          data: {
            scanId,
            seq,
            level: "finding",
            message: `[${f.severity}] ${f.title} @ ${f.location}`,
            meta: { checkId: f.checkId },
          },
        });
      }
    } catch (err) {
      // Never let persistence failures kill a scan; the stream still flows.
      console.error("event persist error", err);
    }

    if (pub) await pub.publish(scanChannel(scanId), JSON.stringify(event));
  };

  return { emit, seq: () => counter };
}

// Stateless emitter: assigns sequence numbers and forwards events straight to
// the SSE writer. No DB, no Redis — used by the DB-less serverless demo.
export function statelessEmitter(send: (e: LiveEvent) => void): Emit {
  let counter = 0;
  return async (partial) => {
    send({ ...partial, seq: counter++, at: new Date().toISOString() } as LiveEvent);
  };
}
