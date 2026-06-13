// Live-event plumbing: every scan step is (1) persisted to Postgres (so a late
// viewer can replay the whole run) and (2) published to a Redis channel that
// the SSE route fans out to connected browsers — the "Matrix log stream".
import { prisma } from "./db";
import { getPublisher, scanChannel } from "./redis";
import type { Emit, LiveEvent, Severity } from "./types";

export function createEmitter(scanId: string): { emit: Emit; seq: () => number } {
  let counter = 0;
  const pub = getPublisher();

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
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            meta: (event.meta ?? undefined) as any,
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

    await pub.publish(scanChannel(scanId), JSON.stringify(event));
  };

  return { emit, seq: () => counter };
}
