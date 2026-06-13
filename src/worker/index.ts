// Standalone BullMQ worker. Run with `npm run worker`. Scales horizontally —
// start as many processes as you need to absorb high scan throughput. The
// concurrency knob bounds in-flight scans per process.
import { Worker } from "bullmq";
import { bullConnection } from "../lib/redis";
import { SCAN_QUEUE, type ScanJobData } from "../lib/queue";
import { runScan } from "../lib/scanner/run";

const concurrency = Number(process.env.SENTINEL_WORKER_CONCURRENCY ?? 4);

const worker = new Worker<ScanJobData>(
  SCAN_QUEUE,
  async (job) => {
    console.log(`[worker] scan ${job.data.scanId} → ${job.data.target}`);
    await runScan(job.data);
  },
  { connection: bullConnection(), concurrency },
);

worker.on("completed", (job) => console.log(`[worker] completed ${job.id}`));
worker.on("failed", (job, err) => console.error(`[worker] failed ${job?.id}:`, err.message));

console.log(`SentinelScan worker ready (queue=${SCAN_QUEUE}, concurrency=${concurrency})`);

async function shutdown() {
  console.log("[worker] shutting down…");
  await worker.close();
  process.exit(0);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
