// BullMQ queue definition. The API enqueues jobs here; the worker consumes them.
import { Queue } from "bullmq";
import { bullConnection } from "./redis";
import type { ScanProfile } from "./types";

export const SCAN_QUEUE = "sentinel-scans";

export interface ScanJobData {
  scanId: string;
  target: string;
  host: string;
  profile: ScanProfile;
}

const globalForQueue = globalThis as unknown as { scanQueue?: Queue<ScanJobData> };

export function getScanQueue(): Queue<ScanJobData> {
  if (!globalForQueue.scanQueue) {
    globalForQueue.scanQueue = new Queue<ScanJobData>(SCAN_QUEUE, {
      connection: bullConnection(),
      defaultJobOptions: {
        attempts: 1,
        removeOnComplete: { age: 3600, count: 1000 },
        removeOnFail: { age: 86400 },
      },
    });
  }
  return globalForQueue.scanQueue!;
}
