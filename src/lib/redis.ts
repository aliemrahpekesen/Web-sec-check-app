// Redis connection helpers. BullMQ requires `maxRetriesPerRequest: null` on its
// connection. We keep separate clients for the queue, the pub/sub publisher,
// and (created on demand) subscribers.
import IORedis, { type Redis } from "ioredis";
import type { ConnectionOptions } from "bullmq";
import { env } from "./env";

// BullMQ bundles its own ioredis copy, so passing one of *our* ioredis
// instances trips a dual-package type clash. Hand BullMQ plain connection
// options instead and let it construct its own client.
export function bullConnection(): ConnectionOptions {
  const u = new URL(env.redisUrl);
  return {
    host: u.hostname,
    port: u.port ? Number(u.port) : 6379,
    username: u.username || undefined,
    password: u.password || undefined,
    db: u.pathname && u.pathname.length > 1 ? Number(u.pathname.slice(1)) : 0,
  };
}

const globalForRedis = globalThis as unknown as {
  redisQueue?: Redis;
  redisPub?: Redis;
};

export function getQueueConnection(): Redis {
  if (!globalForRedis.redisQueue) {
    globalForRedis.redisQueue = new IORedis(env.redisUrl, {
      maxRetriesPerRequest: null,
      enableReadyCheck: false,
    });
  }
  return globalForRedis.redisQueue;
}

export function getPublisher(): Redis {
  if (!globalForRedis.redisPub) {
    globalForRedis.redisPub = new IORedis(env.redisUrl, {
      maxRetriesPerRequest: null,
    });
  }
  return globalForRedis.redisPub;
}

// Subscribers must be dedicated connections (a subscribed client can't run
// other commands), so always create a fresh one.
export function createSubscriber(): Redis {
  return new IORedis(env.redisUrl, { maxRetriesPerRequest: null });
}

export const scanChannel = (scanId: string) => `scan:${scanId}:events`;
