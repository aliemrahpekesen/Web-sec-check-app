import { z } from "zod";

export const createScanSchema = z.object({
  target: z.string().min(3).max(2048),
  profile: z.enum(["PASSIVE", "STANDARD", "DEEP"]).default("STANDARD"),
});

export const verifySchema = z.object({
  host: z.string().min(3).max(255),
});

export type CreateScanInput = z.infer<typeof createScanSchema>;
