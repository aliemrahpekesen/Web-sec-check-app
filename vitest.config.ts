import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    // Analyzer/SSRF tests exercise pure logic; no globals or DOM needed.
    globals: false,
  },
});
