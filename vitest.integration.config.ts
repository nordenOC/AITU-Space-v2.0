import { defineConfig } from "vitest/config";

// Live-stack tests: need a running Supabase (local or a dedicated test project).
export default defineConfig({
  test: { include: ["tests/integration/**/*.test.ts"], testTimeout: 60_000 },
});
