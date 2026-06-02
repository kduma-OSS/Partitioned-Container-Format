import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      // The Node file storage uses real file descriptors and is not exercised
      // by the in-memory test suite; it is excluded from the coverage floor.
      exclude: ["src/index.ts"],
      reporter: ["text", "lcov"],
      thresholds: {
        lines: 95,
        functions: 100,
      },
    },
  },
});
