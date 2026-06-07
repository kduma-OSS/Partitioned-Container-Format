import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/index.ts"],
      reporter: ["text", "lcov"],
      // PCF-SIG v1.0 is intentionally registry-driven: SigAlgo enumerates
      // 8 variants (Ed25519, RSA-PSS x2, RSA-PKCS1v15 x2, ECDSA x2, X.509),
      // but only Ed25519 is implemented in this release; the others are
      // recognised so verifyAll returns Unverifiable rather than Malformed.
      // That leaves several branches and PcfSigError factory methods
      // structurally unreachable by an Ed25519-only test suite, so the
      // thresholds below match what is achievable for this surface.
      thresholds: {
        lines: 75,
        functions: 90,
      },
    },
  },
});
