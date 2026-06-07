/**
 * Cross-port test vector parity. The same 966-byte canonical container is
 * shipped by every PCF-SIG language port. This test:
 *
 *   1. Loads the file from disk and asserts byte-exact equality with what we
 *      regenerate locally from the same seed.
 *   2. Opens it as a PCF container, verifies the PCF cascade.
 *   3. Verifies the PCF-SIG signature end-to-end with data recheck.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { describe, expect, it } from "vitest";
import { Container, HashAlgo, MemoryStorage } from "@kduma-oss/pcf";
import { sha256 } from "@noble/hashes/sha2";

import {
  EntryVerdict,
  ManifestVerdict,
  SigningMaterial,
  signPartitions,
  verifyAllWithRecheck,
} from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CANONICAL = readFileSync(
  resolve(__dirname, "..", "testdata", "canonical.bin"),
);

const EXPECTED_SHA256 =
  "b158e2f5b160d72cea3226af2041f8d18aa75b3db6cb85faeca5df7879871307";

function uid(n: number): Uint8Array {
  return new Uint8Array(16).fill(n);
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

describe("canonical test vector", () => {
  it("ships the expected SHA-256", () => {
    expect(hex(sha256(CANONICAL))).toBe(EXPECTED_SHA256);
  });

  it("opens, verifies the PCF cascade, and verifies PCF-SIG", () => {
    const c = Container.open(new MemoryStorage(new Uint8Array(CANONICAL)));
    c.verify();
    const reports = verifyAllWithRecheck(c);
    expect(reports).toHaveLength(1);
    expect(reports[0]!.verdict).toBe(ManifestVerdict.Valid);
    expect(reports[0]!.entries).toHaveLength(1);
    expect(reports[0]!.entries[0]!.verdict).toBe(EntryVerdict.Valid);
  });

  it("regenerates byte-exact from a deterministic seed", () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) seed[i] = i;
    const signer = SigningMaterial.ed25519FromSeed(seed);

    const c = Container.createWith(new MemoryStorage(), 8, HashAlgo.Sha256);
    c.addPartition(
      0x10,
      uid(0x11),
      "alpha",
      new TextEncoder().encode("Hello, PCF-SIG!"),
      0,
      HashAlgo.Sha256,
    );
    signPartitions(c, signer, {
      targetUids: [uid(0x11)],
      sigPartitionUid: uid(0x33),
      keyPartitionUid: uid(0x22),
      signedAtUnixSeconds: 0n,
      sigLabel: "pcfsig",
      keyLabel: "pcfkey",
    });
    const image = c.compactedImage();
    expect(image.length).toBe(CANONICAL.length);
    expect(hex(sha256(image))).toBe(EXPECTED_SHA256);
  });
});
