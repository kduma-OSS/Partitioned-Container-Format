/**
 * Cross-port test vector parity. The same 700-byte canonical container is
 * shipped by every PCF-DCP language port (spec Section 17). This test:
 *
 *   1. Loads the file from disk and asserts SHA-256 + byte-exact regeneration.
 *   2. Opens it as a PCF container and verifies the PCF cascade.
 *   3. Opens it as a DCP container and verifies it end-to-end.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { describe, expect, it } from "vitest";
import { Container, MemoryStorage } from "@kduma-oss/pcf";

import { buildReferenceVector, DcpReader } from "../src/index.js";
import { dec, fill, hex, sha256hex } from "./helpers.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CANONICAL = new Uint8Array(
  readFileSync(resolve(__dirname, "..", "testdata", "canonical.bin")),
);

const EXPECTED_SHA256 =
  "b9bb59794abed008863063886d8d0daa810c44939c1c5d29449475ced8156b90";

describe("canonical test vector", () => {
  it("ships the expected SHA-256 and length", () => {
    expect(CANONICAL.length).toBe(700);
    expect(sha256hex(CANONICAL)).toBe(EXPECTED_SHA256);
  });

  it("regenerates byte-exact", () => {
    const image = buildReferenceVector();
    expect(image.length).toBe(700);
    expect(sha256hex(image)).toBe(EXPECTED_SHA256);
    expect(hex(image)).toBe(hex(CANONICAL));
  });

  it("is a valid PCF file", () => {
    const c = Container.open(new MemoryStorage(CANONICAL));
    c.verify();
    const entries = c.entries();
    expect(entries).toHaveLength(1);
    expect(entries[0]!.partitionType).toBe(0xaaac_0001);
    expect(Number(entries[0]!.usedBytes)).toBe(465);
  });

  it("is a valid DCP file with reconstructable inners", () => {
    const r = DcpReader.open(new MemoryStorage(CANONICAL));
    r.verify();
    expect(dec(r.readInner(fill(0xa1)))).toBe("Hello, World!");
    expect(dec(r.readInner(fill(0xb2)))).toBe("World!");
  });
});
