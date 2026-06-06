/**
 * Generates the canonical PCF v1.0 test-vector file used in spec section 15.
 *
 * Run with: `npx tsx examples/gen-testvector.ts <output-path>`
 * (defaults to ./pcf_testvector.bin). Everything is fixed and deterministic so
 * that ports can reproduce the file byte-for-byte.
 */

import { writeFileSync } from "node:fs";

import {
  Container,
  digestLen,
  entryLabelString,
  HashAlgo,
  MemoryStorage,
  TYPE_RAW,
} from "../src/index.js";

function main(): void {
  const path = process.argv[2] ?? "pcf_testvector.bin";

  const c = Container.createWith(new MemoryStorage(), 8, HashAlgo.Sha256);

  // Partition 0: a SHA-256-protected text region.
  c.addPartition(
    0x0000_0010,
    new Uint8Array(16).fill(0x11),
    "alpha",
    new TextEncoder().encode("Hello, PCF!"),
    0,
    HashAlgo.Sha256,
  );

  // Partition 1: a RAW region protected by CRC-32C.
  c.addPartition(
    TYPE_RAW,
    new Uint8Array(16).fill(0x22),
    "raw",
    new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
    0,
    HashAlgo.Crc32c,
  );

  // Compact to the canonical, tightly-packed layout.
  const image = c.compactedImage();
  writeFileSync(path, image);

  // Re-open the produced bytes and verify, then print a short report.
  const v = Container.open(new MemoryStorage(image));
  v.verify();

  process.stderr.write(`wrote ${path} (${image.length} bytes)\n`);
  for (const e of v.entries()) {
    const n = digestLen(e.dataHashAlgo);
    const hex = Array.from(e.dataHash.slice(0, n))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const typeHex = (e.partitionType >>> 0)
      .toString(16)
      .padStart(8, "0")
      .toUpperCase();
    process.stderr.write(
      `  ${entryLabelString(e).padEnd(6)} type=0x${typeHex} ` +
        `algo=${HashAlgo[e.dataHashAlgo]} start=${e.startOffset} ` +
        `used=${e.usedBytes} data_hash=${hex}\n`,
    );
  }
}

main();
