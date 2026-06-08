/**
 * Generates the canonical PCF-DCP v1.0 test-vector file (spec Section 17). Run
 * with `npm run gen-testvector -- <output-path>` (defaults to
 * ./pcf_dcp_testvector.bin). Everything is fixed and deterministic so that
 * independent implementations can reproduce the file byte-for-byte.
 */

import { writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

import { Container, MemoryStorage } from "@kduma-oss/pcf";

import { buildReferenceVector, DcpReader } from "../src/index.js";

const path = process.argv[2] ?? "pcf_dcp_testvector.bin";

const image = buildReferenceVector();
writeFileSync(path, image);

// It is a conforming PCF v1.0 file ...
const pcf = Container.open(new MemoryStorage(image));
pcf.verify();

// ... and a conforming DCP file.
const dcp = DcpReader.open(new MemoryStorage(image));
dcp.verify();

const digest = createHash("sha256").update(image).digest("hex");
console.error(`wrote ${path} (${image.length} bytes)`);
console.error(`sha256 = ${digest}`);
for (const c of dcp.containers()) {
  const arena = dcp.openArena(c);
  console.error(`  container used=${c.usedBytes} inners=${arena.len()}`);
  for (const info of arena.innerInfos()) {
    const shared = info.extents.filter((e) => e.shared).length;
    console.error(
      `    inner ${info.label} type=0x${info.partitionType.toString(16)} used=${info.usedBytes} extents=${info.extents.length} shared=${shared}`,
    );
  }
}
