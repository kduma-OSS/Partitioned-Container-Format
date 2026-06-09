/**
 * The canonical PCF-DCP v1.0 test vector (spec Section 17).
 */

import { HashAlgo } from "@kduma-oss/pcf";

import { Arena, Chunker } from "./arena.js";
import { DcpWriter } from "./writer.js";

/**
 * Build the byte-exact 700-byte reference file from spec Section 17.
 *
 * The file is one DCP container ("dcp", uid 16×0xDC, unsealed) holding two
 * inner partitions: **A** ("Hello, World!", 13 B) stored as two extents —
 * `"Hello, "` (7 B, private) and `"World!"` (6 B, shared) — via fixed-7
 * chunking; and **B** ("World!", 6 B) stored as one extent that deduplicates
 * onto A's second extent (both SHARED). Building the same logical container and
 * emitting the canonical layout MUST reproduce these exact bytes.
 */
export function buildReferenceVector(): Uint8Array {
  const enc = new TextEncoder();
  const arena = new Arena();
  arena.addInner(
    0x0000_0010,
    new Uint8Array(16).fill(0xa1),
    "A",
    enc.encode("Hello, World!"),
    HashAlgo.Sha256,
    Chunker.fixed(7),
  );
  arena.addInner(
    0x0000_0010,
    new Uint8Array(16).fill(0xb2),
    "B",
    enc.encode("World!"),
    HashAlgo.Sha256,
    Chunker.whole(),
  );

  const w = new DcpWriter();
  w.addContainer(new Uint8Array(16).fill(0xdc), "dcp", arena);
  return w.toImage();
}
