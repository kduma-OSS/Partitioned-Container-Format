/**
 * # `pcf` — Partitioned Container Format (TypeScript implementation)
 *
 * A language-agnostic binary container that stores multiple independent regions
 * of bytes ("partitions") in a single file. This package mirrors the written
 * specification (`PCF-spec-v1.0.txt`) and the Rust reference implementation
 * field-for-field and favours auditability over performance.
 *
 * ## Layout at a glance
 *
 * ```text
 * [ 20-byte header ] [ table block(s) ] [ partition data regions ]
 * ```
 *
 * All integers are little-endian. Free space is derived as
 * `maxLength - usedBytes`.
 *
 * ## Example
 *
 * ```ts
 * import { Container, HashAlgo } from "pcf";
 *
 * const c = Container.create();
 * const uid = new Uint8Array(16).fill(1);
 * c.addPartition(0x10, uid, "notes", new TextEncoder().encode("hello world"), 64, HashAlgo.Sha256);
 *
 * c.verify();
 * const entries = c.entries();
 * console.log(new TextDecoder().decode(c.readPartitionData(entries[0]))); // "hello world"
 * ```
 */

export * from "./consts.js";
export { PcfError, PcfErrorKind } from "./errors.js";
export {
  HashAlgo,
  hashAlgoFromId,
  hashAlgoId,
  digestLen,
  verifies,
  computeHashField,
  verifyHashField,
} from "./hash.js";
export { crc32, crc32c, crc64 } from "./crc.js";
export {
  type FileHeader,
  headerToBytes,
  headerFromBytes,
} from "./header.js";
export {
  type PartitionEntry,
  entryToBytes,
  entryFromBytes,
  validateEntry,
  freeBytes,
  entryLabelString,
  encodeLabel,
  decodeLabel,
} from "./entry.js";
export {
  type TableBlockHeader,
  tableHeaderToBytes,
  tableHeaderFromBytes,
  computeTableHash,
} from "./table.js";
export { type Storage, MemoryStorage } from "./storage.js";
export { NodeFileStorage } from "./node-storage.js";
export { Container } from "./container.js";
