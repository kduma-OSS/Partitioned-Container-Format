/**
 * # `pcf-dcp` — PCF Dynamic Container Partition (TypeScript implementation)
 *
 * Adds *dynamic*, fragmentable, dedup-friendly sub-partitions to the
 * {@link "@kduma-oss/pcf"} container without changing its byte format. One new
 * PCF partition type is defined:
 *
 * * **`DCP_CONTAINER`** (type `0xAAAC0001`) — a partition whose bytes are an
 *   *arena*: a {@link DcpHeader}, a chain of reused PCF Table Blocks listing
 *   *inner* partitions, a Fragment Table per inner partition, and the data
 *   extents those fragments name.
 *
 * Each inner partition's logical content is the concatenation of its DATA
 * extents (spec Section 8.3); its `dataHash` covers that logical content, so
 * fragmentation, deduplication, compaction, and promotion all leave the hash
 * (and any PCF-SIG signature over it) unchanged. A generic PCF reader sees a
 * DCP file as one opaque, typed partition; only a DCP-aware reader looks inside.
 *
 * ## Example
 *
 * ```ts
 * import { Arena, Chunker, DcpReader, DcpWriter } from "@kduma-oss/pcf-dcp";
 * import { HashAlgo, MemoryStorage } from "@kduma-oss/pcf";
 *
 * const arena = new Arena();
 * arena.addInner(0x10, new Uint8Array(16).fill(0xa1), "A",
 *   new TextEncoder().encode("Hello, World!"), HashAlgo.Sha256, Chunker.fixed(7));
 * arena.addInner(0x10, new Uint8Array(16).fill(0xb2), "B",
 *   new TextEncoder().encode("World!"), HashAlgo.Sha256, Chunker.whole());
 *
 * const w = new DcpWriter();
 * w.addContainer(new Uint8Array(16).fill(0xdc), "dcp", arena);
 * const image = w.toImage();
 *
 * const r = DcpReader.open(new MemoryStorage(image));
 * r.verify();
 * // r.readInner(new Uint8Array(16).fill(0xb2)) === "World!"
 * ```
 */

export * from "./consts.js";
export { PcfDcpError, PcfDcpErrorKind } from "./errors.js";
export {
  type DcpHeader,
  dcpHeaderToBytes,
  dcpHeaderFromBytes,
} from "./header.js";
export {
  type FragmentEntry,
  type FragTableHeader,
  fragmentEntryToBytes,
  fragmentEntryFromBytes,
  fragTableHeaderToBytes,
  fragTableHeaderFromBytes,
  isData,
  isShared,
  walkFragmentTable,
  reconstruct,
} from "./fragment.js";
export {
  Arena,
  Chunker,
  type ExtentInfo,
  type InnerInfo,
} from "./arena.js";
export {
  DcpReader,
  type InnerLocation,
  type Resolved,
} from "./reader.js";
export { DcpWriter } from "./writer.js";
export { buildReferenceVector } from "./vector.js";

// Re-export the underlying hash registry for convenience.
export { HashAlgo } from "@kduma-oss/pcf";
