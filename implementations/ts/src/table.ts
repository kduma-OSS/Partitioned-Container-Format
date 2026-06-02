/**
 * The 74-byte table-block header and table-block hashing
 * (spec sections 5.1, 8.4).
 */

import { HASH_FIELD_SIZE, TABLE_HEADER_SIZE } from "./consts.js";
import { entryToBytes, type PartitionEntry } from "./entry.js";
import { computeHashField, HashAlgo, hashAlgoFromId, hashAlgoId } from "./hash.js";

/** Parsed table-block header (the entries follow it on disk). */
export interface TableBlockHeader {
  /** Number of entries stored in this block (0..=255). */
  partitionCount: number;
  /** Absolute offset of the next block, or 0 for end-of-chain. */
  nextTableOffset: bigint;
  /** Algorithm used for `tableHash`. */
  tableHashAlgo: HashAlgo;
  /** 64-byte table hash field. */
  tableHash: Uint8Array;
}

/** Serialise a table-block header to its on-disk 74-byte layout. */
export function tableHeaderToBytes(h: TableBlockHeader): Uint8Array {
  const b = new Uint8Array(TABLE_HEADER_SIZE);
  const view = new DataView(b.buffer);
  b[0] = h.partitionCount & 0xff;
  view.setBigUint64(1, h.nextTableOffset, true);
  b[9] = hashAlgoId(h.tableHashAlgo);
  b.set(h.tableHash, 10);
  return b;
}

/** Parse a table-block header from its on-disk 74-byte layout. */
export function tableHeaderFromBytes(b: Uint8Array): TableBlockHeader {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const partitionCount = b[0]!;
  const nextTableOffset = view.getBigUint64(1, true);
  const tableHashAlgo = hashAlgoFromId(b[9]!);
  const tableHash = b.slice(10, 10 + HASH_FIELD_SIZE);
  return { partitionCount, nextTableOffset, tableHashAlgo, tableHash };
}

/**
 * Compute the table hash over `[header-with-zeroed-hash || entries]`
 * (spec section 8.4). The `table_hash_algo` byte is included; the 64-byte
 * hash field is treated as zero; trailing reserved space is excluded.
 */
export function computeTableHash(
  algo: HashAlgo,
  nextTableOffset: bigint,
  entries: readonly PartitionEntry[],
): Uint8Array {
  const header = tableHeaderToBytes({
    partitionCount: entries.length,
    nextTableOffset,
    tableHashAlgo: algo,
    tableHash: new Uint8Array(HASH_FIELD_SIZE), // zeroed for the computation
  });
  const image = new Uint8Array(TABLE_HEADER_SIZE + entries.length * 141);
  image.set(header, 0);
  let off = TABLE_HEADER_SIZE;
  for (const e of entries) {
    image.set(entryToBytes(e), off);
    off += 141;
  }
  return computeHashField(algo, image);
}
