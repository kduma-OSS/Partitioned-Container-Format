/**
 * The fixed 20-byte file header (spec section 4).
 */

import { HEADER_SIZE, MAGIC, VERSION_MAJOR } from "./consts.js";
import { PcfError } from "./errors.js";

/** Parsed file header. */
export interface FileHeader {
  /** Major format version. */
  versionMajor: number;
  /** Minor format version. */
  versionMinor: number;
  /** Absolute offset of the first table block. */
  partitionTableOffset: bigint;
}

/** Serialise a header to its on-disk 20-byte layout. */
export function headerToBytes(h: FileHeader): Uint8Array {
  const b = new Uint8Array(HEADER_SIZE);
  b.set(MAGIC, 0);
  const view = new DataView(b.buffer);
  view.setUint16(8, h.versionMajor, true);
  view.setUint16(10, h.versionMinor, true);
  view.setBigUint64(12, h.partitionTableOffset, true);
  return b;
}

/**
 * Parse a header from its on-disk 20-byte layout, validating magic and major
 * version (spec conformance checks C1, C2).
 */
export function headerFromBytes(b: Uint8Array): FileHeader {
  if (b.length < HEADER_SIZE) {
    throw PcfError.badMagic();
  }
  for (let i = 0; i < MAGIC.length; i++) {
    if (b[i] !== MAGIC[i]) {
      throw PcfError.badMagic();
    }
  }
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const versionMajor = view.getUint16(8, true);
  if (versionMajor !== VERSION_MAJOR) {
    throw PcfError.unsupportedMajor(versionMajor);
  }
  const versionMinor = view.getUint16(10, true);
  const partitionTableOffset = view.getBigUint64(12, true);
  return { versionMajor, versionMinor, partitionTableOffset };
}
