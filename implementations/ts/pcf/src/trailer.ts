/**
 * The optional fixed 20-byte file trailer (spec section 4, "File Trailer").
 *
 * A trailer is present only when the file header's `partitionTableOffset` holds
 * the {@link PT_OFFSET_TRAILER} sentinel. It occupies the final
 * {@link TRAILER_SIZE} bytes of the file and records the real offset of the
 * partition-table head together with the chain direction. Because every append
 * places a fresh trailer at the new end of file, the file's last bytes always
 * point at the newest table — enabling append-only writers with no in-place
 * header rewrite.
 */

import { TRAILER_MAGIC, TRAILER_SIZE } from "./consts.js";
import { PcfError } from "./errors.js";

/** Parsed file trailer. */
export interface Trailer {
  /** Absolute offset of the partition-table head (0 = empty container). */
  partitionTableOffset: bigint;
  /** Chain-direction flags; bit 0 selects forward (0) or backward (1). */
  chainFlags: number;
}

/** Serialise to the on-disk 20-byte layout (reserved bytes 9..12 are zero). */
export function trailerToBytes(t: Trailer): Uint8Array {
  const b = new Uint8Array(TRAILER_SIZE);
  const view = new DataView(b.buffer);
  view.setBigUint64(0, t.partitionTableOffset, true);
  b[8] = t.chainFlags & 0xff;
  b.set(TRAILER_MAGIC, 12);
  return b;
}

/**
 * Parse from the on-disk 20-byte layout, validating the trailer magic. Throws
 * {@link PcfError} (BadTrailer) if the magic does not match.
 */
export function trailerFromBytes(b: Uint8Array): Trailer {
  if (b.length < TRAILER_SIZE) {
    throw PcfError.badTrailer();
  }
  for (let i = 0; i < TRAILER_MAGIC.length; i++) {
    if (b[12 + i] !== TRAILER_MAGIC[i]) {
      throw PcfError.badTrailer();
    }
  }
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  return { partitionTableOffset: view.getBigUint64(0, true), chainFlags: b[8]! };
}
