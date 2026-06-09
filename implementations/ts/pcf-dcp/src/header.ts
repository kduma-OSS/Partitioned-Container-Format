/**
 * The fixed 24-byte DCP Header at arena offset 0 (spec Section 6).
 */

import { DCP_HEADER_SIZE, DCP_MAGIC } from "./consts.js";
import { PcfDcpError } from "./errors.js";

/** Parsed DCP Header. All offsets it carries are arena-relative. */
export interface DcpHeader {
  /** PCF-DCP profile major version. */
  profileVersionMajor: number;
  /** PCF-DCP profile minor version. */
  profileVersionMinor: number;
  /** Reserved; MUST be 0 in v1.0. */
  flags: number;
  /** Arena-relative offset of the first Inner Table Block (0 = none). */
  innerTableOffset: number;
  /** Bump pointer: arena-relative offset of the first free byte. */
  arenaUsed: number;
}

/** Serialise a DCP Header to its on-disk 24-byte layout. */
export function dcpHeaderToBytes(h: DcpHeader): Uint8Array {
  const b = new Uint8Array(DCP_HEADER_SIZE);
  const view = new DataView(b.buffer);
  b.set(DCP_MAGIC, 0);
  b[4] = h.profileVersionMajor & 0xff;
  b[5] = h.profileVersionMinor & 0xff;
  view.setUint16(6, h.flags & 0xffff, true);
  view.setBigUint64(8, BigInt(h.innerTableOffset), true);
  view.setBigUint64(16, BigInt(h.arenaUsed), true);
  return b;
}

/** Parse a DCP Header from its on-disk 24-byte layout, validating the magic. */
export function dcpHeaderFromBytes(b: Uint8Array): DcpHeader {
  for (let i = 0; i < 4; i++) {
    if (b[i] !== DCP_MAGIC[i]) {
      throw PcfDcpError.badDcpMagic();
    }
  }
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  return {
    profileVersionMajor: b[4]!,
    profileVersionMinor: b[5]!,
    flags: view.getUint16(6, true),
    innerTableOffset: Number(view.getBigUint64(8, true)),
    arenaUsed: Number(view.getBigUint64(16, true)),
  };
}

/** Read a DCP Header from the start of an arena byte slice. */
export function readHeader(arena: Uint8Array): DcpHeader {
  if (arena.length < DCP_HEADER_SIZE) {
    throw PcfDcpError.badDcpMagic();
  }
  return dcpHeaderFromBytes(arena.subarray(0, DCP_HEADER_SIZE));
}
