/**
 * The Fragment Table: its 9-byte block header and 18-byte entries
 * (spec Section 8).
 */

import {
  ARENA_NONE,
  FLAG_SHARED,
  FRAGMENT_ENTRY_SIZE,
  FRAGTABLE_HEADER_SIZE,
  KIND_DATA,
} from "./consts.js";
import { PcfDcpError } from "./errors.js";

/** One Fragment Entry: a single extent of an inner partition (spec 8.2). */
export interface FragmentEntry {
  /** Arena-relative start of the extent's bytes. */
  extentOffset: number;
  /** Length of the extent in bytes. */
  extentLength: number;
  /** Extent kind (`1` = DATA; `0` invalid; `2`/`3` reserved). */
  kind: number;
  /** `flags` byte (bit 0 = SHARED; others reserved 0). */
  flags: number;
}

/** Serialise a Fragment Entry to its on-disk 18-byte layout. */
export function fragmentEntryToBytes(e: FragmentEntry): Uint8Array {
  const b = new Uint8Array(FRAGMENT_ENTRY_SIZE);
  const view = new DataView(b.buffer);
  view.setBigUint64(0, BigInt(e.extentOffset), true);
  view.setBigUint64(8, BigInt(e.extentLength), true);
  b[16] = e.kind & 0xff;
  b[17] = e.flags & 0xff;
  return b;
}

/** Parse a Fragment Entry from its on-disk 18-byte layout. */
export function fragmentEntryFromBytes(b: Uint8Array): FragmentEntry {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  return {
    extentOffset: Number(view.getBigUint64(0, true)),
    extentLength: Number(view.getBigUint64(8, true)),
    kind: b[16]!,
    flags: b[17]!,
  };
}

/** Whether a Fragment Entry's `kind` is DATA. */
export function isData(e: FragmentEntry): boolean {
  return e.kind === KIND_DATA;
}

/** Whether the SHARED flag (bit 0) is set on a Fragment Entry. */
export function isShared(e: FragmentEntry): boolean {
  return (e.flags & FLAG_SHARED) !== 0;
}

/** The 9-byte header that begins each Fragment Table block (spec 8.1). */
export interface FragTableHeader {
  /** Arena-relative offset of the next block of this partition, or 0. */
  nextFragtableOffset: number;
  /** Number of Fragment Entries packed immediately after this header. */
  fragmentCount: number;
}

/** Serialise a Fragment Table block header to its on-disk 9-byte layout. */
export function fragTableHeaderToBytes(h: FragTableHeader): Uint8Array {
  const b = new Uint8Array(FRAGTABLE_HEADER_SIZE);
  const view = new DataView(b.buffer);
  view.setBigUint64(0, BigInt(h.nextFragtableOffset), true);
  b[8] = h.fragmentCount & 0xff;
  return b;
}

/** Parse a Fragment Table block header from its on-disk 9-byte layout. */
export function fragTableHeaderFromBytes(b: Uint8Array): FragTableHeader {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  return {
    nextFragtableOffset: Number(view.getBigUint64(0, true)),
    fragmentCount: b[8]!,
  };
}

/**
 * Walk an inner partition's Fragment Table chain starting at arena-relative
 * `firstOff`, returning its Fragment Entries in logical order (spec 8.3).
 */
export function walkFragmentTable(
  arena: Uint8Array,
  firstOff: number,
): FragmentEntry[] {
  const out: FragmentEntry[] = [];
  let off = firstOff;
  let budget = Math.floor(arena.length / FRAGTABLE_HEADER_SIZE) + 1;
  while (off !== ARENA_NONE) {
    if (budget === 0) {
      throw PcfDcpError.offsetOutOfRange();
    }
    budget -= 1;
    if (off + FRAGTABLE_HEADER_SIZE > arena.length) {
      throw PcfDcpError.offsetOutOfRange();
    }
    const h = fragTableHeaderFromBytes(
      arena.subarray(off, off + FRAGTABLE_HEADER_SIZE),
    );
    let eo = off + FRAGTABLE_HEADER_SIZE;
    for (let i = 0; i < h.fragmentCount; i++) {
      if (eo + FRAGMENT_ENTRY_SIZE > arena.length) {
        throw PcfDcpError.offsetOutOfRange();
      }
      out.push(fragmentEntryFromBytes(arena.subarray(eo, eo + FRAGMENT_ENTRY_SIZE)));
      eo += FRAGMENT_ENTRY_SIZE;
    }
    off = h.nextFragtableOffset;
  }
  return out;
}

/**
 * Reconstruct the logical content of a partition from its Fragment Entries
 * (spec Section 8.3): concatenate the bytes of its DATA extents in order.
 */
export function reconstruct(
  arena: Uint8Array,
  frags: readonly FragmentEntry[],
  arenaUsed: number,
): Uint8Array {
  let total = 0;
  for (const f of frags) {
    if (!isData(f)) {
      throw PcfDcpError.badFragmentKind(f.kind);
    }
    const end = f.extentOffset + f.extentLength;
    if (end > arenaUsed || end > arena.length) {
      throw PcfDcpError.offsetOutOfRange();
    }
    total += f.extentLength;
  }
  const out = new Uint8Array(total);
  let p = 0;
  for (const f of frags) {
    out.set(arena.subarray(f.extentOffset, f.extentOffset + f.extentLength), p);
    p += f.extentLength;
  }
  return out;
}
