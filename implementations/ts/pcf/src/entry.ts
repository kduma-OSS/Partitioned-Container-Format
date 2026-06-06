/**
 * The fixed 141-byte partition entry (spec section 5.2).
 */

import {
  ENTRY_SIZE,
  HASH_FIELD_SIZE,
  LABEL_SIZE,
  NIL_UID,
  TYPE_RESERVED,
} from "./consts.js";
import { PcfError } from "./errors.js";
import { HashAlgo, hashAlgoFromId, hashAlgoId } from "./hash.js";

/** One partition's metadata. */
export interface PartitionEntry {
  /** Application-defined type (`0` and `0xFFFFFFFF` are reserved). */
  partitionType: number;
  /** 16-byte unique identifier. */
  uid: Uint8Array;
  /** 32-byte ASCII label, NUL-padded. */
  label: Uint8Array;
  /** Absolute offset of the partition's data region. */
  startOffset: bigint;
  /** Bytes reserved for the partition. */
  maxLength: bigint;
  /** Bytes currently used (a contiguous prefix of the reservation). */
  usedBytes: bigint;
  /** Algorithm used for `dataHash`. */
  dataHashAlgo: HashAlgo;
  /** 64-byte data hash field. */
  dataHash: Uint8Array;
}

/** Serialise an entry to its on-disk 141-byte layout. */
export function entryToBytes(e: PartitionEntry): Uint8Array {
  const b = new Uint8Array(ENTRY_SIZE);
  const view = new DataView(b.buffer);
  view.setUint32(0, e.partitionType >>> 0, true);
  b.set(e.uid, 4);
  b.set(e.label, 20);
  view.setBigUint64(52, e.startOffset, true);
  view.setBigUint64(60, e.maxLength, true);
  view.setBigUint64(68, e.usedBytes, true);
  b[76] = hashAlgoId(e.dataHashAlgo);
  b.set(e.dataHash, 77);
  return b;
}

/** Parse an entry from its on-disk 141-byte layout. */
export function entryFromBytes(b: Uint8Array): PartitionEntry {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const partitionType = view.getUint32(0, true);
  const uid = b.slice(4, 20);
  const label = b.slice(20, 52);
  const startOffset = view.getBigUint64(52, true);
  const maxLength = view.getBigUint64(60, true);
  const usedBytes = view.getBigUint64(68, true);
  const dataHashAlgo = hashAlgoFromId(b[76]!);
  const dataHash = b.slice(77, 77 + HASH_FIELD_SIZE);
  return {
    partitionType,
    uid,
    label,
    startOffset,
    maxLength,
    usedBytes,
    dataHashAlgo,
    dataHash,
  };
}

/**
 * Apply the conformance checks a reader must run on a live entry
 * (spec C5, C6, C7).
 */
export function validateEntry(e: PartitionEntry): void {
  if (e.partitionType === TYPE_RESERVED) {
    throw PcfError.reservedType();
  }
  if (bytesEqual(e.uid, NIL_UID)) {
    throw PcfError.nilUid();
  }
  if (e.usedBytes > e.maxLength) {
    throw PcfError.usedExceedsMax();
  }
  decodeLabel(e.label); // validates label bytes
}

/** Free bytes remaining in a partition (`max_length - used_bytes`). */
export function freeBytes(e: PartitionEntry): bigint {
  return e.usedBytes > e.maxLength ? 0n : e.maxLength - e.usedBytes;
}

/** Decode an entry's label as a string (reads up to the first NUL). */
export function entryLabelString(e: PartitionEntry): string {
  return decodeLabel(e.label);
}

/** Build a 32-byte label field from a string (spec section 10). */
export function encodeLabel(s: string): Uint8Array {
  // Labels are ASCII (0x01..0x7F); reject anything that is not.
  const out = new Uint8Array(LABEL_SIZE);
  let n = 0;
  for (const ch of s) {
    const code = ch.codePointAt(0)!;
    if (code === 0 || code >= 0x80) {
      throw PcfError.invalidLabel();
    }
    if (n >= LABEL_SIZE) {
      throw PcfError.invalidLabel();
    }
    out[n] = code;
    n++;
  }
  return out;
}

/**
 * Decode a 32-byte label field: read until the first NUL or 32 bytes,
 * rejecting any byte >= 0x80 (spec section 10).
 */
export function decodeLabel(label: Uint8Array): string {
  let end = LABEL_SIZE;
  for (let i = 0; i < LABEL_SIZE; i++) {
    const c = label[i]!;
    if (c === 0) {
      end = i;
      break;
    }
    if (c >= 0x80) {
      throw PcfError.invalidLabel();
    }
  }
  let s = "";
  for (let i = 0; i < end; i++) {
    s += String.fromCharCode(label[i]!);
  }
  return s;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}
