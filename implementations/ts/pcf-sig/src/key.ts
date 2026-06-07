/**
 * The Key Record stored in a `PCFSIG_KEY` partition (spec Section 6).
 *
 * A Key Record is a fixed prefix (`KEY_PREFIX_SIZE` bytes) carrying the
 * 32-byte SHA-256 fingerprint plus a length-prefixed `key_data` blob, then
 * an optional Type-Length-Value metadata stream that runs to `used_bytes`.
 */

import { sha256 } from "@noble/hashes/sha2";

import {
  KeyFormat,
  keyFormatFromId,
  keyFormatId,
} from "./algo.js";
import {
  FINGERPRINT_SIZE,
  KEY_MAGIC,
  KEY_PREFIX_SIZE,
  PROFILE_VERSION_MAJOR,
  PROFILE_VERSION_MINOR,
} from "./consts.js";
import { PcfSigError } from "./errors.js";

/** One metadata TLV entry (spec Section 6.4). */
export interface KeyMetadata {
  /** 16-bit tag from the registry (Appendix B). */
  tag: number;
  /** Value bytes; interpretation depends on `tag`. */
  value: Uint8Array;
}

/** A parsed Key Record (spec Section 6). */
export interface KeyRecord {
  /** `record_version_major`. v1.0 implementations require 1. */
  versionMajor: number;
  /** `record_version_minor`. */
  versionMinor: number;
  /** `key_format_id` (spec Section 6.2). */
  keyFormat: KeyFormat;
  /** 32-byte SHA-256 fingerprint of `key_data` (spec Section 6.3). */
  fingerprint: Uint8Array;
  /** Raw key material in the encoding named by `keyFormat`. */
  keyData: Uint8Array;
  /** Optional metadata entries (spec Section 6.4). */
  metadata: KeyMetadata[];
}

/**
 * Build a Key Record from raw key bytes; fills in version and fingerprint
 * deterministically.
 */
export function makeKeyRecord(
  keyFormat: KeyFormat,
  keyData: Uint8Array,
  metadata: KeyMetadata[] = [],
): KeyRecord {
  if (keyData.length === 0) {
    throw PcfSigError.emptyKeyData();
  }
  return {
    versionMajor: PROFILE_VERSION_MAJOR,
    versionMinor: PROFILE_VERSION_MINOR,
    keyFormat,
    fingerprint: computeFingerprint(keyData),
    keyData: new Uint8Array(keyData),
    metadata: metadata.map((m) => ({ tag: m.tag, value: new Uint8Array(m.value) })),
  };
}

/** Serialise a Key Record to the on-disk byte layout (spec Section 6.1). */
export function keyRecordToBytes(rec: KeyRecord): Uint8Array {
  const metaLen = rec.metadata.reduce((s, m) => s + 6 + m.value.length, 0);
  const out = new Uint8Array(KEY_PREFIX_SIZE + rec.keyData.length + metaLen);
  const view = new DataView(out.buffer);

  out.set(KEY_MAGIC, 0);
  view.setUint16(8, rec.versionMajor, true);
  view.setUint16(10, rec.versionMinor, true);
  out[12] = keyFormatId(rec.keyFormat);
  // bytes 13..16 reserved = 0
  out.set(rec.fingerprint, 16);
  view.setUint32(48, rec.keyData.length, true);
  out.set(rec.keyData, KEY_PREFIX_SIZE);

  let cur = KEY_PREFIX_SIZE + rec.keyData.length;
  for (const m of rec.metadata) {
    view.setUint16(cur, m.tag, true);
    view.setUint32(cur + 2, m.value.length, true);
    out.set(m.value, cur + 6);
    cur += 6 + m.value.length;
  }
  return out;
}

/** Parse a Key Record from the on-disk byte layout (spec Section 6.1). */
export function keyRecordFromBytes(b: Uint8Array): KeyRecord {
  if (b.length < KEY_PREFIX_SIZE) {
    throw PcfSigError.malformedSignaturePartition();
  }
  if (!bytesEqual(b.subarray(0, 8), KEY_MAGIC)) {
    throw PcfSigError.badKeyMagic();
  }
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const versionMajor = view.getUint16(8, true);
  const versionMinor = view.getUint16(10, true);
  if (versionMajor !== PROFILE_VERSION_MAJOR) {
    throw PcfSigError.unsupportedMajor(versionMajor);
  }
  const keyFormat = keyFormatFromId(b[12]!);
  if (b[13] !== 0 || b[14] !== 0 || b[15] !== 0) {
    throw PcfSigError.nonZeroKeyReserved();
  }
  const fingerprintStored = b.slice(16, 16 + FINGERPRINT_SIZE);
  const keyDataLength = view.getUint32(48, true);
  if (keyDataLength === 0) {
    throw PcfSigError.emptyKeyData();
  }
  const keyEnd = KEY_PREFIX_SIZE + keyDataLength;
  if (b.length < keyEnd) {
    throw PcfSigError.malformedSignaturePartition();
  }
  const keyData = b.slice(KEY_PREFIX_SIZE, keyEnd);

  const recomputed = computeFingerprint(keyData);
  if (!bytesEqual(recomputed, fingerprintStored)) {
    throw PcfSigError.fingerprintMismatch();
  }

  const metadata: KeyMetadata[] = [];
  let cur = keyEnd;
  while (cur < b.length) {
    if (b.length - cur < 6) {
      throw PcfSigError.malformedSignaturePartition();
    }
    const tag = view.getUint16(cur, true);
    const len = view.getUint32(cur + 2, true);
    const valueStart = cur + 6;
    const valueEnd = valueStart + len;
    if (valueEnd > b.length) {
      throw PcfSigError.malformedSignaturePartition();
    }
    metadata.push({ tag, value: b.slice(valueStart, valueEnd) });
    cur = valueEnd;
  }

  return {
    versionMajor,
    versionMinor,
    keyFormat,
    fingerprint: fingerprintStored,
    keyData,
    metadata,
  };
}

/** Compute the SHA-256 fingerprint of a key's `key_data` (spec Section 6.3). */
export function computeFingerprint(keyData: Uint8Array): Uint8Array {
  return sha256(keyData);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
