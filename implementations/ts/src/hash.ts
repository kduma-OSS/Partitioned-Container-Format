/**
 * Hash-algorithm registry (spec section 8).
 *
 * Each hash field in the format is a fixed 64-byte field accompanied by a
 * `u8` algorithm identifier. Digests are stored left-aligned and zero-padded;
 * CRC values are stored as little-endian integers, left-aligned and
 * zero-padded (spec section 8.2).
 *
 * Digests are provided by the audited `@noble/hashes` package; the CRC variants
 * are implemented locally in {@link "./crc"}.
 */

import { sha256, sha512 } from "@noble/hashes/sha2";
import { md5, sha1 } from "@noble/hashes/legacy";
import { blake3 } from "@noble/hashes/blake3";

import { HASH_FIELD_SIZE } from "./consts.js";
import { crc32, crc32c, crc64 } from "./crc.js";
import { PcfError } from "./errors.js";

/**
 * A hash algorithm from the PCF registry (spec section 8.1).
 *
 * The numeric value of each member is exactly its on-disk registry id, so
 * `algo as number` yields the id byte.
 */
export enum HashAlgo {
  /** `0` — no verification. */
  None = 0,
  /** `1` — CRC-32/ISO-HDLC. */
  Crc32 = 1,
  /** `2` — CRC-32C (Castagnoli). */
  Crc32c = 2,
  /** `3` — CRC-64/XZ. */
  Crc64 = 3,
  /** `4` — MD5 (checksum use only). */
  Md5 = 4,
  /** `5` — SHA-1 (checksum use only). */
  Sha1 = 5,
  /** `16` — SHA-256 (default). */
  Sha256 = 16,
  /** `17` — SHA-512. */
  Sha512 = 17,
  /** `18` — BLAKE3. */
  Blake3 = 18,
}

const KNOWN_IDS: ReadonlySet<number> = new Set([0, 1, 2, 3, 4, 5, 16, 17, 18]);

/** Map a registry id byte to an algorithm (spec section 8.1). */
export function hashAlgoFromId(id: number): HashAlgo {
  if (!KNOWN_IDS.has(id)) {
    throw PcfError.unknownHashAlgo(id);
  }
  return id as HashAlgo;
}

/** The registry id byte for an algorithm. */
export function hashAlgoId(algo: HashAlgo): number {
  return algo;
}

/** Number of significant bytes an algorithm writes into a hash field. */
export function digestLen(algo: HashAlgo): number {
  switch (algo) {
    case HashAlgo.None:
      return 0;
    case HashAlgo.Crc32:
    case HashAlgo.Crc32c:
      return 4;
    case HashAlgo.Crc64:
      return 8;
    case HashAlgo.Md5:
      return 16;
    case HashAlgo.Sha1:
      return 20;
    case HashAlgo.Sha256:
    case HashAlgo.Blake3:
      return 32;
    case HashAlgo.Sha512:
      return 64;
  }
}

/** Whether an algorithm performs any verification (everything but `None`). */
export function verifies(algo: HashAlgo): boolean {
  return algo !== HashAlgo.None;
}

function writeU32Le(field: Uint8Array, value: number): void {
  field[0] = value & 0xff;
  field[1] = (value >>> 8) & 0xff;
  field[2] = (value >>> 16) & 0xff;
  field[3] = (value >>> 24) & 0xff;
}

function writeU64Le(field: Uint8Array, value: bigint): void {
  let v = value;
  for (let i = 0; i < 8; i++) {
    field[i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

/**
 * Compute the full 64-byte hash field for `data` per spec section 8.2.
 *
 * Digest-producing algorithms write their digest starting at byte 0; CRCs write
 * a little-endian integer of their width; all remaining bytes are 0x00.
 * Algorithm `None` yields an all-zero field.
 */
export function computeHashField(algo: HashAlgo, data: Uint8Array): Uint8Array {
  const field = new Uint8Array(HASH_FIELD_SIZE);
  switch (algo) {
    case HashAlgo.None:
      break;
    case HashAlgo.Crc32:
      writeU32Le(field, crc32(data));
      break;
    case HashAlgo.Crc32c:
      writeU32Le(field, crc32c(data));
      break;
    case HashAlgo.Crc64:
      writeU64Le(field, crc64(data));
      break;
    case HashAlgo.Md5:
      field.set(md5(data), 0);
      break;
    case HashAlgo.Sha1:
      field.set(sha1(data), 0);
      break;
    case HashAlgo.Sha256:
      field.set(sha256(data), 0);
      break;
    case HashAlgo.Sha512:
      field.set(sha512(data), 0);
      break;
    case HashAlgo.Blake3:
      field.set(blake3(data), 0);
      break;
  }
  return field;
}

/**
 * Verify `data` against a stored 64-byte hash field. `None` always succeeds
 * (no verification). Only the significant prefix is compared, per spec 8.2.
 */
export function verifyHashField(
  algo: HashAlgo,
  data: Uint8Array,
  stored: Uint8Array,
): boolean {
  if (!verifies(algo)) {
    return true;
  }
  const computed = computeHashField(algo, data);
  const n = digestLen(algo);
  for (let i = 0; i < n; i++) {
    if (computed[i] !== stored[i]) {
      return false;
    }
  }
  return true;
}
