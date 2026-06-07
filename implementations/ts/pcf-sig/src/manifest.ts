/**
 * The Manifest and Signed Entry stored in a `PCFSIG_SIG` partition
 * (spec Section 7).
 *
 * The Manifest is the byte sequence that is hashed and signed. Its length is
 * deterministic from `signedCount`:
 *   `MANIFEST_PREFIX_SIZE + SIGNED_ENTRY_SIZE * signedCount`.
 */

import {
  HASH_FIELD_SIZE,
  HashAlgo,
  TYPE_RESERVED,
  UID_SIZE,
  hashAlgoFromId,
  hashAlgoId,
} from "@kduma-oss/pcf";

import {
  SigAlgo,
  requiredManifestHash,
  sigAlgoFromId,
  sigAlgoId,
} from "./algo.js";
import {
  FINGERPRINT_SIZE,
  MANIFEST_PREFIX_SIZE,
  PROFILE_VERSION_MAJOR,
  PROFILE_VERSION_MINOR,
  SIG_MAGIC,
  SIGNED_ENTRY_SIZE,
} from "./consts.js";
import { PcfSigError } from "./errors.js";

/** Whether a PCF hash algorithm id is cryptographic (spec Section 9). */
export function isCryptoHash(algo: HashAlgo): boolean {
  return (
    algo === HashAlgo.Sha256 ||
    algo === HashAlgo.Sha512 ||
    algo === HashAlgo.Blake3
  );
}

/** One Signed Entry inside a Manifest (spec Section 7.2). */
export interface SignedEntry {
  /** PCF uid of the covered partition (verbatim). */
  uid: Uint8Array;
  /** PCF type of the covered partition (verbatim). */
  partitionType: number;
  /** PCF label of the covered partition (verbatim 32-byte field). */
  label: Uint8Array;
  /** PCF `used_bytes` of the covered partition. */
  usedBytes: bigint;
  /** PCF `data_hash_algo_id`. MUST be cryptographic in v1.0 (16/17/18). */
  dataHashAlgo: HashAlgo;
  /** PCF `data_hash` field bytes (verbatim 64-byte field). */
  dataHash: Uint8Array;
}

/** Serialise a Signed Entry to its on-disk 218-byte layout (spec Section 7.2). */
export function signedEntryToBytes(e: SignedEntry): Uint8Array {
  const b = new Uint8Array(SIGNED_ENTRY_SIZE);
  const view = new DataView(b.buffer);
  b.set(e.uid, 0);
  view.setUint32(16, e.partitionType >>> 0, true);
  b.set(e.label, 20);
  view.setBigUint64(52, e.usedBytes, true);
  b[60] = hashAlgoId(e.dataHashAlgo);
  // b[61] reserved = 0
  b.set(e.dataHash, 62);
  // b[126..218] reserved = 0
  return b;
}

/**
 * Parse a Signed Entry from its on-disk 218-byte layout. Validates the
 * reserved spans, the cryptographic-hash constraint (Section 9), and the PCF
 * reserved-value guards (Section 11, V7).
 */
export function signedEntryFromBytes(b: Uint8Array): SignedEntry {
  if (b.length !== SIGNED_ENTRY_SIZE) {
    throw PcfSigError.malformedSignaturePartition();
  }
  if (b[61] !== 0) {
    throw PcfSigError.nonZeroEntryReserved();
  }
  for (let i = 126; i < 218; i++) {
    if (b[i] !== 0) {
      throw PcfSigError.nonZeroEntryReserved();
    }
  }
  const uid = b.slice(0, UID_SIZE);
  if (uid.every((x) => x === 0)) {
    throw PcfSigError.entryNilUid();
  }
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const partitionType = view.getUint32(16, true);
  if (partitionType === TYPE_RESERVED) {
    throw PcfSigError.entryReservedType();
  }
  const label = b.slice(20, 52);
  const usedBytes = view.getBigUint64(52, true);
  const dataHashAlgo = hashAlgoFromId(b[60]!);
  if (!isCryptoHash(dataHashAlgo)) {
    throw PcfSigError.nonCryptoEntryHash(b[60]!);
  }
  const dataHash = b.slice(62, 62 + HASH_FIELD_SIZE);
  return {
    uid,
    partitionType,
    label,
    usedBytes,
    dataHashAlgo,
    dataHash,
  };
}

/** A parsed Manifest (spec Section 7.1). */
export interface Manifest {
  /** `manifest_version_major`. */
  versionMajor: number;
  /** `manifest_version_minor`. */
  versionMinor: number;
  /** `sig_algo_id`. */
  sigAlgo: SigAlgo;
  /** `manifest_hash_algo_id`. MUST be cryptographic (16/17/18). */
  manifestHashAlgo: HashAlgo;
  /** Reserved `flags` field; v1.0 MUST be 0. */
  flags: number;
  /** Signer key fingerprint. */
  signerKeyFingerprint: Uint8Array;
  /** `signed_at_unix_seconds` (i64). */
  signedAtUnixSeconds: bigint;
  /** `signed_entries`, packed in writer-chosen order. */
  signedEntries: SignedEntry[];
}

/** Construct a Manifest from its component parts. */
export function makeManifest(
  sigAlgo: SigAlgo,
  manifestHashAlgo: HashAlgo,
  signerKeyFingerprint: Uint8Array,
  signedAtUnixSeconds: bigint,
  signedEntries: SignedEntry[],
): Manifest {
  return {
    versionMajor: PROFILE_VERSION_MAJOR,
    versionMinor: PROFILE_VERSION_MINOR,
    sigAlgo,
    manifestHashAlgo,
    flags: 0,
    signerKeyFingerprint: new Uint8Array(signerKeyFingerprint),
    signedAtUnixSeconds,
    signedEntries,
  };
}

/** Serialised length in bytes. */
export function manifestByteLen(m: Manifest): number {
  return MANIFEST_PREFIX_SIZE + SIGNED_ENTRY_SIZE * m.signedEntries.length;
}

/** Serialise a Manifest to the on-disk byte layout (spec Section 7.1). */
export function manifestToBytes(m: Manifest): Uint8Array {
  const out = new Uint8Array(manifestByteLen(m));
  const view = new DataView(out.buffer);
  out.set(SIG_MAGIC, 0);
  view.setUint16(8, m.versionMajor, true);
  view.setUint16(10, m.versionMinor, true);
  out[12] = sigAlgoId(m.sigAlgo);
  out[13] = hashAlgoId(m.manifestHashAlgo);
  view.setUint16(14, m.flags, true);
  out.set(m.signerKeyFingerprint, 16);
  view.setBigInt64(48, m.signedAtUnixSeconds, true);
  view.setUint32(56, m.signedEntries.length, true);
  for (let i = 0; i < m.signedEntries.length; i++) {
    out.set(
      signedEntryToBytes(m.signedEntries[i]!),
      MANIFEST_PREFIX_SIZE + i * SIGNED_ENTRY_SIZE,
    );
  }
  return out;
}

/**
 * Parse a Manifest from the on-disk byte layout. Validates: magic, major
 * version, algorithm registry membership, hash-algo binding (Section 8),
 * cryptographic hash requirement (Section 9), reserved flags, non-empty
 * signed_count, and per-entry reserved spans (Section 7.2). Does NOT validate
 * duplicate uids or self-reference; the verifier does that with context from
 * the enclosing partition.
 */
export function manifestFromBytes(b: Uint8Array): Manifest {
  if (b.length < MANIFEST_PREFIX_SIZE) {
    throw PcfSigError.malformedSignaturePartition();
  }
  if (!bytesEqual(b.subarray(0, 8), SIG_MAGIC)) {
    throw PcfSigError.badManifestMagic();
  }
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const versionMajor = view.getUint16(8, true);
  const versionMinor = view.getUint16(10, true);
  if (versionMajor !== PROFILE_VERSION_MAJOR) {
    throw PcfSigError.unsupportedMajor(versionMajor);
  }
  const sigAlgo = sigAlgoFromId(b[12]!);
  const manifestHashId = b[13]!;
  const manifestHashAlgo = hashAlgoFromId(manifestHashId);
  if (!isCryptoHash(manifestHashAlgo)) {
    throw PcfSigError.nonCryptoManifestHash(manifestHashId);
  }
  const required = requiredManifestHash(sigAlgo);
  if (required !== null && required !== manifestHashAlgo) {
    throw PcfSigError.hashAlgoBindingMismatch();
  }
  const flags = view.getUint16(14, true);
  if (flags !== 0) {
    throw PcfSigError.nonZeroFlags();
  }
  const signerKeyFingerprint = b.slice(16, 16 + FINGERPRINT_SIZE);
  const signedAtUnixSeconds = view.getBigInt64(48, true);
  const signedCount = view.getUint32(56, true);
  if (signedCount === 0) {
    throw PcfSigError.emptyManifest();
  }
  const expected = MANIFEST_PREFIX_SIZE + SIGNED_ENTRY_SIZE * signedCount;
  if (b.length < expected) {
    throw PcfSigError.malformedSignaturePartition();
  }
  const signedEntries: SignedEntry[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < signedCount; i++) {
    const off = MANIFEST_PREFIX_SIZE + i * SIGNED_ENTRY_SIZE;
    const e = signedEntryFromBytes(b.slice(off, off + SIGNED_ENTRY_SIZE));
    const key = uidKey(e.uid);
    if (seen.has(key)) {
      throw PcfSigError.duplicateSignedUid();
    }
    seen.add(key);
    signedEntries.push(e);
  }
  return {
    versionMajor,
    versionMinor,
    sigAlgo,
    manifestHashAlgo,
    flags,
    signerKeyFingerprint,
    signedAtUnixSeconds,
    signedEntries,
  };
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function uidKey(uid: Uint8Array): string {
  let s = "";
  for (let i = 0; i < uid.length; i++) {
    s += uid[i]!.toString(16).padStart(2, "0");
  }
  return s;
}
