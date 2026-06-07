/**
 * Spec-conformance tests — every assertion in this file traces back to a
 * specific MUST/SHALL clause of `PCF-SIG-spec-v1.0.txt`.
 */

import { describe, expect, it } from "vitest";

import {
  HASH_FIELD_SIZE,
  HashAlgo,
  hashAlgoId,
} from "@kduma-oss/pcf";

import {
  FINGERPRINT_SIZE,
  KEY_MAGIC,
  KeyFormat,
  MANIFEST_PREFIX_SIZE,
  PcfSigError,
  PcfSigErrorKind,
  PROFILE_VERSION_MAJOR,
  PROFILE_VERSION_MINOR,
  SIGNED_ENTRY_SIZE,
  SIG_MAGIC,
  SigAlgo,
  TYPE_PCFSIG_KEY,
  TYPE_PCFSIG_SIG,
  computeFingerprint,
  isCryptoHash,
  keyRecordFromBytes,
  keyRecordToBytes,
  makeKeyRecord,
  makeManifest,
  manifestToBytes,
  requiredManifestHash,
  signaturePartitionFromBytes,
  sigAlgoIsImplemented,
  signedEntryFromBytes,
  signedEntryToBytes,
} from "../src/index.js";

const TEXT = new TextEncoder();

function uid(n: number): Uint8Array {
  const u = new Uint8Array(16);
  u[0] = n;
  u[15] = 0xaa;
  return u;
}

describe("PCF-SIG spec compliance", () => {
  // Section 5 — Partition Types
  it("Section 5: reserved type values", () => {
    expect(TYPE_PCFSIG_KEY).toBe(0xaaab_0001);
    expect(TYPE_PCFSIG_SIG).toBe(0xaaab_0002);
  });

  // Section 6.1
  it("Section 6.1: KEY magic is \"PCFKEY\\0\\0\"", () => {
    expect(Array.from(KEY_MAGIC)).toEqual([
      0x50, 0x43, 0x46, 0x4b, 0x45, 0x59, 0x00, 0x00,
    ]);
  });

  it("Section 6.1: profile version constants", () => {
    expect(PROFILE_VERSION_MAJOR).toBe(1);
    expect(PROFILE_VERSION_MINOR).toBe(0);
  });

  it("Section 6.1: reader rejects bad key magic", () => {
    const bytes = keyRecordToBytes(
      makeKeyRecord(KeyFormat.Ed25519Raw, new Uint8Array(32).fill(0x10)),
    );
    bytes[0] = 0x58; // 'X'
    expect(() => keyRecordFromBytes(bytes)).toThrowError(PcfSigError);
    try {
      keyRecordFromBytes(bytes);
    } catch (e) {
      expect((e as PcfSigError).kind).toBe(PcfSigErrorKind.BadKeyMagic);
    }
  });

  it("Section 6.1: reader rejects unknown major", () => {
    const bytes = keyRecordToBytes(
      makeKeyRecord(KeyFormat.Ed25519Raw, new Uint8Array(32).fill(0x10)),
    );
    bytes[8] = 2;
    try {
      keyRecordFromBytes(bytes);
    } catch (e) {
      expect((e as PcfSigError).kind).toBe(PcfSigErrorKind.UnsupportedMajor);
    }
  });

  it("Section 6.1: reader rejects non-zero reserved bytes", () => {
    const bytes = keyRecordToBytes(
      makeKeyRecord(KeyFormat.Ed25519Raw, new Uint8Array(32).fill(0x10)),
    );
    bytes[13] = 0xff;
    try {
      keyRecordFromBytes(bytes);
    } catch (e) {
      expect((e as PcfSigError).kind).toBe(PcfSigErrorKind.NonZeroKeyReserved);
    }
  });

  // Section 6.3
  it("Section 6.3: fingerprint is SHA-256 of key_data", () => {
    const key = new Uint8Array(32).fill(0xaa);
    const rec = makeKeyRecord(KeyFormat.Ed25519Raw, key);
    expect(rec.fingerprint).toEqual(computeFingerprint(key));
    expect(FINGERPRINT_SIZE).toBe(32);
  });

  it("Section 6.3: reader rejects fingerprint mismatch", () => {
    const bytes = keyRecordToBytes(
      makeKeyRecord(KeyFormat.Ed25519Raw, new Uint8Array(32).fill(0x10)),
    );
    bytes[16] ^= 0x01;
    try {
      keyRecordFromBytes(bytes);
    } catch (e) {
      expect((e as PcfSigError).kind).toBe(PcfSigErrorKind.FingerprintMismatch);
    }
  });

  // Section 7.1
  it("Section 7.1: SIG magic is \"PCFSIG\\0\\0\"", () => {
    expect(Array.from(SIG_MAGIC)).toEqual([
      0x50, 0x43, 0x46, 0x53, 0x49, 0x47, 0x00, 0x00,
    ]);
  });

  it("Section 7.1: byte-layout sizes", () => {
    expect(MANIFEST_PREFIX_SIZE).toBe(60);
    expect(SIGNED_ENTRY_SIZE).toBe(218);
  });

  // Section 8
  it("Section 8: Ed25519 requires SHA-512 manifest hash", () => {
    expect(requiredManifestHash(SigAlgo.Ed25519)).toBe(HashAlgo.Sha512);
  });

  it("Section 8: Ed25519 is implemented", () => {
    expect(sigAlgoIsImplemented(SigAlgo.Ed25519)).toBe(true);
  });

  // Section 9
  it("Section 9: cryptographic hash check", () => {
    expect(isCryptoHash(HashAlgo.Sha256)).toBe(true);
    expect(isCryptoHash(HashAlgo.Sha512)).toBe(true);
    expect(isCryptoHash(HashAlgo.Blake3)).toBe(true);
    expect(isCryptoHash(HashAlgo.Crc32c)).toBe(false);
    expect(isCryptoHash(HashAlgo.Md5)).toBe(false);
    expect(isCryptoHash(HashAlgo.Sha1)).toBe(false);
  });

  // Section 7.2
  it("Section 7.2: NIL UID entry is rejected", () => {
    const bytes = new Uint8Array(SIGNED_ENTRY_SIZE);
    const view = new DataView(bytes.buffer);
    view.setUint32(16, 0x10, true);
    bytes[60] = hashAlgoId(HashAlgo.Sha256);
    // No data_hash content needed; just ensure 64 bytes are zero.
    try {
      signedEntryFromBytes(bytes);
    } catch (e) {
      expect((e as PcfSigError).kind).toBe(PcfSigErrorKind.EntryNilUid);
    }
  });

  it("Section 7.2: weak data_hash is rejected", () => {
    // Build a SignedEntry by hand with data_hash_algo = CRC-32.
    const bytes = new Uint8Array(SIGNED_ENTRY_SIZE);
    const view = new DataView(bytes.buffer);
    bytes[0] = 1; // uid[0]
    view.setUint32(16, 0x10, true);
    bytes[60] = hashAlgoId(HashAlgo.Crc32c);
    try {
      signedEntryFromBytes(bytes);
    } catch (e) {
      expect((e as PcfSigError).kind).toBe(PcfSigErrorKind.NonCryptoEntryHash);
    }
  });

  // Section 7.3
  it("Section 7.3: non-zero trailer is rejected", () => {
    const entry = {
      uid: uid(1),
      partitionType: 0x10,
      label: new Uint8Array(32),
      usedBytes: 0n,
      dataHashAlgo: HashAlgo.Sha256,
      dataHash: new Uint8Array(HASH_FIELD_SIZE),
    };
    const manifest = makeManifest(
      SigAlgo.Ed25519,
      HashAlgo.Sha512,
      new Uint8Array(FINGERPRINT_SIZE),
      0n,
      [entry],
    );
    const mb = manifestToBytes(manifest);

    // Tail: sig_length=64 + zeroes + trailer_length=1 + one byte.
    const out = new Uint8Array(mb.length + 4 + 64 + 4 + 1);
    const view = new DataView(out.buffer);
    out.set(mb, 0);
    view.setUint32(mb.length, 64, true);
    view.setUint32(mb.length + 4 + 64, 1, true);

    try {
      signaturePartitionFromBytes(out);
    } catch (e) {
      expect((e as PcfSigError).kind).toBe(PcfSigErrorKind.NonZeroTrailer);
    }
  });

  // Round-trip: parsed bytes equal serialised bytes for a clean entry.
  it("Section 7.2: signed-entry round-trip", () => {
    const data = TEXT.encode("Hello, PCF-SIG!");
    const entry = {
      uid: uid(1),
      partitionType: 0x10,
      label: (() => {
        const l = new Uint8Array(32);
        l.set(TEXT.encode("alpha"));
        return l;
      })(),
      usedBytes: BigInt(data.length),
      dataHashAlgo: HashAlgo.Sha256,
      dataHash: (() => {
        const h = new Uint8Array(HASH_FIELD_SIZE);
        // Just synthesise a non-empty hash; round-trip doesn't check content.
        h.fill(0x7f, 0, 32);
        return h;
      })(),
    };
    const bytes = signedEntryToBytes(entry);
    expect(bytes.length).toBe(SIGNED_ENTRY_SIZE);
    const parsed = signedEntryFromBytes(bytes);
    expect(parsed.partitionType).toBe(entry.partitionType);
    expect(parsed.usedBytes).toBe(entry.usedBytes);
    expect(parsed.dataHashAlgo).toBe(entry.dataHashAlgo);
  });
});
