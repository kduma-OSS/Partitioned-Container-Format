/**
 * Spec-conformance tests — every assertion traces back to a specific
 * MUST/SHALL clause of `PCF-spec-v1.0.txt`. Organised by spec section so
 * reviewers can pair each test with its normative source.
 */

import { describe, expect, it } from "vitest";

import {
  computeHashField,
  computeTableHash,
  Container,
  decodeLabel,
  digestLen,
  ENTRY_SIZE,
  encodeLabel,
  entryToBytes,
  freeBytes,
  HASH_FIELD_SIZE,
  HEADER_SIZE,
  HashAlgo,
  hashAlgoFromId,
  hashAlgoId,
  headerToBytes,
  LABEL_SIZE,
  MAGIC,
  MemoryStorage,
  NIL_UID,
  type PartitionEntry,
  PcfErrorKind,
  TABLE_HEADER_SIZE,
  tableHeaderFromBytes,
  tableHeaderToBytes,
  TYPE_RAW,
  TYPE_RESERVED,
  UID_SIZE,
  validateEntry,
  verifyHashField,
  VERSION_MAJOR,
  VERSION_MINOR,
} from "../src/index.js";
import { bytes, expectKind, snapshot, uid } from "./helpers.js";

function sampleEntry(over: Partial<PartitionEntry> = {}): PartitionEntry {
  return {
    partitionType: 1,
    uid: uid(1),
    label: encodeLabel("x"),
    startOffset: 0n,
    maxLength: 0n,
    usedBytes: 0n,
    dataHashAlgo: HashAlgo.None,
    dataHash: new Uint8Array(HASH_FIELD_SIZE),
    ...over,
  };
}

// === Section 2.3 — Data Types and Byte Order =============================

describe("§2.3 byte order", () => {
  it("multi-byte integers are little-endian", () => {
    const h = headerToBytes({
      versionMajor: 0x0201,
      versionMinor: 0x0403,
      partitionTableOffset: 0x0807_0605_0403_0201n,
    });
    expect([...h.slice(8, 10)]).toEqual([0x01, 0x02]);
    expect([...h.slice(10, 12)]).toEqual([0x03, 0x04]);
    expect([...h.slice(12, 20)]).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
  });
});

// === Section 4 — File Header ==============================================

describe("§4 file header", () => {
  it("is exactly 20 bytes", () => {
    expect(HEADER_SIZE).toBe(20);
    expect(
      headerToBytes({ versionMajor: 1, versionMinor: 0, partitionTableOffset: 20n })
        .length,
    ).toBe(20);
  });

  it("magic bytes match the specification", () => {
    expect([...MAGIC]).toEqual([0x89, 0x4b, 0x50, 0x52, 0x54, 0x0d, 0x0a, 0x1a]);
  });

  it("reader rejects bad magic", () => {
    const b = new Uint8Array(20);
    b.set(bytes("NOTAPCF!"), 0);
    expectKind(() => Container.open(new MemoryStorage(b)), PcfErrorKind.BadMagic);
  });

  it("reader rejects an unsupported major", () => {
    const b = headerToBytes({
      versionMajor: 2,
      versionMinor: 0,
      partitionTableOffset: 20n,
    });
    expectKind(
      () => Container.open(new MemoryStorage(b)),
      PcfErrorKind.UnsupportedMajor,
    );
  });
});

// === Section 5.1 — Table Block Header =====================================

describe("§5.1 table block header", () => {
  it("is 74 bytes", () => {
    expect(TABLE_HEADER_SIZE).toBe(74);
    expect(
      tableHeaderToBytes({
        partitionCount: 0,
        nextTableOffset: 0n,
        tableHashAlgo: HashAlgo.Sha256,
        tableHash: new Uint8Array(HASH_FIELD_SIZE),
      }).length,
    ).toBe(74);
  });

  it("partition_count is a u8", () => {
    const parsed = tableHeaderFromBytes(
      tableHeaderToBytes({
        partitionCount: 255,
        nextTableOffset: 0n,
        tableHashAlgo: HashAlgo.Sha256,
        tableHash: new Uint8Array(HASH_FIELD_SIZE),
      }),
    );
    expect(parsed.partitionCount).toBe(255);
  });

  it("chain traversal stops at zero", () => {
    const c = Container.create();
    c.addPartition(1, uid(1), "only", bytes("x"), 0, HashAlgo.Sha256);
    expect(c.entries().length).toBe(1);
  });
});

// === Section 5.2 — Partition Entry ========================================

describe("§5.2 partition entry", () => {
  it("is 141 bytes", () => {
    expect(ENTRY_SIZE).toBe(141);
    expect(entryToBytes(sampleEntry()).length).toBe(141);
  });

  it("used_bytes must not exceed max_length", () => {
    expectKind(
      () => validateEntry(sampleEntry({ maxLength: 10n, usedBytes: 11n })),
      PcfErrorKind.UsedExceedsMax,
    );
  });

  it("free byte count is derived", () => {
    expect(freeBytes(sampleEntry({ maxLength: 100n, usedBytes: 30n }))).toBe(70n);
  });
});

// === Section 5.3 — Overflow Table Blocks ==================================

describe("§5.3 overflow blocks", () => {
  it("more than 255 partitions use an overflow chain", () => {
    const c = Container.createWith(new MemoryStorage(), 255, HashAlgo.Sha256);
    for (let i = 0; i < 260; i++) {
      const u = new Uint8Array(16);
      new DataView(u.buffer).setUint32(0, i, true);
      u[15] = 0xcc;
      c.addPartition(i + 1, u, "x", new Uint8Array([i & 0xff]), 0, HashAlgo.Crc32c);
    }
    const image = c.compactedImage();
    const view = new DataView(image.buffer, image.byteOffset, image.byteLength);
    expect(image[20]).toBe(255);
    const next = view.getBigUint64(21, true);
    expect(next).not.toBe(0n);
    const secondOff = Number(next);
    expect(image[secondOff]).toBe(5);
    expect(view.getBigUint64(secondOff + 1, true)).toBe(0n);
  });

  it("an empty block is valid", () => {
    const c = Container.create();
    const image = c.compactedImage();
    const c2 = Container.open(new MemoryStorage(image));
    c2.verify();
    expect(image[20]).toBe(0);
    expect(c2.entries().length).toBe(0);
  });
});

// === Section 7.1 — Reserved Partition Types ===============================

describe("§7.1 reserved types", () => {
  it("type zero is rejected by the writer", () => {
    const c = Container.create();
    expectKind(
      () => c.addPartition(TYPE_RESERVED, uid(1), "x", bytes("x"), 0, HashAlgo.Sha256),
      PcfErrorKind.ReservedType,
    );
  });

  it("type zero in an existing entry fails validate", () => {
    expectKind(
      () => validateEntry(sampleEntry({ partitionType: 0 })),
      PcfErrorKind.ReservedType,
    );
  });

  it("the maximum application type is accepted", () => {
    const c = Container.create();
    c.addPartition(0xffff_fffe, uid(1), "edge", bytes("x"), 0, HashAlgo.Sha256);
    c.verify();
    expect(c.entries()[0]!.partitionType).toBe(0xffff_fffe);
  });

  it("the RAW type is allowed", () => {
    const c = Container.create();
    c.addPartition(TYPE_RAW, uid(1), "raw", new Uint8Array([0, 0xff]), 0, HashAlgo.Crc32c);
    c.verify();
  });
});

// === Section 7.2 — Reserved UID ===========================================

describe("§7.2 reserved UID", () => {
  it("the NIL UID is rejected by the writer", () => {
    const c = Container.create();
    expectKind(
      () => c.addPartition(1, NIL_UID, "x", bytes("x"), 0, HashAlgo.Sha256),
      PcfErrorKind.NilUid,
    );
  });

  it("the NIL UID in an existing entry fails validate", () => {
    expectKind(
      () => validateEntry(sampleEntry({ uid: new Uint8Array(UID_SIZE) })),
      PcfErrorKind.NilUid,
    );
  });
});

// === Section 8.1 — Hash Algorithm Registry ================================

describe("§8.1 hash registry", () => {
  it("every registered id maps back to itself", () => {
    for (const id of [0, 1, 2, 3, 4, 5, 16, 17, 18]) {
      expect(hashAlgoId(hashAlgoFromId(id))).toBe(id);
    }
  });

  it("reserved ids are rejected", () => {
    for (let id = 6; id <= 15; id++) {
      expectKind(() => hashAlgoFromId(id), PcfErrorKind.UnknownHashAlgo);
    }
    for (let id = 19; id <= 30; id++) {
      expectKind(() => hashAlgoFromId(id), PcfErrorKind.UnknownHashAlgo);
    }
  });

  it("CRC-64/XZ canonical check value", () => {
    const f = computeHashField(HashAlgo.Crc64, bytes("123456789"));
    const v = new DataView(f.buffer, f.byteOffset, f.byteLength).getBigUint64(0, true);
    expect(v).toBe(0x995d_c9bb_df19_39fan);
  });
});

// === Section 8.2 — Hash Field Encoding ====================================

describe("§8.2 hash field encoding", () => {
  it("hash field size is 64", () => {
    expect(HASH_FIELD_SIZE).toBe(64);
  });

  it("digests are left-aligned and zero-padded", () => {
    for (const algo of [
      HashAlgo.Md5,
      HashAlgo.Sha1,
      HashAlgo.Sha256,
      HashAlgo.Sha512,
      HashAlgo.Blake3,
    ]) {
      const f = computeHashField(algo, bytes("some content"));
      const n = digestLen(algo);
      expect(f.slice(n).every((b) => b === 0)).toBe(true);
    }
  });

  it("CRCs are little-endian, left-aligned and zero-padded", () => {
    expect(computeHashField(HashAlgo.Crc32, bytes("abc")).slice(4).every((b) => b === 0)).toBe(true);
    expect(computeHashField(HashAlgo.Crc32c, bytes("abc")).slice(4).every((b) => b === 0)).toBe(true);
    expect(computeHashField(HashAlgo.Crc64, bytes("abc")).slice(8).every((b) => b === 0)).toBe(true);
  });

  it("None is all zero and always verifies", () => {
    const f = computeHashField(HashAlgo.None, bytes("anything"));
    expect(f.every((b) => b === 0)).toBe(true);
    const anything = new Uint8Array(HASH_FIELD_SIZE).fill(0xff);
    anything[0] = 0;
    expect(verifyHashField(HashAlgo.None, bytes("data"), anything)).toBe(true);
  });

  it("reader compares only significant bytes", () => {
    const f = computeHashField(HashAlgo.Crc32c, bytes("hello"));
    f[10] = 0x99; // garbage in the unused tail
    expect(verifyHashField(HashAlgo.Crc32c, bytes("hello"), f)).toBe(true);
  });
});

// === Section 8.3 — Partition Data Hash ====================================

describe("§8.3 partition data hash", () => {
  it("covers used bytes only and ignores the reservation", () => {
    const c = Container.create();
    c.addPartition(1, uid(1), "p", bytes("hello"), 1024, HashAlgo.Sha256);
    const e = c.entries();
    expect(e[0]!.dataHash).toEqual(computeHashField(HashAlgo.Sha256, bytes("hello")));
    c.verify();
  });

  it("an empty partition hashes the empty input", () => {
    const c = Container.create();
    c.addPartition(1, uid(1), "p", bytes(""), 0, HashAlgo.Sha256);
    const e = c.entries();
    expect(e[0]!.usedBytes).toBe(0n);
    expect(e[0]!.dataHash).toEqual(computeHashField(HashAlgo.Sha256, bytes("")));
    c.verify();
  });
});

// === Section 8.4 — Table Block Hash =======================================

describe("§8.4 table block hash", () => {
  it("depends on the algo id", () => {
    const hSha = computeTableHash(HashAlgo.Sha256, 0n, []);
    const hBlake = computeTableHash(HashAlgo.Blake3, 0n, []);
    expect(hSha.slice(0, 32)).not.toEqual(hBlake.slice(0, 32));
  });

  it("treats the hash field as zero during computation", () => {
    const c = Container.create();
    c.addPartition(1, uid(1), "p", bytes("abc"), 0, HashAlgo.Sha256);
    c.verify();
  });
});

// === Section 8.5 — Hash Cascade ===========================================

describe("§8.5 hash cascade", () => {
  it("an update cascades to the table hash", () => {
    const c = Container.create();
    c.addPartition(1, uid(1), "p", bytes("old"), 100, HashAlgo.Sha256);
    c.updatePartitionData(uid(1), bytes("new value"));
    c.verify();
  });
});

// === Section 9 — Versioning ===============================================

describe("§9 versioning", () => {
  it("a higher minor is accepted", () => {
    const b = new Uint8Array(HEADER_SIZE + TABLE_HEADER_SIZE);
    b.set(MAGIC, 0);
    const dv = new DataView(b.buffer);
    dv.setUint16(8, VERSION_MAJOR, true);
    dv.setUint16(10, 999, true);
    dv.setBigUint64(12, 20n, true);
    // Empty block with HashAlgo.None — no hash verification needed.
    b[20] = 0; // partition_count
    dv.setBigUint64(21, 0n, true); // next_table_offset
    b[29] = 0; // table_hash_algo = none
    const c = Container.open(new MemoryStorage(b));
    expect(c.header().versionMinor).toBe(999);
    c.verify();
  });
});

// === Section 10 — Labels ==================================================

describe("§10 labels", () => {
  it("label is NUL-terminated", () => {
    const l = encodeLabel("abc");
    expect([...l.slice(0, 3)]).toEqual([...bytes("abc")]);
    expect(l.slice(3).every((b) => b === 0)).toBe(true);
    expect(decodeLabel(l)).toBe("abc");
  });

  it("a full 32-byte label has no terminator", () => {
    const s = "a".repeat(32);
    const l = encodeLabel(s);
    expect(l[31]).toBe(0x61);
    expect(decodeLabel(l)).toBe(s);
  });

  it("an empty label is all zero", () => {
    const l = encodeLabel("");
    expect(l.every((b) => b === 0)).toBe(true);
    expect(decodeLabel(l)).toBe("");
  });

  it("a high-bit byte in the label is rejected", () => {
    const l = new Uint8Array(LABEL_SIZE);
    l[0] = 0x61;
    l[1] = 0xff;
    expectKind(() => decodeLabel(l), PcfErrorKind.InvalidLabel);
  });
});

// === Section 12 — Conformance and Validation ==============================

describe("§12 conformance", () => {
  it("C4: table hash is skipped when the algo is None", () => {
    const c = Container.createWith(new MemoryStorage(), 4, HashAlgo.None);
    c.addPartition(1, uid(1), "p", bytes("abc"), 0, HashAlgo.Sha256);
    const image = snapshot(c.intoStorage());
    // Tamper with the table_hash field — verify() must still succeed.
    for (let i = 0; i < HASH_FIELD_SIZE; i++) {
      image[HEADER_SIZE + 10 + i] = 0xff;
    }
    const c2 = Container.open(new MemoryStorage(image));
    c2.verify();
  });

  it("C8: data hash is skipped when the algo is None", () => {
    const c = Container.create();
    c.addPartition(1, uid(1), "p", bytes("original"), 64, HashAlgo.None);
    c.updatePartitionData(uid(1), bytes("different bytes"));
    c.verify();
  });

  it("W2: a duplicate UID is rejected", () => {
    const c = Container.create();
    c.addPartition(1, uid(1), "a", bytes("a"), 0, HashAlgo.Sha256);
    expectKind(
      () => c.addPartition(2, uid(1), "b", bytes("b"), 0, HashAlgo.Sha256),
      PcfErrorKind.DuplicateUid,
    );
  });

  it("W5: label and hash tails are zero-filled on write", () => {
    const c = Container.create();
    c.addPartition(1, uid(1), "ab", bytes("x"), 0, HashAlgo.Crc32c);
    const image = c.compactedImage();
    const e0 = HEADER_SIZE + TABLE_HEADER_SIZE;
    expect(image.slice(e0 + 22, e0 + 52).every((b) => b === 0)).toBe(true);
    expect(image.slice(e0 + 77 + 4, e0 + 77 + 64).every((b) => b === 0)).toBe(true);
  });
});

// === Appendix A — Field Layout Summary ====================================

describe("Appendix A", () => {
  it("constants are authoritative", () => {
    expect(UID_SIZE).toBe(16);
    expect(LABEL_SIZE).toBe(32);
    expect(HASH_FIELD_SIZE).toBe(64);
    expect(HEADER_SIZE).toBe(20);
    expect(TABLE_HEADER_SIZE).toBe(74);
    expect(ENTRY_SIZE).toBe(141);
    expect(VERSION_MAJOR).toBe(1);
    expect(VERSION_MINOR).toBe(0);
  });
});
