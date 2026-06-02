/**
 * Targeted tests exercising error paths and algorithm variants that the
 * happy-path roundtrip suite does not touch. Together with `roundtrip.test.ts`
 * these aim for full coverage of the library.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  computeHashField,
  computeTableHash,
  Container,
  decodeLabel,
  digestLen,
  ENTRY_SIZE,
  encodeLabel,
  entryFromBytes,
  HASH_FIELD_SIZE,
  HEADER_SIZE,
  HashAlgo,
  hashAlgoFromId,
  headerFromBytes,
  headerToBytes,
  LABEL_SIZE,
  MAGIC,
  MemoryStorage,
  NIL_UID,
  NodeFileStorage,
  PcfError,
  PcfErrorKind,
  TABLE_HEADER_SIZE,
  tableHeaderFromBytes,
  tableHeaderToBytes,
  TYPE_RAW,
  TYPE_RESERVED,
  VERSION_MAJOR,
  VERSION_MINOR,
  verifyHashField,
} from "../src/index.js";
import { bytes, expectKind, snapshot, uid } from "./helpers.js";

function hexBytes(s: string): Uint8Array {
  const clean = s.replace(/\s+/g, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// ---- header --------------------------------------------------------------

describe("header", () => {
  it("rejects unsupported major", () => {
    const b = headerToBytes({
      versionMajor: 1,
      versionMinor: 0,
      partitionTableOffset: 20n,
    });
    b[8] = 0x02; // bump major to 2
    try {
      headerFromBytes(b);
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(PcfError);
      expect((e as PcfError).kind).toBe(PcfErrorKind.UnsupportedMajor);
      expect((e as PcfError).value).toBe(2);
    }
  });

  it("accepts a minor higher than the implementation", () => {
    const b = headerToBytes({
      versionMajor: 1,
      versionMinor: 0,
      partitionTableOffset: 20n,
    });
    b[10] = 0x05; // minor = 5
    expect(headerFromBytes(b).versionMinor).toBe(5);
  });
});

// ---- entry / label -------------------------------------------------------

describe("entry and label", () => {
  it("encodeLabel rejects embedded NUL and non-ASCII", () => {
    expectKind(() => encodeLabel("a\0b"), PcfErrorKind.InvalidLabel);
    expectKind(() => encodeLabel("é"), PcfErrorKind.InvalidLabel);
    expectKind(() => encodeLabel("a".repeat(33)), PcfErrorKind.InvalidLabel);
  });

  it("decodeLabel rejects a high-bit byte", () => {
    const l = new Uint8Array(LABEL_SIZE);
    l[0] = 0x61;
    l[1] = 0x80;
    expectKind(() => decodeLabel(l), PcfErrorKind.InvalidLabel);
  });

  it("entryFromBytes propagates an unknown algo id", () => {
    const b = new Uint8Array(ENTRY_SIZE);
    new DataView(b.buffer).setUint32(0, 1, true);
    b[4] = 0x01;
    b[76] = 99; // unknown algo id
    expectKind(() => entryFromBytes(b), PcfErrorKind.UnknownHashAlgo);
  });
});

// ---- hash ----------------------------------------------------------------

describe("hash registry", () => {
  it("rejects an unknown id", () => {
    expectKind(() => hashAlgoFromId(99), PcfErrorKind.UnknownHashAlgo);
  });

  it("digestLen matches the registry", () => {
    expect(digestLen(HashAlgo.None)).toBe(0);
    expect(digestLen(HashAlgo.Crc32)).toBe(4);
    expect(digestLen(HashAlgo.Crc32c)).toBe(4);
    expect(digestLen(HashAlgo.Crc64)).toBe(8);
    expect(digestLen(HashAlgo.Md5)).toBe(16);
    expect(digestLen(HashAlgo.Sha1)).toBe(20);
    expect(digestLen(HashAlgo.Sha256)).toBe(32);
    expect(digestLen(HashAlgo.Sha512)).toBe(64);
    expect(digestLen(HashAlgo.Blake3)).toBe(32);
  });

  it("md5 of the empty string matches the canonical digest", () => {
    const f = computeHashField(HashAlgo.Md5, bytes(""));
    expect(f.slice(0, 16)).toEqual(hexBytes("d41d8cd98f00b204e9800998ecf8427e"));
    expect(f.slice(16).every((x) => x === 0)).toBe(true);
    expect(verifyHashField(HashAlgo.Md5, bytes(""), f)).toBe(true);
  });

  it("sha1 of the empty string matches the canonical digest", () => {
    const f = computeHashField(HashAlgo.Sha1, bytes(""));
    expect(f.slice(0, 20)).toEqual(
      hexBytes("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
    );
    expect(f.slice(20).every((x) => x === 0)).toBe(true);
  });

  it("sha256 of the empty string matches the canonical digest", () => {
    const f = computeHashField(HashAlgo.Sha256, bytes(""));
    expect(f.slice(0, 32)).toEqual(
      hexBytes(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      ),
    );
    expect(f.slice(32).every((x) => x === 0)).toBe(true);
  });

  it("sha512 of the empty string matches the canonical digest", () => {
    const f = computeHashField(HashAlgo.Sha512, bytes(""));
    expect(f.slice(0, 64)).toEqual(
      hexBytes(
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
          "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
      ),
    );
  });

  it("blake3 of the empty string matches the known vector", () => {
    const f = computeHashField(HashAlgo.Blake3, bytes(""));
    expect(f.slice(0, 32)).toEqual(
      hexBytes(
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
      ),
    );
    expect(f.slice(32).every((x) => x === 0)).toBe(true);
  });

  it("CRC check values for '123456789'", () => {
    const dv = (f: Uint8Array, n: 4 | 8) =>
      n === 4
        ? new DataView(f.buffer, f.byteOffset, f.byteLength).getUint32(0, true)
        : new DataView(f.buffer, f.byteOffset, f.byteLength).getBigUint64(0, true);
    expect(dv(computeHashField(HashAlgo.Crc32, bytes("123456789")), 4)).toBe(
      0xcbf43926,
    );
    expect(dv(computeHashField(HashAlgo.Crc32c, bytes("123456789")), 4)).toBe(
      0xe3069283,
    );
    expect(dv(computeHashField(HashAlgo.Crc64, bytes("123456789")), 8)).toBe(
      0x995dc9bbdf1939fan,
    );
  });

  it("verify rejects wrong data", () => {
    const stored = computeHashField(HashAlgo.Sha256, bytes("correct"));
    expect(verifyHashField(HashAlgo.Sha256, bytes("tampered"), stored)).toBe(
      false,
    );
  });
});

// ---- errors --------------------------------------------------------------

describe("errors", () => {
  it("every variant has a non-empty message", () => {
    const cases: PcfError[] = [
      new PcfError(PcfErrorKind.Io, "boom"),
      PcfError.badMagic(),
      PcfError.unsupportedMajor(7),
      PcfError.unknownHashAlgo(42),
      PcfError.reservedType(),
      PcfError.nilUid(),
      PcfError.usedExceedsMax(),
      PcfError.invalidLabel(),
      PcfError.tableHashMismatch(),
      PcfError.dataHashMismatch(),
      PcfError.dataTooLarge(),
      PcfError.notFound(),
      PcfError.duplicateUid(),
    ];
    for (const e of cases) {
      expect(e.message.length).toBeGreaterThan(0);
      expect(e).toBeInstanceOf(Error);
    }
  });
});

// ---- container -----------------------------------------------------------

describe("container", () => {
  it("header accessor and intoStorage", () => {
    const c = Container.create();
    const h = c.header();
    expect(h.versionMajor).toBe(VERSION_MAJOR);
    expect(h.versionMinor).toBe(VERSION_MINOR);
    expect(h.partitionTableOffset).toBe(BigInt(HEADER_SIZE));
    expect(c.intoStorage()).toBeInstanceOf(MemoryStorage);
  });

  it("empty partition reads back as empty and updates to empty", () => {
    const c = Container.create();
    c.addPartition(7, uid(1), "empty", bytes(""), 0, HashAlgo.Sha256);
    const e = c.entries();
    expect(c.readPartitionData(e[0]!).length).toBe(0);
    c.verify();

    c.updatePartitionData(uid(1), bytes(""));
    c.verify();
  });

  it("update of a missing UID is NotFound", () => {
    const c = Container.create();
    c.addPartition(1, uid(1), "x", bytes("x"), 0, HashAlgo.Sha256);
    expectKind(
      () => c.updatePartitionData(uid(99), bytes("y")),
      PcfErrorKind.NotFound,
    );
  });

  it("open rejects bad magic and unsupported major", () => {
    expectKind(
      () => Container.open(new MemoryStorage(new Uint8Array(20))),
      PcfErrorKind.BadMagic,
    );
    const bad = new Uint8Array(20);
    bad.set(MAGIC, 0);
    bad[8] = 9;
    expectKind(
      () => Container.open(new MemoryStorage(bad)),
      PcfErrorKind.UnsupportedMajor,
    );
  });

  it("table hash corruption is detected", () => {
    const c = Container.create();
    c.addPartition(1, uid(1), "p", bytes("payload"), 0, HashAlgo.Sha256);
    const image = snapshot(c.intoStorage());
    // Flip a byte inside the table_hash field (offset HEADER_SIZE + 10).
    image[HEADER_SIZE + 10] ^= 0xff;
    const c2 = Container.open(new MemoryStorage(image));
    expectKind(() => c2.verify(), PcfErrorKind.TableHashMismatch);
  });

  it("compaction with more than one table block", () => {
    const c = Container.createWith(new MemoryStorage(), 255, HashAlgo.Sha256);
    for (let i = 0; i < 260; i++) {
      const u = new Uint8Array(16);
      new DataView(u.buffer).setUint32(0, i, true);
      u[15] = 0x55;
      c.addPartition(i + 1, u, "p", new Uint8Array([i & 0xff]), 0, HashAlgo.Crc32);
    }
    const image = c.compactedImage();
    const c2 = Container.open(new MemoryStorage(image));
    c2.verify();
    expect(c2.entries().length).toBe(260);
  });

  it("verify with the None algorithm skips hash checks", () => {
    const c = Container.createWith(new MemoryStorage(), 4, HashAlgo.None);
    c.addPartition(1, uid(1), "p", bytes("abc"), 0, HashAlgo.None);
    c.verify();
  });

  it("compaction of an empty container is valid", () => {
    const c = Container.create();
    const image = c.compactedImage();
    const c2 = Container.open(new MemoryStorage(image));
    c2.verify();
    expect(c2.entries().length).toBe(0);
  });
});

// ---- table ---------------------------------------------------------------

describe("table block", () => {
  it("computeTableHash changes with the next offset", () => {
    const a = computeTableHash(HashAlgo.Sha256, 0n, []);
    const b = computeTableHash(HashAlgo.Sha256, 4096n, []);
    expect(a).not.toEqual(b);
  });

  it("roundtrips a header with the None hash", () => {
    const h = {
      partitionCount: 0,
      nextTableOffset: 0n,
      tableHashAlgo: HashAlgo.None,
      tableHash: new Uint8Array(HASH_FIELD_SIZE),
    };
    const parsed = tableHeaderFromBytes(tableHeaderToBytes(h));
    expect(parsed.tableHashAlgo).toBe(HashAlgo.None);
  });

  it("tableHeaderFromBytes propagates an unknown algo id", () => {
    const b = new Uint8Array(TABLE_HEADER_SIZE);
    b[9] = 100;
    expectKind(() => tableHeaderFromBytes(b), PcfErrorKind.UnknownHashAlgo);
  });
});

// ---- NodeFileStorage -----------------------------------------------------

describe("NodeFileStorage", () => {
  it("supports a create -> reopen -> verify roundtrip on a real file", () => {
    const dir = mkdtempSync(join(tmpdir(), "pcf-ts-"));
    const path = join(dir, "container.pcf");
    try {
      const store = NodeFileStorage.open(path, true);
      const c = Container.createWith(store, 8, HashAlgo.Sha256);
      c.addPartition(0x10, uid(1), "alpha", bytes("hello file"), 16, HashAlgo.Sha256);
      c.addPartition(TYPE_RAW, uid(2), "raw", new Uint8Array([1, 2, 3]), 0, HashAlgo.Crc32c);
      c.verify();
      store.close();

      const reopened = NodeFileStorage.open(path);
      const c2 = Container.open(reopened);
      c2.verify();
      expect(c2.entries().length).toBe(2);
      reopened.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---- spec section 15: byte-exact test vector -----------------------------

describe("spec section 15", () => {
  it("the canonical compacted image matches byte-for-byte", () => {
    const c = Container.createWith(new MemoryStorage(), 8, HashAlgo.Sha256);
    c.addPartition(
      0x0000_0010,
      new Uint8Array(16).fill(0x11),
      "alpha",
      bytes("Hello, PCF!"),
      0,
      HashAlgo.Sha256,
    );
    c.addPartition(
      TYPE_RAW,
      new Uint8Array(16).fill(0x22),
      "raw",
      new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
      0,
      HashAlgo.Crc32c,
    );
    const image = c.compactedImage();
    expect(image.length).toBe(395);

    const expect395 = new Uint8Array(395);
    const dv = new DataView(expect395.buffer);
    // Header (20 B).
    expect395.set(MAGIC, 0);
    dv.setUint16(8, 1, true);
    dv.setUint16(10, 0, true);
    dv.setBigUint64(12, 20n, true);
    // Table block header @ 0x14.
    expect395[20] = 2; // partition_count
    dv.setBigUint64(21, 0n, true); // next_table_offset
    expect395[29] = 16; // SHA-256
    expect395.set(
      hexBytes(
        "f5ebfe8c26b170f7c97cf92ed24cf61e042bbdfac5099bc7801f0e810fc327b6",
      ),
      30,
    );
    // Entry 0 @ 0x5E.
    const e0 = 0x5e;
    dv.setUint32(e0, 0x0000_0010, true);
    expect395.fill(0x11, e0 + 4, e0 + 20);
    expect395.set(bytes("alpha"), e0 + 20);
    dv.setBigUint64(e0 + 52, 376n, true);
    dv.setBigUint64(e0 + 60, 11n, true);
    dv.setBigUint64(e0 + 68, 11n, true);
    expect395[e0 + 76] = 16; // SHA-256
    expect395.set(
      hexBytes(
        "dc02cf82cec23405617ad4bf901c0975b64a4be57c303a8f5cf0a2c251cb90bc",
      ),
      e0 + 77,
    );
    // Entry 1 @ 0xEB.
    const e1 = 0xeb;
    dv.setUint32(e1, TYPE_RAW, true);
    expect395.fill(0x22, e1 + 4, e1 + 20);
    expect395.set(bytes("raw"), e1 + 20);
    dv.setBigUint64(e1 + 52, 387n, true);
    dv.setBigUint64(e1 + 60, 8n, true);
    dv.setBigUint64(e1 + 68, 8n, true);
    expect395[e1 + 76] = 2; // CRC-32C
    dv.setUint32(e1 + 77, 0x8a2c_bc3b, true);
    // Data region @ 0x178.
    expect395.set(bytes("Hello, PCF!"), 0x178);
    expect395.set(new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]), 0x183);

    expect(image).toEqual(expect395);
  });
});

// ---- constants -----------------------------------------------------------

describe("constants", () => {
  it("match Appendix A", () => {
    expect(HEADER_SIZE).toBe(20);
    expect(TABLE_HEADER_SIZE).toBe(74);
    expect(HASH_FIELD_SIZE).toBe(64);
    expect(LABEL_SIZE).toBe(32);
    expect(ENTRY_SIZE).toBe(141);
    expect(TYPE_RESERVED).toBe(0x0000_0000);
    expect(TYPE_RAW).toBe(0xffff_ffff);
    expect([...NIL_UID]).toEqual([...new Uint8Array(16)]);
  });
});
