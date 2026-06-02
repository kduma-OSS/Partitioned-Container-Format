/** End-to-end tests for the `pcf` TypeScript implementation. */

import { describe, expect, it } from "vitest";

import {
  Container,
  entryLabelString,
  freeBytes,
  HashAlgo,
  MemoryStorage,
  PcfErrorKind,
} from "../src/index.js";
import { bytes, expectKind, snapshot, str, uid } from "./helpers.js";

describe("roundtrip", () => {
  it("create, add, read, verify", () => {
    const c = Container.create();
    c.addPartition(0x10, uid(1), "alpha", bytes("first payload"), 16, HashAlgo.Sha256);
    c.addPartition(0xffff_ffff, uid(2), "blob", bytes("raw bytes"), 0, HashAlgo.Crc32c);

    c.verify();
    const entries = c.entries();
    expect(entries.length).toBe(2);
    expect(entryLabelString(entries[0]!)).toBe("alpha");
    expect(str(c.readPartitionData(entries[0]!))).toBe("first payload");
    expect(str(c.readPartitionData(entries[1]!))).toBe("raw bytes");
    expect(freeBytes(entries[0]!)).toBe(16n);
  });

  it("reopen roundtrip", () => {
    const c = Container.create();
    c.addPartition(1, uid(1), "one", bytes("aaaa"), 8, HashAlgo.Sha256);
    c.addPartition(2, uid(2), "two", bytes("bbbbbb"), 0, HashAlgo.Crc64);
    const image = snapshot(c.intoStorage());

    const c2 = Container.open(new MemoryStorage(image));
    c2.verify();
    const e = c2.entries();
    expect(e.length).toBe(2);
    expect(str(c2.readPartitionData(e[1]!))).toBe("bbbbbb");
  });

  it("update in place and cascade", () => {
    const c = Container.create();
    c.addPartition(1, uid(1), "p", bytes("short"), 100, HashAlgo.Sha256);
    c.updatePartitionData(uid(1), bytes("a longer replacement payload"));
    c.verify();
    const e = c.entries();
    expect(str(c.readPartitionData(e[0]!))).toBe("a longer replacement payload");

    // Exceeding the reservation must fail.
    expectKind(
      () => c.updatePartitionData(uid(1), new Uint8Array(1000)),
      PcfErrorKind.DataTooLarge,
    );
  });

  it("remove partition works", () => {
    const c = Container.create();
    c.addPartition(1, uid(1), "a", bytes("AAAA"), 0, HashAlgo.Sha256);
    c.addPartition(2, uid(2), "b", bytes("BBBB"), 0, HashAlgo.Sha256);
    c.addPartition(3, uid(3), "c", bytes("CCCC"), 0, HashAlgo.Sha256);

    c.removePartition(uid(2));
    c.verify();
    const labels = c.entries().map((e) => entryLabelString(e));
    expect(labels).toEqual(["a", "c"]);

    expectKind(() => c.removePartition(uid(2)), PcfErrorKind.NotFound);
  });

  it("overflow chain", () => {
    // First block capacity of 3 forces overflow blocks for 10 partitions.
    const c = Container.createWith(new MemoryStorage(), 3, HashAlgo.Sha256);
    for (let i = 1; i <= 10; i++) {
      const payload = new Uint8Array(i + 1).fill(i);
      c.addPartition(i, uid(i), `part${i}`, payload, 4, HashAlgo.Sha256);
    }
    c.verify();
    const e = c.entries();
    expect(e.length).toBe(10);
    for (let idx = 0; idx < e.length; idx++) {
      const i = idx + 1;
      expect([...c.readPartitionData(e[idx]!)]).toEqual([
        ...new Uint8Array(i + 1).fill(i),
      ]);
    }
  });

  it("duplicate uid rejected", () => {
    const c = Container.create();
    c.addPartition(1, uid(1), "x", bytes("x"), 0, HashAlgo.Sha256);
    expectKind(
      () => c.addPartition(2, uid(1), "y", bytes("y"), 0, HashAlgo.Sha256),
      PcfErrorKind.DuplicateUid,
    );
  });

  it("reserved type and nil uid rejected", () => {
    const c = Container.create();
    expectKind(
      () => c.addPartition(0, uid(1), "x", bytes("x"), 0, HashAlgo.Sha256),
      PcfErrorKind.ReservedType,
    );
    expectKind(
      () => c.addPartition(1, new Uint8Array(16), "x", bytes("x"), 0, HashAlgo.Sha256),
      PcfErrorKind.NilUid,
    );
  });

  it("corruption is detected", () => {
    const c = Container.create();
    c.addPartition(1, uid(1), "p", bytes("important data"), 0, HashAlgo.Sha256);
    const image = snapshot(c.intoStorage());
    // Flip a byte in the partition data region (the last byte of the file).
    image[image.length - 1] ^= 0xff;

    const c2 = Container.open(new MemoryStorage(image));
    expectKind(() => c2.verify(), PcfErrorKind.DataHashMismatch);
  });

  it("compaction reclaims space and stays valid", () => {
    const c = Container.createWith(new MemoryStorage(), 8, HashAlgo.Sha256);
    for (let i = 1; i <= 5; i++) {
      c.addPartition(i, uid(i), `f${i}`, new Uint8Array(32).fill(i), 4096, HashAlgo.Sha256);
    }
    // Remove a couple to create dead space.
    c.removePartition(uid(2));
    c.removePartition(uid(4));

    const compacted = c.compactedImage();
    const c2 = Container.open(new MemoryStorage(compacted));
    c2.verify();
    const e = c2.entries();
    expect(e.length).toBe(3);
    // After compaction every reservation equals the used size.
    for (const entry of e) {
      expect(entry.maxLength).toBe(entry.usedBytes);
      expect(freeBytes(entry)).toBe(0n);
    }
    expect(e.map((x) => entryLabelString(x))).toEqual(["f1", "f3", "f5"]);
  });

  it("compactInto writes to a storage", () => {
    const c = Container.create();
    c.addPartition(1, uid(1), "p", bytes("payload"), 64, HashAlgo.Sha256);
    const out = new MemoryStorage();
    c.compactInto(out);
    const c2 = Container.open(new MemoryStorage(out.toUint8Array()));
    c2.verify();
    expect(c2.entries().length).toBe(1);
  });
});
