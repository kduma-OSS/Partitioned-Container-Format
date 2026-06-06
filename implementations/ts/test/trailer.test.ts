import { describe, expect, it } from "vitest";

import {
  CHAIN_BACKWARD,
  CHAIN_FORWARD,
  Container,
  HashAlgo,
  HEADER_SIZE,
  MemoryStorage,
  PcfErrorKind,
  PT_OFFSET_TRAILER,
  TRAILER_SIZE,
  TYPE_RAW,
  type Trailer,
  trailerFromBytes,
  trailerToBytes,
} from "../src/index.js";
import { expectKind, snapshot, str, uid } from "./helpers.js";

function headerOffset(b: Uint8Array): bigint {
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(12, true);
}

function setSentinel(b: Uint8Array): Uint8Array {
  const out = b.slice();
  new DataView(out.buffer).setBigUint64(12, PT_OFFSET_TRAILER, true);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let p = 0;
  for (const part of parts) {
    out.set(part, p);
    p += part.length;
  }
  return out;
}

function build(): Uint8Array {
  const store = new MemoryStorage();
  const c = Container.createWith(store, 4, HashAlgo.Sha256);
  c.addPartition(0x10, uid(1), "alpha", new TextEncoder().encode("Hello, PCF!"), 0, HashAlgo.Sha256);
  c.addPartition(TYPE_RAW, uid(2), "raw", new Uint8Array([0, 1, 2]), 0, HashAlgo.Crc32c);
  c.finalizeWithTrailer();
  return snapshot(store);
}

describe("file trailer", () => {
  it("finalizeWithTrailer round-trips", () => {
    const bytes = build();
    expect(headerOffset(bytes)).toBe(PT_OFFSET_TRAILER);
    const t = trailerFromBytes(bytes.subarray(bytes.length - TRAILER_SIZE));
    expect(t.partitionTableOffset).toBe(BigInt(HEADER_SIZE));
    expect(t.chainFlags).toBe(CHAIN_FORWARD);

    const c = Container.open(new MemoryStorage(bytes));
    expect(c.header().partitionTableOffset).toBe(PT_OFFSET_TRAILER);
    expect(c.tableHead()).toBe(HEADER_SIZE);
    expect(c.chainIsBackward()).toBe(false);
    c.verify();
    const e = c.entries();
    expect(e.length).toBe(2);
    expect(str(c.readPartitionData(e[0]!))).toBe("Hello, PCF!");
  });

  it("reports the backward flag", () => {
    const store = new MemoryStorage();
    const c = Container.create(store);
    c.addPartition(1, uid(1), "only", new TextEncoder().encode("data"), 0, HashAlgo.Sha256);
    const base = snapshot(store);
    const head = headerOffset(base);
    const trailer: Trailer = { partitionTableOffset: head, chainFlags: CHAIN_BACKWARD };
    const bytes = setSentinel(concat(base, trailerToBytes(trailer)));

    const reopened = Container.open(new MemoryStorage(bytes));
    expect(BigInt(reopened.tableHead())).toBe(head);
    expect(reopened.chainIsBackward()).toBe(true);
    reopened.verify();
    expect(reopened.entries().length).toBe(1);
  });

  it("rejects a missing trailer", () => {
    const store = new MemoryStorage();
    const c = Container.create(store);
    c.addPartition(1, uid(1), "p", new TextEncoder().encode("x"), 0, HashAlgo.Sha256);
    const bytes = setSentinel(snapshot(store));
    expectKind(() => Container.open(new MemoryStorage(bytes)), PcfErrorKind.BadTrailer);
  });

  it("recovers from an aborted append", () => {
    const bytes = concat(build(), new Uint8Array(500).fill(0xab));
    const c = Container.open(new MemoryStorage(bytes));
    expect(c.tableHead()).toBe(HEADER_SIZE);
    c.verify();
    expect(c.entries().length).toBe(2);
  });

  it("skips spurious trailer magic in an aborted tail", () => {
    const fakeA: Trailer = { partitionTableOffset: 5n, chainFlags: CHAIN_FORWARD };
    const fakeB: Trailer = {
      partitionTableOffset: 0xffff_ffff_0000n,
      chainFlags: CHAIN_FORWARD,
    };
    const bytes = concat(build(), trailerToBytes(fakeA), trailerToBytes(fakeB));
    const c = Container.open(new MemoryStorage(bytes));
    expect(c.tableHead()).toBe(HEADER_SIZE);
    c.verify();
    expect(c.entries().length).toBe(2);
  });

  it("trailerFromBytes validates length and magic", () => {
    expectKind(() => trailerFromBytes(new Uint8Array(10)), PcfErrorKind.BadTrailer);
    const good = trailerToBytes({ partitionTableOffset: 20n, chainFlags: CHAIN_FORWARD });
    const bad = good.slice();
    bad[19] = 0; // corrupt the magic
    expectKind(() => trailerFromBytes(bad), PcfErrorKind.BadTrailer);
  });

  it("rejects a header-only sentinel file", () => {
    const store = new MemoryStorage();
    const c = Container.create(store);
    c.addPartition(1, uid(1), "p", new TextEncoder().encode("x"), 0, HashAlgo.Sha256);
    const header = setSentinel(snapshot(store).subarray(0, 20));
    expectKind(() => Container.open(new MemoryStorage(header)), PcfErrorKind.BadTrailer);
  });
});
