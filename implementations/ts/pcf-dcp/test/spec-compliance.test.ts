/**
 * Conformance tests tied to specific sections of `PCF-DCP-spec-v1.0.txt`.
 */

import { describe, expect, it } from "vitest";
import { computeHashField, HashAlgo } from "@kduma-oss/pcf";

import {
  Arena,
  Chunker,
  DCP_CONTAINER_TYPE,
  DCP_HEADER_SIZE,
  dcpHeaderFromBytes,
  dcpHeaderToBytes,
  FRAGMENT_ENTRY_SIZE,
  FRAGTABLE_HEADER_SIZE,
  fragmentEntryFromBytes,
  fragmentEntryToBytes,
  fragTableHeaderFromBytes,
  fragTableHeaderToBytes,
} from "../src/index.js";
import { dec, enc, fill, hex } from "./helpers.js";

describe("spec compliance", () => {
  it("structure sizes match Appendix A", () => {
    expect(DCP_HEADER_SIZE).toBe(24);
    expect(FRAGTABLE_HEADER_SIZE).toBe(9);
    expect(FRAGMENT_ENTRY_SIZE).toBe(18);
    expect(DCP_CONTAINER_TYPE).toBe(0xaaac_0001);
  });

  it("header round-trips and carries the magic", () => {
    const h = {
      profileVersionMajor: 1,
      profileVersionMinor: 0,
      flags: 0,
      innerTableOffset: 109,
      arenaUsed: 465,
    };
    const b = dcpHeaderToBytes(h);
    expect(Array.from(b.subarray(0, 4))).toEqual([0x50, 0x44, 0x43, 0x50]);
    expect(dcpHeaderFromBytes(b)).toEqual(h);
  });

  it("fragment records round-trip", () => {
    const e = { extentOffset: 31, extentLength: 6, kind: 1, flags: 1 };
    expect(fragmentEntryFromBytes(fragmentEntryToBytes(e))).toEqual(e);
    const h = { nextFragtableOffset: 0, fragmentCount: 2 };
    expect(fragTableHeaderFromBytes(fragTableHeaderToBytes(h))).toEqual(h);
  });

  it("reconstruction equals the logical content", () => {
    const a = new Arena();
    a.addInner(0x10, fill(1), "x", enc("Hello, World!"), HashAlgo.Sha256, Chunker.fixed(7));
    expect(dec(a.content(fill(1)))).toBe("Hello, World!");
    const info = a.innerInfo(fill(1));
    expect(info.usedBytes).toBe(13);
    expect(info.extents).toHaveLength(2);
  });

  it("data_hash is invariant under fragmentation", () => {
    const mk = (c: Chunker): string => {
      const a = new Arena();
      a.addInner(0x10, fill(7), "x", enc("abcdefghij"), HashAlgo.Sha256, c);
      return hex(a.innerInfo(fill(7)).dataHash);
    };
    expect(mk(Chunker.whole())).toBe(mk(Chunker.fixed(3)));
    expect(mk(Chunker.whole())).toBe(hex(computeHashField(HashAlgo.Sha256, enc("abcdefghij"))));
  });

  it("dedup sets SHARED on all aliases (rule F1)", () => {
    const a = new Arena();
    a.addInner(0x10, fill(0xa1), "A", enc("Hello, World!"), HashAlgo.Sha256, Chunker.fixed(7));
    a.addInner(0x10, fill(0xb2), "B", enc("World!"), HashAlgo.Sha256, Chunker.whole());

    const ia = a.innerInfo(fill(0xa1));
    const ib = a.innerInfo(fill(0xb2));
    expect(ia.extents[0]!.shared).toBe(false);
    expect(ia.extents[1]!.shared).toBe(true);
    expect(ib.extents).toHaveLength(1);
    expect(ib.extents[0]!.shared).toBe(true);
    expect(hex(ib.dataHash)).toBe(hex(computeHashField(HashAlgo.Sha256, enc("World!"))));
  });

  it("parse round-trips the canonical arena byte-exact", () => {
    const a = new Arena();
    a.addInner(0x10, fill(0xa1), "A", enc("Hello, World!"), HashAlgo.Sha256, Chunker.fixed(7));
    a.addInner(0x10, fill(0xb2), "B", enc("World!"), HashAlgo.Sha256, Chunker.whole());
    const bytes = a.toBytes();
    expect(hex(Arena.parse(bytes).toBytes())).toBe(hex(bytes));
  });
});
