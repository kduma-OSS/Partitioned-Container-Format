/**
 * Error paths and edge cases (spec Sections 8, 13).
 */

import { describe, expect, it } from "vitest";
import { Container, HashAlgo, MemoryStorage } from "@kduma-oss/pcf";

import {
  Arena,
  Chunker,
  DcpReader,
  DcpWriter,
  PcfDcpErrorKind,
  reconstruct,
} from "../src/index.js";
import { enc, expectKind, fill } from "./helpers.js";

describe("coverage / error paths", () => {
  it("rejects a bad arena magic", () => {
    const a = new Arena();
    a.addInner(0x10, fill(1), "x", enc("hi"), HashAlgo.Sha256, Chunker.whole());
    const bytes = a.toBytes();
    bytes[0] = 0x58; // 'X'
    expectKind(() => Arena.parse(bytes), PcfDcpErrorKind.BadDcpMagic);
  });

  it("rejects an unsupported profile major", () => {
    const a = new Arena();
    a.addInner(0x10, fill(1), "x", enc("hi"), HashAlgo.Sha256, Chunker.whole());
    const bytes = a.toBytes();
    bytes[4] = 2;
    expectKind(() => Arena.parse(bytes), PcfDcpErrorKind.UnsupportedProfileMajor);
  });

  it("rejects reserved type, nested container and NIL uid", () => {
    const a = new Arena();
    expectKind(
      () => a.addInner(0, fill(1), "x", enc(""), HashAlgo.None, Chunker.whole()),
      PcfDcpErrorKind.ReservedType,
    );
    expectKind(
      () => a.addInner(0xaaac_0001, fill(1), "x", enc(""), HashAlgo.None, Chunker.whole()),
      PcfDcpErrorKind.NestedContainer,
    );
    expectKind(
      () => a.addInner(0x10, new Uint8Array(16), "x", enc(""), HashAlgo.None, Chunker.whole()),
      PcfDcpErrorKind.NilUid,
    );
  });

  it("rejects a duplicate uid within an arena", () => {
    const a = new Arena();
    a.addInner(0x10, fill(1), "x", enc("a"), HashAlgo.None, Chunker.whole());
    expectKind(
      () => a.addInner(0x10, fill(1), "y", enc("b"), HashAlgo.None, Chunker.whole()),
      PcfDcpErrorKind.DuplicateUid,
    );
  });

  it("rejects a reserved fragment kind and out-of-range extent", () => {
    expectKind(
      () => reconstruct(new Uint8Array(64), [{ extentOffset: 24, extentLength: 1, kind: 2, flags: 0 }], 64),
      PcfDcpErrorKind.BadFragmentKind,
    );
    expectKind(
      () => reconstruct(new Uint8Array(64), [{ extentOffset: 60, extentLength: 100, kind: 1, flags: 0 }], 64),
      PcfDcpErrorKind.OffsetOutOfRange,
    );
  });

  it("allows an empty inner partition", () => {
    const a = new Arena();
    a.addInner(0x10, fill(1), "empty", enc(""), HashAlgo.Sha256, Chunker.whole());
    const info = a.innerInfo(fill(1));
    expect(info.usedBytes).toBe(0);
    expect(info.extents).toHaveLength(0);
    const parsed = Arena.parse(a.toBytes());
    expect(parsed.content(fill(1))).toHaveLength(0);
  });

  it("chains the inner table beyond 255 partitions", () => {
    const a = new Arena();
    for (let i = 0; i < 300; i++) {
      const uid = new Uint8Array(16);
      uid[0] = i & 0xff;
      uid[1] = (i >> 8) & 0xff;
      uid[15] = 1;
      const data = new Uint8Array([i & 0xff, (i >> 8) & 0xff]);
      a.addInner(0x10, uid, "n", data, HashAlgo.Sha256, Chunker.whole());
    }
    expect(a.len()).toBe(300);
    const parsed = Arena.parse(a.toBytes());
    expect(parsed.len()).toBe(300);

    const w = new DcpWriter();
    w.addContainer(fill(0xdc), "big", a);
    const r = DcpReader.open(new MemoryStorage(w.toImage()));
    r.verify();
  });

  it("chains the fragment table beyond 255 extents", () => {
    const a = new Arena();
    const distinct = new Uint8Array(300);
    for (let i = 0; i < 300; i++) distinct[i] = i & 0xff;
    a.addInner(0x10, fill(2), "frag", distinct, HashAlgo.Sha256, Chunker.fixed(1));
    const parsed = Arena.parse(a.toBytes());
    expect(parsed.content(fill(2))).toEqual(distinct);
  });

  it("verify detects a file-wide uid collision", () => {
    const a = new Arena();
    a.addInner(0x10, fill(0xb2), "B", enc("World!"), HashAlgo.Sha256, Chunker.whole());
    const w = new DcpWriter();
    w.addContainer(fill(0xdc), "dcp", a);
    w.addPlain(0x10, fill(0xb2), "dup", enc("x"), HashAlgo.Sha256);
    const r = DcpReader.open(new MemoryStorage(w.toImage()));
    expectKind(() => r.verify(), PcfDcpErrorKind.DuplicateUid);
  });

  it("openArena rejects a non-DCP partition", () => {
    const c = Container.createWith(new MemoryStorage(), 4, HashAlgo.Sha256);
    c.addPartition(0x10, fill(7), "plain", enc("hi"), 0, HashAlgo.Sha256);
    const r = DcpReader.open(c.intoStorage());
    const entry = r.entries()[0]!;
    expectKind(() => r.openArena(entry), PcfDcpErrorKind.NotADcpContainer);
  });
});
