/**
 * End-to-end round-trips: build, edit, dedup/defrag, promote/demote, trailer.
 */

import { describe, expect, it } from "vitest";
import { HashAlgo, MemoryStorage } from "@kduma-oss/pcf";

import { Arena, Chunker, DcpReader, DcpWriter } from "../src/index.js";
import { dec, enc, fill } from "./helpers.js";

function buildTwoInnerFile(): Uint8Array {
  const arena = new Arena();
  arena.addInner(0x10, fill(0xa1), "A", enc("Hello, World!"), HashAlgo.Sha256, Chunker.fixed(7));
  arena.addInner(0x10, fill(0xb2), "B", enc("World!"), HashAlgo.Sha256, Chunker.whole());
  const w = new DcpWriter();
  w.addContainer(fill(0xdc), "dcp", arena);
  return w.toImage();
}

describe("round-trips", () => {
  it("edits reconstruct correctly", () => {
    const a = new Arena();
    a.addInner(0x10, fill(1), "f", enc("Hello, World!"), HashAlgo.Sha256, Chunker.fixed(7));

    a.append(fill(1), enc("!!"));
    expect(dec(a.content(fill(1)))).toBe("Hello, World!!!");

    a.insert(fill(1), 5, enc("XYZ"));
    expect(dec(a.content(fill(1)))).toBe("HelloXYZ, World!!!");

    a.delete(fill(1), 5, 3);
    expect(dec(a.content(fill(1)))).toBe("Hello, World!!!");

    a.overwrite(fill(1), 0, 5, enc("HOWDY"));
    expect(dec(a.content(fill(1)))).toBe("HOWDY, World!!!");

    a.truncate(fill(1), 5);
    expect(dec(a.content(fill(1)))).toBe("HOWDY");
  });

  it("copy-on-write does not disturb shared bytes", () => {
    const a = new Arena();
    a.addInner(0x10, fill(0xa1), "A", enc("Hello, World!"), HashAlgo.Sha256, Chunker.fixed(7));
    a.addInner(0x10, fill(0xb2), "B", enc("World!"), HashAlgo.Sha256, Chunker.whole());
    a.overwrite(fill(0xa1), 7, 6, enc("PLANET"));
    expect(dec(a.content(fill(0xa1)))).toBe("Hello, PLANET");
    expect(dec(a.content(fill(0xb2)))).toBe("World!");
  });

  it("dedup then defrag preserve content", () => {
    const a = new Arena();
    a.addInner(0x10, fill(1), "A", enc("abcabc"), HashAlgo.Sha256, Chunker.whole());
    a.addInner(0x10, fill(2), "B", enc("abcabc"), HashAlgo.Sha256, Chunker.whole());
    const h1 = a.innerInfo(fill(1)).dataHash;

    const saved = a.dedup(Chunker.fixed(3));
    expect(saved).toBeGreaterThan(0);
    expect(dec(a.content(fill(1)))).toBe("abcabc");
    expect(dec(a.content(fill(2)))).toBe("abcabc");
    expect(a.innerInfo(fill(1)).dataHash).toEqual(h1);

    a.compact();
    expect(dec(a.content(fill(2)))).toBe("abcabc");
  });

  it("defrag clears SHARED when no longer aliased (rule F2)", () => {
    const a = new Arena();
    a.addInner(0x10, fill(0xa1), "A", enc("Hello, World!"), HashAlgo.Sha256, Chunker.fixed(7));
    a.addInner(0x10, fill(0xb2), "B", enc("World!"), HashAlgo.Sha256, Chunker.whole());
    a.removeInner(fill(0xb2));
    a.compact();
    const ia = a.innerInfo(fill(0xa1));
    expect(ia.extents.every((e) => !e.shared)).toBe(true);
    expect(dec(a.content(fill(0xa1)))).toBe("Hello, World!");
  });

  it("promote preserves uid and data_hash", () => {
    const w = DcpWriter.open(new MemoryStorage(buildTwoInnerFile()));
    const before = (() => {
      const r = DcpReader.open(new MemoryStorage(w.toImage()));
      return r.innerPartitions().find((l) => l.info.uid[0] === 0xb2)!.info.dataHash;
    })();

    w.promote(fill(0xdc), fill(0xb2));
    const r = DcpReader.open(new MemoryStorage(w.toImage()));
    r.verify();
    const resolved = r.resolveUid(fill(0xb2));
    expect(resolved.kind).toBe("top-level");
    if (resolved.kind === "top-level") {
      expect(resolved.entry.dataHash).toEqual(before);
      expect(Number(resolved.entry.usedBytes)).toBe(6);
    }
    expect(dec(r.readInner(fill(0xa1)))).toBe("Hello, World!");
  });

  it("demote then promote is identity for content", () => {
    const w = DcpWriter.open(new MemoryStorage(buildTwoInnerFile()));
    w.promote(fill(0xdc), fill(0xb2));
    w.demote(fill(0xb2), fill(0xdc));
    const r = DcpReader.open(new MemoryStorage(w.toImage()));
    r.verify();
    expect(dec(r.readInner(fill(0xb2)))).toBe("World!");
    expect(r.resolveUid(fill(0xb2)).kind).toBe("inner");
  });

  it("trailer mode reads back identically", () => {
    const arena = new Arena();
    arena.addInner(0x10, fill(0xa1), "A", enc("Hello, World!"), HashAlgo.Sha256, Chunker.fixed(7));
    arena.addInner(0x10, fill(0xb2), "B", enc("World!"), HashAlgo.Sha256, Chunker.whole());
    const w = new DcpWriter();
    w.addContainer(fill(0xdc), "dcp", arena);
    w.setTrailer(true);
    const r = DcpReader.open(new MemoryStorage(w.toImage()));
    r.verify();
    expect(dec(r.readInner(fill(0xa1)))).toBe("Hello, World!");
    expect(r.innerPartitions()).toHaveLength(2);
  });
});
