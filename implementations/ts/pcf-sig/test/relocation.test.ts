/**
 * Relocation-stability tests (spec Section 4.2).
 *
 * A signature MUST remain valid across operations that change a partition's
 * file layout but not its contents.
 */

import { describe, expect, it } from "vitest";

import { Container, HashAlgo, MemoryStorage } from "@kduma-oss/pcf";

import {
  EntryVerdict,
  ManifestVerdict,
  SigningMaterial,
  signPartitions,
  verifyAllWithRecheck,
} from "../src/index.js";

function uid(n: number): Uint8Array {
  const u = new Uint8Array(16);
  u[0] = n;
  u[15] = 0xaa;
  return u;
}

describe("relocation", () => {
  it("signature survives PCF compaction", () => {
    const c = Container.create();
    c.addPartition(0x10, uid(1), "alpha", new TextEncoder().encode("alpha payload"), 1024, HashAlgo.Sha256);
    c.addPartition(0x11, uid(2), "beta", new TextEncoder().encode("beta payload"), 1024, HashAlgo.Sha512);
    c.addPartition(0x12, uid(3), "gamma", new TextEncoder().encode("gamma payload"), 1024, HashAlgo.Blake3);
    const signer = SigningMaterial.ed25519FromSeed(new Uint8Array(32).fill(0x10));
    signPartitions(c, signer, {
      targetUids: [uid(1), uid(2), uid(3)],
      sigPartitionUid: uid(0xa1),
      keyPartitionUid: uid(0xa0),
      signedAtUnixSeconds: 0n,
      sigLabel: "sig",
      keyLabel: "key",
    });

    const compacted = c.compactedImage();
    const c2 = Container.open(new MemoryStorage(compacted));
    c2.verify();

    const alpha = c2.entries().find((e) => e.uid[0] === 1)!;
    expect(alpha.usedBytes).toBe(13n);
    expect(alpha.maxLength).toBe(13n); // trimmed by compaction

    const reports = verifyAllWithRecheck(c2);
    expect(reports).toHaveLength(1);
    expect(reports[0]!.verdict).toBe(ManifestVerdict.Valid);
    expect(reports[0]!.entries).toHaveLength(3);
    for (const e of reports[0]!.entries) {
      expect(e.verdict).toBe(EntryVerdict.Valid);
    }
  });

  it("signature survives table-block chain growth", () => {
    const c = Container.createWith(new MemoryStorage(), 2, HashAlgo.Sha256);
    c.addPartition(0x10, uid(1), "alpha", new TextEncoder().encode("alpha"), 0, HashAlgo.Sha256);
    const signer = SigningMaterial.ed25519FromSeed(new Uint8Array(32).fill(0x20));
    signPartitions(c, signer, {
      targetUids: [uid(1)],
      sigPartitionUid: uid(0xa1),
      keyPartitionUid: uid(0xa0),
      signedAtUnixSeconds: 0n,
      sigLabel: "sig",
      keyLabel: "key",
    });
    for (let i = 0; i < 6; i++) {
      c.addPartition(0x20, uid(0x40 + i), "extra", new Uint8Array([i, i, i, i]), 0, HashAlgo.Sha256);
    }
    c.verify();
    const reports = verifyAllWithRecheck(c);
    expect(reports[0]!.verdict).toBe(ManifestVerdict.Valid);
    expect(reports[0]!.entries[0]!.verdict).toBe(EntryVerdict.Valid);
  });

  it("signature survives in-place update of unsigned partition", () => {
    const c = Container.create();
    c.addPartition(0x10, uid(1), "signed", new TextEncoder().encode("locked"), 0, HashAlgo.Sha256);
    c.addPartition(0x11, uid(2), "free", new TextEncoder().encode("original"), 64, HashAlgo.Sha256);
    const signer = SigningMaterial.ed25519FromSeed(new Uint8Array(32).fill(0x30));
    signPartitions(c, signer, {
      targetUids: [uid(1)],
      sigPartitionUid: uid(0xa1),
      keyPartitionUid: uid(0xa0),
      signedAtUnixSeconds: 0n,
      sigLabel: "sig",
      keyLabel: "key",
    });
    c.updatePartitionData(uid(2), new TextEncoder().encode("replaced payload data"));
    c.verify();
    const reports = verifyAllWithRecheck(c);
    expect(reports[0]!.verdict).toBe(ManifestVerdict.Valid);
    expect(reports[0]!.entries[0]!.verdict).toBe(EntryVerdict.Valid);
  });
});
