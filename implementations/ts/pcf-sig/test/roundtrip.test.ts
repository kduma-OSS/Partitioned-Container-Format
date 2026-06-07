/**
 * End-to-end roundtrip tests: build a container with a signed partition,
 * reopen it, verify.
 */

import { describe, expect, it } from "vitest";

import { Container, HashAlgo, MemoryStorage } from "@kduma-oss/pcf";

import {
  DataRecheck,
  EntryVerdict,
  ManifestVerdict,
  PcfSigError,
  PcfSigErrorKind,
  SigningMaterial,
  TYPE_PCFSIG_KEY,
  signPartitions,
  verifyAll,
  verifyAllWithRecheck,
} from "../src/index.js";

function uid(n: number): Uint8Array {
  const u = new Uint8Array(16);
  u[0] = n;
  u[15] = 0xaa;
  return u;
}

describe("roundtrip", () => {
  it("signs and verifies a single partition", () => {
    const c = Container.create();
    const alpha = uid(1);
    c.addPartition(
      0x10,
      alpha,
      "alpha",
      new TextEncoder().encode("hello"),
      0,
      HashAlgo.Sha256,
    );

    const signer = SigningMaterial.ed25519FromSeed(new Uint8Array(32).fill(0x42));
    signPartitions(c, signer, {
      targetUids: [alpha],
      sigPartitionUid: uid(0xa1),
      keyPartitionUid: uid(0xa0),
      signedAtUnixSeconds: 1_700_000_000n,
      sigLabel: "pcfsig",
      keyLabel: "pcfkey",
    });

    c.verify();
    const reports = verifyAll(c, DataRecheck.Skip);
    expect(reports).toHaveLength(1);
    expect(reports[0]!.verdict).toBe(ManifestVerdict.Valid);
    expect(reports[0]!.entries).toHaveLength(1);
    expect(reports[0]!.entries[0]!.verdict).toBe(EntryVerdict.Valid);
    expect(reports[0]!.signedAtUnixSeconds).toBe(1_700_000_000n);
    expect(reports[0]!.signerKeyFingerprint).toEqual(signer.fingerprint());
  });

  it("reopens after serialise and verifies", () => {
    const c = Container.create();
    c.addPartition(0x10, uid(1), "alpha", new TextEncoder().encode("hello"), 0, HashAlgo.Sha256);
    c.addPartition(0x11, uid(2), "beta", new TextEncoder().encode("world"), 0, HashAlgo.Blake3);
    const signer = SigningMaterial.ed25519FromSeed(new Uint8Array(32).fill(0x01));
    signPartitions(c, signer, {
      targetUids: [uid(1), uid(2)],
      sigPartitionUid: uid(0xa1),
      keyPartitionUid: uid(0xa0),
      signedAtUnixSeconds: 0n,
      sigLabel: "sig",
      keyLabel: "key",
    });
    const bytes = c.compactedImage();

    const c2 = Container.open(new MemoryStorage(bytes));
    c2.verify();
    const reports = verifyAllWithRecheck(c2);
    expect(reports).toHaveLength(1);
    expect(reports[0]!.verdict).toBe(ManifestVerdict.Valid);
    expect(reports[0]!.entries).toHaveLength(2);
    for (const er of reports[0]!.entries) {
      expect(er.verdict).toBe(EntryVerdict.Valid);
    }
  });

  it("deduplicates key partitions for the same signer", () => {
    const c = Container.create();
    c.addPartition(0x10, uid(1), "a", new Uint8Array([0x61]), 0, HashAlgo.Sha256);
    c.addPartition(0x10, uid(2), "b", new Uint8Array([0x62]), 0, HashAlgo.Sha256);

    const signer = SigningMaterial.ed25519FromSeed(new Uint8Array(32).fill(0x03));
    signPartitions(c, signer, {
      targetUids: [uid(1)],
      sigPartitionUid: uid(0xa1),
      keyPartitionUid: uid(0xa0),
      signedAtUnixSeconds: 0n,
      sigLabel: "sig1",
      keyLabel: "k",
    });
    signPartitions(c, signer, {
      targetUids: [uid(2)],
      sigPartitionUid: uid(0xa2),
      keyPartitionUid: uid(0xa3), // would be a second key partition, must be ignored
      signedAtUnixSeconds: 0n,
      sigLabel: "sig2",
      keyLabel: "k2",
    });

    const keyPartitions = c.entries().filter((e) => e.partitionType === TYPE_PCFSIG_KEY);
    expect(keyPartitions).toHaveLength(1);

    const reports = verifyAll(c, DataRecheck.Skip);
    expect(reports).toHaveLength(2);
    for (const r of reports) {
      expect(r.verdict).toBe(ManifestVerdict.Valid);
    }
  });

  it("refuses to sign a weakly-hashed partition", () => {
    const c = Container.create();
    const alpha = uid(1);
    c.addPartition(0x10, alpha, "alpha", new Uint8Array([0x78]), 0, HashAlgo.Crc32c);
    const signer = SigningMaterial.ed25519FromSeed(new Uint8Array(32).fill(0x04));
    expect(() =>
      signPartitions(c, signer, {
        targetUids: [alpha],
        sigPartitionUid: uid(0xa1),
        keyPartitionUid: uid(0xa0),
        signedAtUnixSeconds: 0n,
        sigLabel: "sig",
        keyLabel: "key",
      }),
    ).toThrowError(PcfSigError);
    try {
      signPartitions(c, signer, {
        targetUids: [alpha],
        sigPartitionUid: uid(0xa1),
        keyPartitionUid: uid(0xa0),
        signedAtUnixSeconds: 0n,
        sigLabel: "sig",
        keyLabel: "key",
      });
    } catch (e) {
      expect((e as PcfSigError).kind).toBe(PcfSigErrorKind.NonCryptoTargetHash);
    }
  });

  it("refuses self-reference", () => {
    const c = Container.create();
    const alpha = uid(1);
    c.addPartition(0x10, alpha, "alpha", new Uint8Array([0x78]), 0, HashAlgo.Sha256);
    const signer = SigningMaterial.ed25519FromSeed(new Uint8Array(32).fill(0x05));
    const sigUid = uid(0xa1);
    expect(() =>
      signPartitions(c, signer, {
        targetUids: [alpha, sigUid],
        sigPartitionUid: sigUid,
        keyPartitionUid: uid(0xa0),
        signedAtUnixSeconds: 0n,
        sigLabel: "sig",
        keyLabel: "key",
      }),
    ).toThrowError(/self/i);
  });
});
