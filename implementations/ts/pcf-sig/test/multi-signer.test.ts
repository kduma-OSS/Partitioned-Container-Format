/**
 * Multi-signer tests (spec Section 4.4, Section 12).
 */

import { describe, expect, it } from "vitest";

import { Container, HashAlgo } from "@kduma-oss/pcf";

import {
  DataRecheck,
  EntryVerdict,
  ManifestVerdict,
  SigningMaterial,
  TYPE_PCFSIG_KEY,
  signPartitions,
  verifyAll,
} from "../src/index.js";

function uid(n: number): Uint8Array {
  const u = new Uint8Array(16);
  u[0] = n;
  u[15] = 0xaa;
  return u;
}

describe("multi-signer", () => {
  it("two signers, each signing their own partition", () => {
    const c = Container.create();
    c.addPartition(0x10, uid(1), "alpha", new TextEncoder().encode("alpha"), 0, HashAlgo.Sha256);
    c.addPartition(0x11, uid(2), "beta", new TextEncoder().encode("beta"), 0, HashAlgo.Sha256);

    const a = SigningMaterial.ed25519FromSeed(new Uint8Array(32).fill(0x01));
    const b = SigningMaterial.ed25519FromSeed(new Uint8Array(32).fill(0x02));

    signPartitions(c, a, {
      targetUids: [uid(1)],
      sigPartitionUid: uid(0xa1),
      keyPartitionUid: uid(0xa0),
      signedAtUnixSeconds: 0n,
      sigLabel: "sigA",
      keyLabel: "keyA",
    });
    signPartitions(c, b, {
      targetUids: [uid(2)],
      sigPartitionUid: uid(0xb1),
      keyPartitionUid: uid(0xb0),
      signedAtUnixSeconds: 0n,
      sigLabel: "sigB",
      keyLabel: "keyB",
    });

    const reports = verifyAll(c, DataRecheck.Skip);
    expect(reports).toHaveLength(2);
    for (const r of reports) {
      expect(r.verdict).toBe(ManifestVerdict.Valid);
      expect(r.entries).toHaveLength(1);
      expect(r.entries[0]!.verdict).toBe(EntryVerdict.Valid);
    }
  });

  it("same signer deduplicates key partition across signatures", () => {
    const c = Container.create();
    c.addPartition(0x10, uid(1), "alpha", new TextEncoder().encode("a"), 0, HashAlgo.Sha256);
    c.addPartition(0x11, uid(2), "beta", new TextEncoder().encode("b"), 0, HashAlgo.Sha256);

    const signer = SigningMaterial.ed25519FromSeed(new Uint8Array(32).fill(0xaa));
    signPartitions(c, signer, {
      targetUids: [uid(1)],
      sigPartitionUid: uid(0xa1),
      keyPartitionUid: uid(0xa0),
      signedAtUnixSeconds: 0n,
      sigLabel: "sig1",
      keyLabel: "key",
    });
    signPartitions(c, signer, {
      targetUids: [uid(2)],
      sigPartitionUid: uid(0xa2),
      keyPartitionUid: uid(0xa3),
      signedAtUnixSeconds: 0n,
      sigLabel: "sig2",
      keyLabel: "key",
    });

    const keyPartitions = c
      .entries()
      .filter((e) => e.partitionType === TYPE_PCFSIG_KEY);
    expect(keyPartitions).toHaveLength(1);
    expect(keyPartitions[0]!.uid[0]).toBe(0xa0);

    const reports = verifyAll(c, DataRecheck.Skip);
    expect(reports).toHaveLength(2);
    for (const r of reports) {
      expect(r.verdict).toBe(ManifestVerdict.Valid);
    }
  });
});
