/**
 * Tamper-detection tests (spec Section 7.4, Section 11 V7).
 *
 * Any modification of a PROTECTED field of a covered partition must produce a
 * per-entry `ProtectedFieldMismatch` or `DataHashRecomputationMismatch`
 * verdict; modifying an UNPROTECTED field (start_offset, max_length) must NOT.
 */

import { describe, expect, it } from "vitest";

import { Container, HashAlgo, MemoryStorage } from "@kduma-oss/pcf";

import {
  EntryVerdict,
  ManifestVerdict,
  SigningMaterial,
  TYPE_PCFSIG_SIG,
  signPartitions,
  verifyAllWithRecheck,
} from "../src/index.js";

function uid(n: number): Uint8Array {
  const u = new Uint8Array(16);
  u[0] = n;
  u[15] = 0xaa;
  return u;
}

function build(): { c: Container; alpha: Uint8Array } {
  const c = Container.create();
  const alpha = uid(1);
  c.addPartition(
    0x10,
    alpha,
    "alpha",
    new TextEncoder().encode("original payload"),
    64,
    HashAlgo.Sha256,
  );
  const signer = SigningMaterial.ed25519FromSeed(new Uint8Array(32).fill(0x33));
  signPartitions(c, signer, {
    targetUids: [alpha],
    sigPartitionUid: uid(0xa1),
    keyPartitionUid: uid(0xa0),
    signedAtUnixSeconds: 0n,
    sigLabel: "sig",
    keyLabel: "key",
  });
  return { c, alpha };
}

describe("tamper", () => {
  it("baseline verifies", () => {
    const { c } = build();
    const reports = verifyAllWithRecheck(c);
    expect(reports[0]!.verdict).toBe(ManifestVerdict.Valid);
    expect(reports[0]!.entries[0]!.verdict).toBe(EntryVerdict.Valid);
  });

  it("data update invalidates the entry", () => {
    const { c, alpha } = build();
    c.updatePartitionData(alpha, new TextEncoder().encode("forged payload"));
    const reports = verifyAllWithRecheck(c);
    expect(reports[0]!.verdict).toBe(ManifestVerdict.Valid);
    expect(reports[0]!.entries[0]!.verdict).toBe(
      EntryVerdict.ProtectedFieldMismatch,
    );
  });

  it("removed covered partition is reported missing", () => {
    const { c, alpha } = build();
    c.removePartition(alpha);
    const reports = verifyAllWithRecheck(c);
    expect(reports[0]!.verdict).toBe(ManifestVerdict.Valid);
    expect(reports[0]!.entries[0]!.verdict).toBe(EntryVerdict.MissingPartition);
  });

  it("flipping a signature byte invalidates the manifest", () => {
    const { c } = build();
    const sigEntry = c
      .entries()
      .find((e) => e.partitionType === TYPE_PCFSIG_SIG)!;
    const bytes = c.compactedImage();

    // The compaction may renumber offsets; reopen, locate sig partition fresh.
    const c2 = Container.open(new MemoryStorage(bytes));
    const sig2 = c2
      .entries()
      .find((e) => e.partitionType === TYPE_PCFSIG_SIG)!;
    expect(sig2.uid).toEqual(sigEntry.uid);
    const last = Number(sig2.startOffset + sig2.usedBytes - 8n);
    bytes[last] ^= 0x01;

    const c3 = Container.open(new MemoryStorage(bytes));
    const reports = verifyAllWithRecheck(c3);
    expect(reports[0]!.verdict).toBe(ManifestVerdict.Invalid);
  });
});
