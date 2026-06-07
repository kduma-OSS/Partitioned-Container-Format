/**
 * High-level signing API (spec Section 10).
 *
 * The Writer collects a set of partition uids, asserts that each one has a
 * cryptographic `dataHashAlgo` (Section 9), builds a {@link Manifest},
 * produces the algorithm's signature over the serialised Manifest bytes, and
 * wraps the result in a {@link SignaturePartition}.
 */

import * as ed25519 from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";

import {
  Container,
  HashAlgo,
  type PartitionEntry,
} from "@kduma-oss/pcf";

import {
  KeyFormat,
  SigAlgo,
  requiredManifestHash,
} from "./algo.js";
import { TYPE_PCFSIG_KEY, TYPE_PCFSIG_SIG } from "./consts.js";
import { PcfSigError } from "./errors.js";
import {
  computeFingerprint,
  keyRecordFromBytes,
  keyRecordToBytes,
  makeKeyRecord,
} from "./key.js";
import {
  isCryptoHash,
  makeManifest,
  manifestToBytes,
  type Manifest,
  type SignedEntry,
} from "./manifest.js";
import {
  signaturePartitionToBytes,
  type SignaturePartition,
} from "./signature-partition.js";

// Ensure noble's sync API has access to SHA-512 from @noble/hashes.
ed25519.etc.sha512Sync = (...messages: Uint8Array[]) =>
  sha512(ed25519.etc.concatBytes(...messages));

/**
 * A signing key wired to one algorithm.
 *
 * v1.0 covers Ed25519, the MUST-support baseline. Additional algorithms can
 * be plugged in by adding variants when their implementations land.
 */
export class SigningMaterial {
  private constructor(
    readonly sigAlgo: SigAlgo,
    readonly keyFormat: KeyFormat,
    private readonly secret: Uint8Array,
    readonly publicKeyBytes: Uint8Array,
  ) {}

  /** Construct an Ed25519 signer from a 32-byte secret seed. */
  static ed25519FromSeed(seed: Uint8Array): SigningMaterial {
    if (seed.length !== 32) {
      throw new Error("Ed25519 seed must be exactly 32 bytes");
    }
    const pub = ed25519.getPublicKey(seed);
    return new SigningMaterial(
      SigAlgo.Ed25519,
      KeyFormat.Ed25519Raw,
      new Uint8Array(seed),
      pub,
    );
  }

  /** The signer's SHA-256 fingerprint over `publicKeyBytes`. */
  fingerprint(): Uint8Array {
    return computeFingerprint(this.publicKeyBytes);
  }

  /** Sign `message` and return the raw signature bytes. */
  sign(message: Uint8Array): Uint8Array {
    switch (this.sigAlgo) {
      case SigAlgo.Ed25519:
        return ed25519.sign(message, this.secret);
      default:
        throw new Error(`sig_algo_id ${this.sigAlgo} is not implemented`);
    }
  }

  /** Build the bytes of a Key Record representing this signer. */
  toKeyRecordBytes(): Uint8Array {
    return keyRecordToBytes(
      makeKeyRecord(this.keyFormat, this.publicKeyBytes),
    );
  }
}

/**
 * Look up an existing PCFSIG_KEY partition by fingerprint, or, if none
 * exists, add a fresh one carrying `signer`'s public material. Returns the
 * PCF uid of the chosen partition.
 *
 * `keyUidSeed` is consulted only when a new partition is added.
 */
export function ensureKeyPartition(
  container: Container,
  signer: SigningMaterial,
  keyUidSeed: Uint8Array,
  label: string,
): Uint8Array {
  const fp = signer.fingerprint();
  for (const e of container.entries()) {
    if (e.partitionType === TYPE_PCFSIG_KEY) {
      try {
        const rec = keyRecordFromBytes(container.readPartitionData(e));
        if (bytesEqual(rec.fingerprint, fp)) {
          return e.uid;
        }
      } catch {
        // ignore malformed key records; we'll add a fresh one
      }
    }
  }
  const data = signer.toKeyRecordBytes();
  container.addPartition(
    TYPE_PCFSIG_KEY,
    keyUidSeed,
    label,
    data,
    0,
    HashAlgo.Sha256,
  );
  return keyUidSeed;
}

/** Build a {@link SignedEntry} mirroring a PCF {@link PartitionEntry}. */
export function signedEntryFromPartition(e: PartitionEntry): SignedEntry {
  if (!isCryptoHash(e.dataHashAlgo)) {
    throw PcfSigError.nonCryptoTargetHash();
  }
  return {
    uid: e.uid.slice(),
    partitionType: e.partitionType,
    label: e.label.slice(),
    usedBytes: e.usedBytes,
    dataHashAlgo: e.dataHashAlgo,
    dataHash: e.dataHash.slice(),
  };
}

/** Options for {@link signPartitions}. */
export interface SignPartitionsOptions {
  targetUids: Uint8Array[];
  sigPartitionUid: Uint8Array;
  keyPartitionUid: Uint8Array;
  signedAtUnixSeconds: bigint;
  sigLabel: string;
  keyLabel: string;
}

/**
 * Sign a chosen set of partitions and write the resulting PCFSIG_SIG
 * partition into `container`.
 */
export function signPartitions(
  container: Container,
  signer: SigningMaterial,
  options: SignPartitionsOptions,
): Uint8Array {
  if (options.targetUids.length === 0) {
    throw PcfSigError.emptyManifest();
  }
  for (const u of options.targetUids) {
    if (bytesEqual(u, options.sigPartitionUid)) {
      throw PcfSigError.selfSignedEntry();
    }
  }
  const seen = new Set<string>();
  for (const u of options.targetUids) {
    const k = hex(u);
    if (seen.has(k)) {
      throw PcfSigError.duplicateSignedUid();
    }
    seen.add(k);
  }

  ensureKeyPartition(container, signer, options.keyPartitionUid, options.keyLabel);

  const entries = container.entries();
  const signedEntries: SignedEntry[] = [];
  for (const uid of options.targetUids) {
    const p = entries.find((e) => bytesEqual(e.uid, uid));
    if (!p) {
      throw PcfSigError.targetPartitionMissing();
    }
    signedEntries.push(signedEntryFromPartition(p));
  }

  const manifestHash = requiredManifestHash(signer.sigAlgo);
  if (manifestHash === null) {
    throw new Error("signer algorithm has no fixed manifest hash binding");
  }
  const manifest: Manifest = makeManifest(
    signer.sigAlgo,
    manifestHash,
    signer.fingerprint(),
    options.signedAtUnixSeconds,
    signedEntries,
  );
  const manifestBytes = manifestToBytes(manifest);
  const signature = signer.sign(manifestBytes);
  const partition: SignaturePartition = {
    manifest,
    manifestBytes,
    signature,
    trailer: new Uint8Array(0),
  };
  const data = signaturePartitionToBytes(partition);
  container.addPartition(
    TYPE_PCFSIG_SIG,
    options.sigPartitionUid,
    options.sigLabel,
    data,
    0,
    HashAlgo.Sha256,
  );
  return options.sigPartitionUid;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function hex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, "0");
  return s;
}
