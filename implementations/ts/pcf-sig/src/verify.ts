/**
 * High-level verification API (spec Section 11).
 *
 * The Verifier scans a PCF container, indexes every PCFSIG_KEY partition by
 * fingerprint, and produces one {@link SignatureReport} per PCFSIG_SIG
 * partition.
 */

import * as ed25519 from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";

import {
  Container,
  computeHashField,
  type PartitionEntry,
} from "@kduma-oss/pcf";

import {
  KeyFormat,
  SigAlgo,
  keyFormatIsImplemented,
  sigAlgoIsImplemented,
} from "./algo.js";
import {
  ED25519_PUBLIC_KEY_LEN,
  ED25519_SIGNATURE_LEN,
  TYPE_PCFSIG_KEY,
  TYPE_PCFSIG_SIG,
} from "./consts.js";
import { keyRecordFromBytes, type KeyRecord } from "./key.js";
import { isCryptoHash } from "./manifest.js";
import { signaturePartitionFromBytes } from "./signature-partition.js";

ed25519.etc.sha512Sync = (...messages: Uint8Array[]) =>
  sha512(ed25519.etc.concatBytes(...messages));

/** Verdict on one SignedEntry inside a Manifest (spec Section 11, V7). */
export enum EntryVerdict {
  /** Covered partition exists, all protected fields match, hash is cryptographic. */
  Valid = "Valid",
  /** No partition in the container has the SignedEntry's uid. */
  MissingPartition = "MissingPartition",
  /** A protected field of the live partition does not match the manifest. */
  ProtectedFieldMismatch = "ProtectedFieldMismatch",
  /** Recomputed digest of live partition data does not match the SignedEntry's data_hash. */
  DataHashRecomputationMismatch = "DataHashRecomputationMismatch",
  /** The covered partition's `dataHashAlgo` is not cryptographic. */
  WeakHash = "WeakHash",
}

/** Per-entry report. */
export interface EntryReport {
  uid: Uint8Array;
  verdict: EntryVerdict;
}

/** Verdict on a whole PCFSIG_SIG partition (spec Section 11, V8). */
export enum ManifestVerdict {
  Valid = "Valid",
  Invalid = "Invalid",
  Unverifiable = "Unverifiable",
}

/** Why a manifest could not be verified. */
export enum UnverifiableReason {
  NoMatchingKey = "NoMatchingKey",
  UnsupportedSigAlgo = "UnsupportedSigAlgo",
  UnsupportedKeyFormat = "UnsupportedKeyFormat",
  MalformedKey = "MalformedKey",
  SignatureLengthMismatch = "SignatureLengthMismatch",
}

/** Report for one PCFSIG_SIG partition. */
export interface SignatureReport {
  /** PCF uid of the PCFSIG_SIG partition itself. */
  sigPartitionUid: Uint8Array;
  /** `signerKeyFingerprint` copied from the manifest. */
  signerKeyFingerprint: Uint8Array;
  /** `signedAtUnixSeconds` copied from the manifest. */
  signedAtUnixSeconds: bigint;
  /** Verdict on the manifest as a whole. */
  verdict: ManifestVerdict;
  /** Detailed reason when `verdict === Unverifiable`. */
  unverifiableReason?: UnverifiableReason;
  /** Optional id detail (e.g. unsupported algorithm id). */
  unverifiableId?: number;
  /** Per-entry verdicts. */
  entries: EntryReport[];
}

/** Whether to independently re-hash each covered partition's bytes during verification. */
export enum DataRecheck {
  Skip = "Skip",
  Recompute = "Recompute",
}

/**
 * Verify every PCFSIG_SIG partition in `container` and return one report each.
 * Returns an empty array if the container has no signatures.
 */
export function verifyAll(
  container: Container,
  recheck: DataRecheck = DataRecheck.Skip,
): SignatureReport[] {
  const entries = container.entries();

  // Index PCFSIG_KEY records.
  const keys: { record: KeyRecord; uid: Uint8Array }[] = [];
  for (const e of entries) {
    if (e.partitionType === TYPE_PCFSIG_KEY) {
      try {
        const rec = keyRecordFromBytes(container.readPartitionData(e));
        keys.push({ record: rec, uid: e.uid });
      } catch {
        // skip malformed keys
      }
    }
  }

  const reports: SignatureReport[] = [];
  for (const e of entries) {
    if (e.partitionType !== TYPE_PCFSIG_SIG) continue;
    const data = container.readPartitionData(e);
    reports.push(verifyOne(entries, keys, e, data));
  }

  if (recheck === DataRecheck.Recompute) {
    for (const r of reports) {
      for (const er of r.entries) {
        if (er.verdict !== EntryVerdict.Valid) continue;
        const p = entries.find((x) => bytesEqual(x.uid, er.uid));
        if (p) {
          const bytes = container.readPartitionData(p);
          const computed = computeHashField(p.dataHashAlgo, bytes);
          if (!bytesEqual(computed, p.dataHash)) {
            er.verdict = EntryVerdict.DataHashRecomputationMismatch;
          }
        }
      }
    }
  }

  return reports;
}

/** Same as {@link verifyAll} but with {@link DataRecheck.Recompute}. */
export function verifyAllWithRecheck(container: Container): SignatureReport[] {
  return verifyAll(container, DataRecheck.Recompute);
}

function verifyOne(
  entries: PartitionEntry[],
  keys: { record: KeyRecord; uid: Uint8Array }[],
  sigEntry: PartitionEntry,
  data: Uint8Array,
): SignatureReport {
  let parsed;
  try {
    parsed = signaturePartitionFromBytes(data);
  } catch {
    return {
      sigPartitionUid: sigEntry.uid,
      signerKeyFingerprint: new Uint8Array(32),
      signedAtUnixSeconds: 0n,
      verdict: ManifestVerdict.Unverifiable,
      unverifiableReason: UnverifiableReason.MalformedKey,
      entries: [],
    };
  }

  const report: SignatureReport = {
    sigPartitionUid: sigEntry.uid,
    signerKeyFingerprint: parsed.manifest.signerKeyFingerprint,
    signedAtUnixSeconds: parsed.manifest.signedAtUnixSeconds,
    verdict: ManifestVerdict.Valid,
    entries: [],
  };

  // Self-reference check (spec Section 7.2).
  if (
    parsed.manifest.signedEntries.some((e) => bytesEqual(e.uid, sigEntry.uid))
  ) {
    report.verdict = ManifestVerdict.Invalid;
    return report;
  }

  if (!sigAlgoIsImplemented(parsed.manifest.sigAlgo)) {
    report.verdict = ManifestVerdict.Unverifiable;
    report.unverifiableReason = UnverifiableReason.UnsupportedSigAlgo;
    report.unverifiableId = parsed.manifest.sigAlgo;
    return report;
  }

  const key = keys.find((k) =>
    bytesEqual(k.record.fingerprint, parsed.manifest.signerKeyFingerprint),
  );
  if (!key) {
    report.verdict = ManifestVerdict.Unverifiable;
    report.unverifiableReason = UnverifiableReason.NoMatchingKey;
    return report;
  }

  if (!keyFormatIsImplemented(key.record.keyFormat)) {
    report.verdict = ManifestVerdict.Unverifiable;
    report.unverifiableReason = UnverifiableReason.UnsupportedKeyFormat;
    report.unverifiableId = key.record.keyFormat;
    return report;
  }

  // Algorithm-specific verification.
  if (
    parsed.manifest.sigAlgo === SigAlgo.Ed25519 &&
    key.record.keyFormat === KeyFormat.Ed25519Raw
  ) {
    if (parsed.signature.length !== ED25519_SIGNATURE_LEN) {
      report.verdict = ManifestVerdict.Unverifiable;
      report.unverifiableReason = UnverifiableReason.SignatureLengthMismatch;
      return report;
    }
    if (key.record.keyData.length !== ED25519_PUBLIC_KEY_LEN) {
      report.verdict = ManifestVerdict.Unverifiable;
      report.unverifiableReason = UnverifiableReason.MalformedKey;
      return report;
    }
    try {
      const ok = ed25519.verify(
        parsed.signature,
        parsed.manifestBytes,
        key.record.keyData,
      );
      if (!ok) {
        report.verdict = ManifestVerdict.Invalid;
        return report;
      }
    } catch {
      report.verdict = ManifestVerdict.Invalid;
      return report;
    }
  } else {
    report.verdict = ManifestVerdict.Unverifiable;
    report.unverifiableReason = UnverifiableReason.UnsupportedSigAlgo;
    report.unverifiableId = parsed.manifest.sigAlgo;
    return report;
  }

  // Per-entry coverage check (spec Section 11, V7).
  for (const se of parsed.manifest.signedEntries) {
    const p = entries.find((x) => bytesEqual(x.uid, se.uid));
    let verdict: EntryVerdict;
    if (!p) {
      verdict = EntryVerdict.MissingPartition;
    } else if (!isCryptoHash(se.dataHashAlgo)) {
      verdict = EntryVerdict.WeakHash;
    } else if (
      p.partitionType !== se.partitionType ||
      !bytesEqual(p.label, se.label) ||
      p.usedBytes !== se.usedBytes ||
      p.dataHashAlgo !== se.dataHashAlgo ||
      !bytesEqual(p.dataHash, se.dataHash)
    ) {
      verdict = EntryVerdict.ProtectedFieldMismatch;
    } else {
      verdict = EntryVerdict.Valid;
    }
    report.entries.push({ uid: se.uid, verdict });
  }

  return report;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
