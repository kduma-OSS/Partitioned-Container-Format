/**
 * # `pcf-sig` — PCF Cryptographic Signatures (TypeScript implementation)
 *
 * Adds digital signatures to the {@link "@kduma-oss/pcf"} container without
 * changing its byte format. Two new PCF partition types are defined:
 *
 * * **`PCFSIG_KEY`** (type `0xAAAB0001`) — one Key Record carrying a signer's
 *   raw public key or X.509 certificate (chain), identified by a 32-byte
 *   SHA-256 fingerprint of the key material.
 * * **`PCFSIG_SIG`** (type `0xAAAB0002`) — one Manifest enumerating the
 *   partitions this signature covers (by uid + protected fields), followed by
 *   the raw bytes of a signature over the manifest.
 *
 * Signatures cover `uid`, `partitionType`, `label`, `usedBytes`,
 * `dataHashAlgo`, and `dataHash` of each named partition. They do NOT cover
 * `startOffset` or `maxLength`, so PCF compaction and other relocations leave
 * signatures valid as long as partition bytes do not change.
 *
 * ## Example
 *
 * ```ts
 * import { Container, HashAlgo } from "@kduma-oss/pcf";
 * import { signPartitions, verifyAllWithRecheck, SigningMaterial } from "@kduma-oss/pcf-sig";
 *
 * const c = Container.create();
 * const alpha = new Uint8Array(16).fill(0x11);
 * c.addPartition(0x10, alpha, "alpha", new TextEncoder().encode("hello"), 0, HashAlgo.Sha256);
 *
 * const signer = SigningMaterial.ed25519FromSeed(new Uint8Array(32).fill(0x42));
 * const sigUid = new Uint8Array(16).fill(0xA1);
 * const keyUid = new Uint8Array(16).fill(0xA0);
 * signPartitions(c, signer, {
 *   targetUids: [alpha],
 *   sigPartitionUid: sigUid,
 *   keyPartitionUid: keyUid,
 *   signedAtUnixSeconds: 0n,
 *   sigLabel: "pcfsig",
 *   keyLabel: "pcfkey",
 * });
 *
 * for (const report of verifyAllWithRecheck(c)) {
 *   console.log(report.verdict, report.entries);
 * }
 * ```
 */

export * from "./consts.js";
export {
  KeyFormat,
  SigAlgo,
  keyFormatFromId,
  keyFormatId,
  keyFormatIsImplemented,
  requiredManifestHash,
  sigAlgoFromId,
  sigAlgoId,
  sigAlgoIsImplemented,
} from "./algo.js";
export { PcfSigError, PcfSigErrorKind } from "./errors.js";
export {
  type KeyMetadata,
  type KeyRecord,
  computeFingerprint,
  keyRecordFromBytes,
  keyRecordToBytes,
  makeKeyRecord,
} from "./key.js";
export {
  type Manifest,
  type SignedEntry,
  isCryptoHash,
  makeManifest,
  manifestByteLen,
  manifestFromBytes,
  manifestToBytes,
  signedEntryFromBytes,
  signedEntryToBytes,
} from "./manifest.js";
export {
  type SignaturePartition,
  makeSignaturePartition,
  signaturePartitionFromBytes,
  signaturePartitionToBytes,
} from "./signature-partition.js";
export {
  type SignPartitionsOptions,
  SigningMaterial,
  ensureKeyPartition,
  signPartitions,
  signedEntryFromPartition,
} from "./sign.js";
export {
  DataRecheck,
  EntryVerdict,
  ManifestVerdict,
  UnverifiableReason,
  type EntryReport,
  type SignatureReport,
  verifyAll,
  verifyAllWithRecheck,
} from "./verify.js";
