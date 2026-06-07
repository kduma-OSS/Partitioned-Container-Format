/**
 * Error type shared across the library (mirrors the reference `Error` enum).
 */

/** Discriminant identifying which kind of {@link PcfSigError} occurred. */
export enum PcfSigErrorKind {
  /** Underlying PCF container error. */
  Pcf = "Pcf",
  /** A Key Record did not begin with `"PCFKEY\0\0"`. */
  BadKeyMagic = "BadKeyMagic",
  /** A Manifest did not begin with `"PCFSIG\0\0"`. */
  BadManifestMagic = "BadManifestMagic",
  /** A record's profile major version is not implemented by this library. */
  UnsupportedMajor = "UnsupportedMajor",
  /** A Key Record's `key_format_id` is unknown or reserved (0). */
  UnknownKeyFormat = "UnknownKeyFormat",
  /** A Key Record's `key_data_length` is zero. */
  EmptyKeyData = "EmptyKeyData",
  /** A Key Record's reserved bytes are non-zero in v1.0. */
  NonZeroKeyReserved = "NonZeroKeyReserved",
  /** `fingerprint` does not equal `SHA-256(key_data)`. */
  FingerprintMismatch = "FingerprintMismatch",
  /** A Manifest's `sig_algo_id` is reserved (0) or unknown. */
  UnknownSigAlgo = "UnknownSigAlgo",
  /** A Manifest's `manifest_hash_algo_id` is not cryptographic. */
  NonCryptoManifestHash = "NonCryptoManifestHash",
  /** `manifest_hash_algo_id` does not match the binding required by `sig_algo_id`. */
  HashAlgoBindingMismatch = "HashAlgoBindingMismatch",
  /** `flags` carries bits not defined in v1.0. */
  NonZeroFlags = "NonZeroFlags",
  /** `signed_count` is 0. */
  EmptyManifest = "EmptyManifest",
  /** `trailer_length` is non-zero (reserved in v1.0). */
  NonZeroTrailer = "NonZeroTrailer",
  /** A SignedEntry's reserved span (1 B or 92 B) is non-zero. */
  NonZeroEntryReserved = "NonZeroEntryReserved",
  /** A SignedEntry's `data_hash_algo_id` is not cryptographic (spec Section 9). */
  NonCryptoEntryHash = "NonCryptoEntryHash",
  /** A SignedEntry references the PCF NIL UID. */
  EntryNilUid = "EntryNilUid",
  /** A SignedEntry uses PCF reserved type 0x00000000. */
  EntryReservedType = "EntryReservedType",
  /** Two SignedEntry records share the same uid. */
  DuplicateSignedUid = "DuplicateSignedUid",
  /** A SignedEntry references the enclosing PCFSIG_SIG partition's own uid. */
  SelfSignedEntry = "SelfSignedEntry",
  /** A truncation, short read, or length-field mismatch in the partition payload. */
  MalformedSignaturePartition = "MalformedSignaturePartition",
  /** Length of `sig_bytes` does not match the algorithm's natural size. */
  SignatureLengthMismatch = "SignatureLengthMismatch",
  /** The Writer was asked to sign a partition whose `data_hash_algo_id` is not cryptographic. */
  NonCryptoTargetHash = "NonCryptoTargetHash",
  /** The Writer was asked to sign a partition that does not exist in the supplied container. */
  TargetPartitionMissing = "TargetPartitionMissing",
}

/** All ways a PCF-SIG operation can fail. */
export class PcfSigError extends Error {
  /** The kind of failure. */
  readonly kind: PcfSigErrorKind;
  /** Optional numeric detail (e.g., the unknown algorithm id). */
  readonly value?: number;

  constructor(kind: PcfSigErrorKind, message: string, value?: number) {
    super(message);
    this.name = "PcfSigError";
    this.kind = kind;
    if (value !== undefined) {
      this.value = value;
    }
  }

  static badKeyMagic(): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.BadKeyMagic,
      "bad PCFSIG_KEY magic",
    );
  }
  static badManifestMagic(): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.BadManifestMagic,
      "bad PCFSIG_SIG manifest magic",
    );
  }
  static unsupportedMajor(v: number): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.UnsupportedMajor,
      `unsupported PCF-SIG major version ${v}`,
      v,
    );
  }
  static unknownKeyFormat(id: number): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.UnknownKeyFormat,
      `unknown key_format_id ${id}`,
      id,
    );
  }
  static emptyKeyData(): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.EmptyKeyData,
      "key_data_length is zero",
    );
  }
  static nonZeroKeyReserved(): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.NonZeroKeyReserved,
      "key record reserved bytes are non-zero",
    );
  }
  static fingerprintMismatch(): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.FingerprintMismatch,
      "stored key fingerprint does not match SHA-256(key_data)",
    );
  }
  static unknownSigAlgo(id: number): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.UnknownSigAlgo,
      `unknown or reserved sig_algo_id ${id}`,
      id,
    );
  }
  static nonCryptoManifestHash(id: number): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.NonCryptoManifestHash,
      `manifest_hash_algo_id ${id} is not cryptographic`,
      id,
    );
  }
  static hashAlgoBindingMismatch(): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.HashAlgoBindingMismatch,
      "manifest_hash_algo_id does not match the binding required by sig_algo_id",
    );
  }
  static nonZeroFlags(): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.NonZeroFlags,
      "manifest flags are non-zero in v1.0",
    );
  }
  static emptyManifest(): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.EmptyManifest,
      "manifest signed_count is 0",
    );
  }
  static nonZeroTrailer(): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.NonZeroTrailer,
      "trailer_length is non-zero in v1.0",
    );
  }
  static nonZeroEntryReserved(): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.NonZeroEntryReserved,
      "SignedEntry reserved span contains non-zero bytes",
    );
  }
  static nonCryptoEntryHash(id: number): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.NonCryptoEntryHash,
      `SignedEntry data_hash_algo_id ${id} is not cryptographic`,
      id,
    );
  }
  static entryNilUid(): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.EntryNilUid,
      "SignedEntry uses the NIL UID",
    );
  }
  static entryReservedType(): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.EntryReservedType,
      "SignedEntry uses PCF reserved type 0x00000000",
    );
  }
  static duplicateSignedUid(): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.DuplicateSignedUid,
      "duplicate uid in manifest",
    );
  }
  static selfSignedEntry(): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.SelfSignedEntry,
      "SignedEntry references the PCFSIG_SIG partition itself",
    );
  }
  static malformedSignaturePartition(): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.MalformedSignaturePartition,
      "PCFSIG_SIG partition layout is malformed",
    );
  }
  static signatureLengthMismatch(): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.SignatureLengthMismatch,
      "sig_bytes length does not match the algorithm",
    );
  }
  static nonCryptoTargetHash(): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.NonCryptoTargetHash,
      "cannot sign a partition whose data_hash_algo_id is not cryptographic",
    );
  }
  static targetPartitionMissing(): PcfSigError {
    return new PcfSigError(
      PcfSigErrorKind.TargetPartitionMissing,
      "partition to sign is not present in the container",
    );
  }
}
