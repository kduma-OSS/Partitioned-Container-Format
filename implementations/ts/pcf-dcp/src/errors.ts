/**
 * Error type shared across the library (mirrors the reference `Error` enum).
 */

/** Discriminant identifying which kind of {@link PcfDcpError} occurred. */
export enum PcfDcpErrorKind {
  /** The arena did not begin with the `"PDCP"` magic (spec Section 6). */
  BadDcpMagic = "BadDcpMagic",
  /** The arena's `profile_version_major` is not implemented by this library. */
  UnsupportedProfileMajor = "UnsupportedProfileMajor",
  /** A Fragment Entry carried an unsupported `kind` (HOLE/REF/unknown). */
  BadFragmentKind = "BadFragmentKind",
  /** An extent range escapes `[0, arena_used)`. */
  OffsetOutOfRange = "OffsetOutOfRange",
  /** Reconstructed length did not match `used_bytes`, or a hash did not verify. */
  LengthMismatch = "LengthMismatch",
  /** A stored hash (inner `table_hash` or inner `data_hash`) did not verify. */
  HashMismatch = "HashMismatch",
  /** No inner (or top-level) partition with the requested uid. */
  NotFound = "NotFound",
  /** A uid is used by more than one partition file-wide (spec Section 2.1). */
  DuplicateUid = "DuplicateUid",
  /** An inner partition is itself a DCP container (nesting forbidden in v1.0). */
  NestedContainer = "NestedContainer",
  /** A partition uid is the PCF NIL uid. */
  NilUid = "NilUid",
  /** A partition type is the PCF reserved type `0x00000000`. */
  ReservedType = "ReservedType",
  /** A top-level partition expected to be a DCP container is not one. */
  NotADcpContainer = "NotADcpContainer",
  /** A logical edit addressed a position beyond the partition's content. */
  PositionOutOfRange = "PositionOutOfRange",
}

/** All ways a PCF-DCP operation can fail. */
export class PcfDcpError extends Error {
  /** The kind of failure. */
  readonly kind: PcfDcpErrorKind;
  /** Optional numeric detail (e.g. the unsupported major or bad fragment kind). */
  readonly value?: number;

  constructor(kind: PcfDcpErrorKind, message: string, value?: number) {
    super(message);
    this.name = "PcfDcpError";
    this.kind = kind;
    if (value !== undefined) {
      this.value = value;
    }
    Object.setPrototypeOf(this, PcfDcpError.prototype);
  }

  static badDcpMagic(): PcfDcpError {
    return new PcfDcpError(
      PcfDcpErrorKind.BadDcpMagic,
      'arena does not begin with "PDCP" magic',
    );
  }
  static unsupportedProfileMajor(v: number): PcfDcpError {
    return new PcfDcpError(
      PcfDcpErrorKind.UnsupportedProfileMajor,
      `unsupported PCF-DCP profile major version ${v}`,
      v,
    );
  }
  static badFragmentKind(k: number): PcfDcpError {
    return new PcfDcpError(
      PcfDcpErrorKind.BadFragmentKind,
      `unsupported fragment kind ${k}`,
      k,
    );
  }
  static offsetOutOfRange(): PcfDcpError {
    return new PcfDcpError(
      PcfDcpErrorKind.OffsetOutOfRange,
      "extent range escapes the arena",
    );
  }
  static lengthMismatch(expected: number, got: number): PcfDcpError {
    return new PcfDcpError(
      PcfDcpErrorKind.LengthMismatch,
      `logical length mismatch: expected ${expected}, got ${got}`,
    );
  }
  static hashMismatch(): PcfDcpError {
    return new PcfDcpError(
      PcfDcpErrorKind.HashMismatch,
      "stored hash does not verify",
    );
  }
  static notFound(): PcfDcpError {
    return new PcfDcpError(PcfDcpErrorKind.NotFound, "no partition with that uid");
  }
  static duplicateUid(): PcfDcpError {
    return new PcfDcpError(
      PcfDcpErrorKind.DuplicateUid,
      "uid is not unique file-wide",
    );
  }
  static nestedContainer(): PcfDcpError {
    return new PcfDcpError(
      PcfDcpErrorKind.NestedContainer,
      "an inner partition may not be a DCP container",
    );
  }
  static nilUid(): PcfDcpError {
    return new PcfDcpError(PcfDcpErrorKind.NilUid, "uid is the NIL uid");
  }
  static reservedType(): PcfDcpError {
    return new PcfDcpError(
      PcfDcpErrorKind.ReservedType,
      "partition type is the reserved type 0x00000000",
    );
  }
  static notADcpContainer(): PcfDcpError {
    return new PcfDcpError(
      PcfDcpErrorKind.NotADcpContainer,
      "partition is not a DCP container",
    );
  }
  static positionOutOfRange(): PcfDcpError {
    return new PcfDcpError(
      PcfDcpErrorKind.PositionOutOfRange,
      "logical position is past end of content",
    );
  }
}
