/**
 * Error type shared across the library (mirrors the reference `Error` enum).
 */

/** Discriminant identifying which kind of {@link PcfError} occurred. */
export enum PcfErrorKind {
  /** Underlying I/O failure. */
  Io = "Io",
  /** The file does not begin with the PCF magic. */
  BadMagic = "BadMagic",
  /** The file's major version is not implemented by this library. */
  UnsupportedMajor = "UnsupportedMajor",
  /** A hash-algorithm identifier is not in the registry. */
  UnknownHashAlgo = "UnknownHashAlgo",
  /** A live entry used the reserved type `0x00000000`. */
  ReservedType = "ReservedType",
  /** A live entry used the NIL UID. */
  NilUid = "NilUid",
  /** `used_bytes` exceeded `max_length` for an entry. */
  UsedExceedsMax = "UsedExceedsMax",
  /** A label byte was outside the permitted range (>= 0x80), or too long. */
  InvalidLabel = "InvalidLabel",
  /** A table block failed hash verification. */
  TableHashMismatch = "TableHashMismatch",
  /** A partition's data failed hash verification. */
  DataHashMismatch = "DataHashMismatch",
  /** An in-place update supplied more data than the partition's reservation. */
  DataTooLarge = "DataTooLarge",
  /** No partition with the requested UID exists. */
  NotFound = "NotFound",
  /** An attempt was made to add a partition whose UID already exists. */
  DuplicateUid = "DuplicateUid",
}

/** All ways a PCF operation can fail. */
export class PcfError extends Error {
  /** The kind of failure. */
  readonly kind: PcfErrorKind;
  /**
   * Optional numeric detail (e.g. the unsupported major version or the unknown
   * hash-algorithm id), preserved for the variants that carry one.
   */
  readonly value?: number;

  constructor(kind: PcfErrorKind, message: string, value?: number) {
    super(message);
    this.name = "PcfError";
    this.kind = kind;
    this.value = value;
    // Restore the prototype chain when targeting older runtimes.
    Object.setPrototypeOf(this, PcfError.prototype);
  }

  static badMagic(): PcfError {
    return new PcfError(PcfErrorKind.BadMagic, "bad magic: not a PCF file");
  }

  static unsupportedMajor(v: number): PcfError {
    return new PcfError(
      PcfErrorKind.UnsupportedMajor,
      `unsupported major version ${v}`,
      v,
    );
  }

  static unknownHashAlgo(id: number): PcfError {
    return new PcfError(
      PcfErrorKind.UnknownHashAlgo,
      `unknown hash algorithm id ${id}`,
      id,
    );
  }

  static reservedType(): PcfError {
    return new PcfError(
      PcfErrorKind.ReservedType,
      "reserved partition type used for a live entry",
    );
  }

  static nilUid(): PcfError {
    return new PcfError(PcfErrorKind.NilUid, "NIL UID used for a live entry");
  }

  static usedExceedsMax(): PcfError {
    return new PcfError(
      PcfErrorKind.UsedExceedsMax,
      "used_bytes exceeds max_length",
    );
  }

  static invalidLabel(): PcfError {
    return new PcfError(PcfErrorKind.InvalidLabel, "invalid label");
  }

  static tableHashMismatch(): PcfError {
    return new PcfError(
      PcfErrorKind.TableHashMismatch,
      "table block hash mismatch",
    );
  }

  static dataHashMismatch(): PcfError {
    return new PcfError(
      PcfErrorKind.DataHashMismatch,
      "partition data hash mismatch",
    );
  }

  static dataTooLarge(): PcfError {
    return new PcfError(
      PcfErrorKind.DataTooLarge,
      "data larger than partition reservation",
    );
  }

  static notFound(): PcfError {
    return new PcfError(PcfErrorKind.NotFound, "partition not found");
  }

  static duplicateUid(): PcfError {
    return new PcfError(PcfErrorKind.DuplicateUid, "duplicate UID");
  }
}
