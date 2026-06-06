<?php

declare(strict_types=1);

namespace Kduma\PCF;

/**
 * Discriminator for {@see PcfException}, mirroring the reference implementation's
 * error enum. Tests can branch on the concrete kind (cf. Rust `matches!`).
 */
enum ErrorKind: string
{
    /** Underlying I/O failure. */
    case Io = 'io';
    /** The file does not begin with the PCF magic. */
    case BadMagic = 'bad_magic';
    /** The file's major version is not implemented by this library. */
    case UnsupportedMajor = 'unsupported_major';
    /** A hash-algorithm identifier is not in the registry. */
    case UnknownHashAlgo = 'unknown_hash_algo';
    /** A live entry used the reserved type 0x00000000. */
    case ReservedType = 'reserved_type';
    /** A live entry used the NIL UID. */
    case NilUid = 'nil_uid';
    /** used_bytes exceeded max_length for an entry. */
    case UsedExceedsMax = 'used_exceeds_max';
    /** A label byte was outside the permitted range (>= 0x80), or too long. */
    case InvalidLabel = 'invalid_label';
    /** A table block failed hash verification. */
    case TableHashMismatch = 'table_hash_mismatch';
    /** A partition's data failed hash verification. */
    case DataHashMismatch = 'data_hash_mismatch';
    /** An in-place update supplied more data than the partition's reservation. */
    case DataTooLarge = 'data_too_large';
    /** No partition with the requested UID exists. */
    case NotFound = 'not_found';
    /** An attempt was made to add a partition whose UID already exists. */
    case DuplicateUid = 'duplicate_uid';
    /** The header requested trailer-based location but no valid trailer exists. */
    case BadTrailer = 'bad_trailer';
}
