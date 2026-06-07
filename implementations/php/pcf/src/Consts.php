<?php

declare(strict_types=1);

namespace Kduma\PCF;

/**
 * On-disk constants defined by PCF v1.0.
 *
 * Every value here is normative and corresponds directly to a figure in the
 * specification (see Appendix A, "Field Layout Summary").
 */
final class Consts
{
    /** File signature, 8 bytes: 0x89 'K' 'P' 'R' 'T' 0x0D 0x0A 0x1A. */
    public const MAGIC = "\x89KPRT\x0D\x0A\x1A";

    /** Major format version implemented by this library. */
    public const VERSION_MAJOR = 1;
    /** Minor format version implemented by this library. */
    public const VERSION_MINOR = 0;

    /** Fixed size of the file header, in bytes. */
    public const HEADER_SIZE = 20;
    /** Fixed size of a table-block header, in bytes. */
    public const TABLE_HEADER_SIZE = 74;
    /** Fixed size of a single partition entry, in bytes. */
    public const ENTRY_SIZE = 141;

    /** Size of every hash field, in bytes (large enough for the widest digest). */
    public const HASH_FIELD_SIZE = 64;
    /** Size of the partition label field, in bytes. */
    public const LABEL_SIZE = 32;
    /** Size of the partition UID field, in bytes. */
    public const UID_SIZE = 16;

    /**
     * Reserved partition type: invalid / uninitialised. MUST NOT label a live
     * partition.
     */
    public const TYPE_RESERVED = 0x0000_0000;
    /**
     * Reserved partition type: raw / blob, interpreted entirely by the
     * application.
     */
    public const TYPE_RAW = 0xFFFF_FFFF;

    /** The NIL UID (all zero). MUST NOT label a live partition. */
    public const NIL_UID = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    /**
     * Maximum number of entries a single table block can hold (partition_count
     * is a u8).
     */
    public const MAX_ENTRIES_PER_BLOCK = 255;

    /**
     * Sentinel value of partition_table_offset (header offset 12) meaning the
     * partition-table head is recorded in the file {@see Trailer} at the end of
     * the file rather than in the header. The on-disk value is the all-ones u64
     * (0xFFFFFFFFFFFFFFFF); on PHP's signed 64-bit integers that is -1, which is
     * exactly what unpack('P') / pack('P', -1) round-trip.
     */
    public const PT_OFFSET_TRAILER = -1;

    /** Fixed size of the optional file trailer, in bytes. */
    public const TRAILER_SIZE = 20;

    /**
     * Trailer signature, 8 bytes: the file {@see MAGIC} reversed
     * (0x1A 0x0A 0x0D 'T' 'R' 'P' 'K' 0x89). Placed as the final 8 bytes of the
     * file so a reader can detect and validate the trailer at the end.
     */
    public const TRAILER_MAGIC = "\x1A\x0A\x0DTRPK\x89";

    /** Chain-direction flag: forward chain, head = first block. */
    public const CHAIN_FORWARD = 0;
    /** Chain-direction flag: backward chain, head = last/newest block. */
    public const CHAIN_BACKWARD = 1;

    private function __construct()
    {
    }
}
