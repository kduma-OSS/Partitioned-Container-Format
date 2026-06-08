<?php

declare(strict_types=1);

namespace Kduma\PCFDCP;

/**
 * On-disk constants defined by PCF-DCP v1.0 (spec Appendix A and B). Every value
 * here is normative.
 */
final class Consts
{
    /** PCF partition type carrying one DCP arena. */
    public const DCP_CONTAINER_TYPE = 0xAAAC_0001;

    /** First value reserved by this profile for future types. */
    public const DCP_TYPE_RESERVED_LO = 0xAAAC_0000;
    /** Last value reserved by this profile. */
    public const DCP_TYPE_RESERVED_HI = 0xAAAC_00FF;

    /** 4-byte magic at the start of a DCP arena: "PDCP". */
    public const DCP_MAGIC = "PDCP";

    /** PCF-DCP profile version implemented by this library (major). */
    public const PROFILE_VERSION_MAJOR = 1;
    /** PCF-DCP profile version implemented by this library (minor). */
    public const PROFILE_VERSION_MINOR = 0;

    /** Fixed size of the DCP Header, in bytes (spec Section 6). */
    public const DCP_HEADER_SIZE = 24;
    /** Fixed size of a Fragment Table block header, in bytes. */
    public const FRAGTABLE_HEADER_SIZE = 9;
    /** Fixed size of one Fragment Entry, in bytes. */
    public const FRAGMENT_ENTRY_SIZE = 18;

    /** Fragment Entry kind: RESERVED / INVALID guard. */
    public const KIND_INVALID = 0;
    /** Fragment Entry kind: DATA — literal content (only kind in v1.0). */
    public const KIND_DATA = 1;
    /** Fragment Entry kind: HOLE (RESERVED). */
    public const KIND_HOLE = 2;
    /** Fragment Entry kind: REF (RESERVED). */
    public const KIND_REF = 3;

    /** Fragment Entry flags bit 0: SHARED (copy-on-write required). */
    public const FLAG_SHARED = 0x01;

    /** The arena-relative offset value reserved as "none" / terminator. */
    public const ARENA_NONE = 0;

    /** Max entries per (inner) Table Block and extents per Fragment block. */
    public const MAX_ENTRIES_PER_BLOCK = 255;

    private function __construct()
    {
    }
}
