/**
 * On-disk constants defined by PCF-DCP v1.0.
 *
 * Every value here is normative and corresponds directly to a figure in the
 * specification (`PCF-DCP-spec-v1.0.txt`, Appendix A and B).
 */

/** PCF partition type carrying one DCP arena (spec Appendix B). */
export const DCP_CONTAINER_TYPE = 0xaaac_0001;

/** First value of the block reserved by this profile for future types. */
export const DCP_TYPE_RESERVED_LO = 0xaaac_0000;
/** Last value of the block reserved by this profile. */
export const DCP_TYPE_RESERVED_HI = 0xaaac_00ff;

/** 4-byte magic at the start of a DCP arena (spec Section 6): `"PDCP"`. */
export const DCP_MAGIC: Uint8Array = new Uint8Array([0x50, 0x44, 0x43, 0x50]);

/** PCF-DCP profile version implemented by this library (major). */
export const PROFILE_VERSION_MAJOR = 1;
/** PCF-DCP profile version implemented by this library (minor). */
export const PROFILE_VERSION_MINOR = 0;

/** Fixed size of the DCP Header, in bytes (spec Section 6). */
export const DCP_HEADER_SIZE = 24;
/** Fixed size of a Fragment Table block header, in bytes (spec Section 8.1). */
export const FRAGTABLE_HEADER_SIZE = 9;
/** Fixed size of one Fragment Entry, in bytes (spec Section 8.2). */
export const FRAGMENT_ENTRY_SIZE = 18;

/** Fragment Entry kind: RESERVED / INVALID guard. */
export const KIND_INVALID = 0;
/** Fragment Entry kind: DATA — literal content bytes (only kind in v1.0). */
export const KIND_DATA = 1;
/** Fragment Entry kind: HOLE (RESERVED). */
export const KIND_HOLE = 2;
/** Fragment Entry kind: REF (RESERVED). */
export const KIND_REF = 3;

/** Fragment Entry `flags` bit 0: SHARED — no in-place overwrite (copy-on-write). */
export const FLAG_SHARED = 0x01;

/** The arena-relative offset value reserved as "none" / chain terminator. */
export const ARENA_NONE = 0;

/** Maximum entries per (inner) Table Block and extents per Fragment Table block. */
export const MAX_ENTRIES_PER_BLOCK = 255;
