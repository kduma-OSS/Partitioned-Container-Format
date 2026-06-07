/**
 * On-disk constants defined by PCF v1.0.
 *
 * Every value here is normative and corresponds directly to a figure in the
 * specification (see Appendix A, "Field Layout Summary").
 */

/** File signature, 8 bytes: `0x89 'K' 'P' 'R' 'T' 0x0D 0x0A 0x1A`. */
export const MAGIC: Uint8Array = new Uint8Array([
  0x89, 0x4b, 0x50, 0x52, 0x54, 0x0d, 0x0a, 0x1a,
]);

/** Major format version implemented by this library. */
export const VERSION_MAJOR = 1;
/** Minor format version implemented by this library. */
export const VERSION_MINOR = 0;

/** Fixed size of the file header, in bytes. */
export const HEADER_SIZE = 20;
/** Fixed size of a table-block header, in bytes. */
export const TABLE_HEADER_SIZE = 74;
/** Fixed size of a single partition entry, in bytes. */
export const ENTRY_SIZE = 141;

/** Size of every hash field, in bytes (large enough for the widest digest). */
export const HASH_FIELD_SIZE = 64;
/** Size of the partition label field, in bytes. */
export const LABEL_SIZE = 32;
/** Size of the partition UID field, in bytes. */
export const UID_SIZE = 16;

/**
 * Reserved partition type: invalid / uninitialised. MUST NOT label a live
 * partition.
 */
export const TYPE_RESERVED = 0x0000_0000;
/**
 * Reserved partition type: raw / blob, interpreted entirely by the
 * application.
 */
export const TYPE_RAW = 0xffff_ffff;

/** The NIL UID (all zero). MUST NOT label a live partition. */
export const NIL_UID: Uint8Array = new Uint8Array(UID_SIZE);

/**
 * Maximum number of entries a single table block can hold (`partition_count`
 * is a `u8`).
 */
export const MAX_ENTRIES_PER_BLOCK = 255;

/**
 * Sentinel value of `partition_table_offset` (header offset 12) meaning the
 * partition-table head is recorded in the file trailer at the end of the file
 * rather than in the header (spec section 4, "File Trailer"). The all-ones u64
 * can never be a real offset, so it is unambiguous.
 */
export const PT_OFFSET_TRAILER = 0xffff_ffff_ffff_ffffn;

/** Fixed size of the optional file trailer, in bytes. */
export const TRAILER_SIZE = 20;

/**
 * Trailer signature, 8 bytes: the file {@link MAGIC} reversed
 * (`0x1A 0x0A 0x0D 'T' 'R' 'P' 'K' 0x89`). Placed as the final 8 bytes of the
 * file so a reader can detect and validate the trailer at the end.
 */
export const TRAILER_MAGIC: Uint8Array = new Uint8Array([
  0x1a, 0x0a, 0x0d, 0x54, 0x52, 0x50, 0x4b, 0x89,
]);

/** Chain-direction flag: forward chain, head = first block. */
export const CHAIN_FORWARD = 0;
/** Chain-direction flag: backward chain, head = last/newest block. */
export const CHAIN_BACKWARD = 1;
