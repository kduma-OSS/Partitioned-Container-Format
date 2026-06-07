//! On-disk constants defined by PCF v1.0.
//!
//! Every value here is normative and corresponds directly to a figure in the
//! specification (see Appendix A, "Field Layout Summary").

/// File signature, 8 bytes: `0x89 'K' 'P' 'R' 'T' 0x0D 0x0A 0x1A`.
pub const MAGIC: [u8; 8] = [0x89, b'K', b'P', b'R', b'T', 0x0D, 0x0A, 0x1A];

/// Major format version implemented by this crate.
pub const VERSION_MAJOR: u16 = 1;
/// Minor format version implemented by this crate.
pub const VERSION_MINOR: u16 = 0;

/// Fixed size of the file header, in bytes.
pub const HEADER_SIZE: u64 = 20;
/// Fixed size of a table-block header, in bytes.
pub const TABLE_HEADER_SIZE: u64 = 74;
/// Fixed size of a single partition entry, in bytes.
pub const ENTRY_SIZE: u64 = 141;

/// Size of every hash field, in bytes (large enough for the widest digest).
pub const HASH_FIELD_SIZE: usize = 64;
/// Size of the partition label field, in bytes.
pub const LABEL_SIZE: usize = 32;
/// Size of the partition UID field, in bytes.
pub const UID_SIZE: usize = 16;

/// Reserved partition type: invalid / uninitialised. MUST NOT label a live
/// partition.
pub const TYPE_RESERVED: u32 = 0x0000_0000;
/// Reserved partition type: raw / blob, interpreted entirely by the
/// application.
pub const TYPE_RAW: u32 = 0xFFFF_FFFF;

/// The NIL UID (all zero). MUST NOT label a live partition.
pub const NIL_UID: [u8; UID_SIZE] = [0u8; UID_SIZE];

/// Maximum number of entries a single table block can hold (`partition_count`
/// is a `u8`).
pub const MAX_ENTRIES_PER_BLOCK: u32 = 255;

/// Sentinel value of `partition_table_offset` (header offset 12). When the
/// header holds this value the partition-table head is not stored in the
/// header; it is recorded in the fixed [`crate::Trailer`] at the end of the
/// file (spec section 4 and "File Trailer"). The all-ones value can never be a
/// real offset, so it is unambiguous.
pub const PT_OFFSET_TRAILER: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// Fixed size of the optional file trailer, in bytes.
pub const TRAILER_SIZE: u64 = 20;

/// Trailer signature, 8 bytes: the file [`MAGIC`] reversed
/// (`0x1A 0x0A 0x0D 'T' 'R' 'P' 'K' 0x89`). Placed as the final 8 bytes of the
/// file so a reader can detect and validate the trailer by reading the last
/// [`TRAILER_SIZE`] bytes.
pub const TRAILER_MAGIC: [u8; 8] = [0x1A, 0x0A, 0x0D, b'T', b'R', b'P', b'K', 0x89];

/// Chain-direction flag (Trailer `chain_flags` bit 0 clear): the chain is
/// forward-linked and the head is the first block; `next_table_offset` points
/// to the next block. This matches the classic header-pointer layout.
pub const CHAIN_FORWARD: u8 = 0;

/// Chain-direction flag (Trailer `chain_flags` bit 0 set): the chain is
/// backward-linked and the head (recorded in the Trailer) is the last/newest
/// block; `next_table_offset` is reinterpreted as the offset of the *previous*
/// (older) block. Both directions still terminate at 0.
pub const CHAIN_BACKWARD: u8 = 1;
