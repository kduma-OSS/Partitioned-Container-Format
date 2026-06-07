//! On-disk constants defined by PCF-DCP v1.0.
//!
//! Every value here is normative and corresponds directly to a figure in the
//! specification (`specs/PCF-DCP-spec-v1.0.txt`, Appendix A and B).

/// PCF partition type carrying one DCP arena (spec Appendix B). A generic PCF
/// reader sees this as one opaque, typed partition.
pub const DCP_CONTAINER_TYPE: u32 = 0xAAAC_0001;

/// First value of the block reserved by this profile for future partition
/// types (spec Appendix B).
pub const DCP_TYPE_RESERVED_LO: u32 = 0xAAAC_0000;

/// Last value of the block reserved by this profile (spec Appendix B).
pub const DCP_TYPE_RESERVED_HI: u32 = 0xAAAC_00FF;

/// 4-byte magic at the start of a DCP arena (spec Section 6): `"PDCP"`.
pub const DCP_MAGIC: [u8; 4] = [0x50, 0x44, 0x43, 0x50];

/// PCF-DCP profile version implemented by this crate (major, spec Section 14).
pub const PROFILE_VERSION_MAJOR: u8 = 1;

/// PCF-DCP profile version implemented by this crate (minor, spec Section 14).
pub const PROFILE_VERSION_MINOR: u8 = 0;

/// Fixed size of the DCP Header, in bytes (spec Section 6).
pub const DCP_HEADER_SIZE: u64 = 24;

/// Fixed size of a Fragment Table block header, in bytes (spec Section 8.1).
pub const FRAGTABLE_HEADER_SIZE: u64 = 9;

/// Fixed size of one Fragment Entry, in bytes (spec Section 8.2).
pub const FRAGMENT_ENTRY_SIZE: u64 = 18;

/// Fragment Entry kind: RESERVED / INVALID guard (spec Section 8.2). MUST NOT
/// appear in a live entry.
pub const KIND_INVALID: u8 = 0;
/// Fragment Entry kind: DATA — literal content bytes (the only kind defined in
/// v1.0).
pub const KIND_DATA: u8 = 1;
/// Fragment Entry kind: HOLE (RESERVED for sparse content; MUST NOT be written
/// in v1.0).
pub const KIND_HOLE: u8 = 2;
/// Fragment Entry kind: REF (RESERVED for cross-container references; MUST NOT
/// be written in v1.0).
pub const KIND_REF: u8 = 3;

/// Fragment Entry `flags` bit 0: SHARED — the extent's bytes MUST NOT be
/// overwritten in place; edits must be copy-on-write (spec Section 8.4).
pub const FLAG_SHARED: u8 = 0x01;

/// The arena-relative offset value reserved as "none" / chain terminator
/// (spec Appendix B).
pub const ARENA_NONE: u64 = 0;

/// Maximum number of entries a single (inner) Table Block can hold, and the
/// maximum number of Fragment Entries a single Fragment Table block can hold
/// (both counts are a `u8`).
pub const MAX_ENTRIES_PER_BLOCK: usize = 255;
