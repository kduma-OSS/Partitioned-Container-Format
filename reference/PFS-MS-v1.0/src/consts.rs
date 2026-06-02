//! On-disk constants defined by PFS-MS v1.0.
//!
//! Every value here is normative and corresponds directly to a figure in the
//! specification (`specs/PFS-MS-spec-v1.0.txt`, Section 5, Section 7, Section 8
//! and Appendix B).

/// PCF partition type for a Node Record (Section 7).
pub const PFS_NODE_TYPE: u32 = 0xAAAA_0001;
/// PCF partition type for a Session Record (Section 8).
pub const PFS_SESSION_TYPE: u32 = 0xAAAA_0002;
/// PCF RAW/BLOB type used for file content (full bytes or a delta patch).
pub const RAW_TYPE: u32 = pcf::TYPE_RAW;

/// Node Record magic, `"PFSN"`.
pub const NODE_MAGIC: [u8; 4] = *b"PFSN";
/// Session Record magic, `"PFSS"`.
pub const SESSION_MAGIC: [u8; 4] = *b"PFSS";

/// `record_version` of a Node Record in this profile version.
pub const NODE_RECORD_VERSION: u8 = 1;
/// Profile major version.
pub const PROFILE_VERSION_MAJOR: u8 = 1;
/// Profile minor version.
pub const PROFILE_VERSION_MINOR: u8 = 0;

/// Node kind: a file.
pub const KIND_FILE: u8 = 1;
/// Node kind: a directory.
pub const KIND_DIR: u8 = 2;

/// Node flag bit 0: the node is deleted as of this session.
pub const FLAG_TOMBSTONE: u16 = 0x0001;
/// Mask of all defined node-flag bits (others MUST be 0).
pub const FLAG_DEFINED_MASK: u16 = FLAG_TOMBSTONE;

/// `content_kind`: the empty byte string.
pub const CONTENT_EMPTY: u8 = 0;
/// `content_kind`: full bytes in one RAW partition.
pub const CONTENT_DIRECT: u8 = 1;
/// `content_kind`: a patch against the previous version.
pub const CONTENT_DELTA: u8 = 2;
/// `content_kind`: identical bytes to the previous version.
pub const CONTENT_INHERIT: u8 = 3;

/// `patch_algo_id`: VCDIFF (RFC 3284), the required default.
pub const PATCH_VCDIFF: u8 = 1;

/// The reserved root `node_id` (16 zero bytes).
pub const ROOT_NODE_ID: [u8; 16] = [0u8; 16];

/// Maximum UTF-8 byte length of a node name (`PFS_MAX_NAME`).
pub const PFS_MAX_NAME: usize = 1024;

/// Fixed prefix length of a Node Record, in bytes (Section 7.1).
pub const NODE_PREFIX_LEN: usize = 54;
/// Length of a DIRECT content section, in bytes (Section 7.3).
pub const DIRECT_SECTION_LEN: usize = 90;
/// Length of a DELTA content section, in bytes (Section 7.3).
pub const DELTA_SECTION_LEN: usize = 164;
/// Fixed prefix length of a Session Record (before the writer field).
pub const SESSION_PREFIX_LEN: usize = 162;

/// Writer re-baseline threshold (`PFS_RECOMMENDED_MAX_DELTA_DEPTH`).
pub const RECOMMENDED_MAX_DELTA_DEPTH: usize = 16;
/// Minimum delta depth a reader must support (`PFS_MIN_READER_DELTA_DEPTH`).
pub const MIN_READER_DELTA_DEPTH: usize = 64;

/// Width of every hash field (matches PCF's 64-byte fields).
pub const HASH_FIELD_SIZE: usize = pcf::HASH_FIELD_SIZE;
