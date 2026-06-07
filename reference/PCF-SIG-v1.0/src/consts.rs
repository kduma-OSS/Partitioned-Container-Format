//! On-disk constants defined by PCF-SIG v1.0.
//!
//! Every value here is normative and corresponds directly to a figure in the
//! specification (see Appendix A, "Field Layout Summary").

/// PCF partition type carrying one Key Record (spec Section 5).
pub const TYPE_PCFSIG_KEY: u32 = 0xAAAB_0001;

/// PCF partition type carrying one Signature Partition (spec Section 5).
pub const TYPE_PCFSIG_SIG: u32 = 0xAAAB_0002;

/// 8-byte magic at the start of a Key Record (spec Section 6.1).
pub const KEY_MAGIC: [u8; 8] = [b'P', b'C', b'F', b'K', b'E', b'Y', 0x00, 0x00];

/// 8-byte magic at the start of a Signature Partition's Manifest
/// (spec Section 7.1).
pub const SIG_MAGIC: [u8; 8] = [b'P', b'C', b'F', b'S', b'I', b'G', 0x00, 0x00];

/// Profile version implemented by this crate (major).
pub const PROFILE_VERSION_MAJOR: u16 = 1;

/// Profile version implemented by this crate (minor).
pub const PROFILE_VERSION_MINOR: u16 = 0;

/// Length of the Key Record fixed prefix that precedes `key_data`
/// (spec Section 6.1).
pub const KEY_PREFIX_SIZE: usize = 52;

/// Length of the Manifest fixed prefix that precedes `signed_entries`
/// (spec Section 7.1).
pub const MANIFEST_PREFIX_SIZE: usize = 60;

/// Length of one Signed Entry (spec Section 7.2).
pub const SIGNED_ENTRY_SIZE: usize = 218;

/// Length of a SHA-256 key fingerprint (spec Section 6.3).
pub const FINGERPRINT_SIZE: usize = 32;

/// Length of the Ed25519 raw public key (spec Section 6.2, key_format_id = 1).
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Length of an Ed25519 signature (spec Section 8, sig_algo_id = 1).
pub const ED25519_SIGNATURE_LEN: usize = 64;
