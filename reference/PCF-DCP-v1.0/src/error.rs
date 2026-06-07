//! Error type shared across the crate.

use std::fmt;

/// All ways a PCF-DCP operation can fail.
#[derive(Debug)]
pub enum Error {
    /// Underlying PCF container error.
    Pcf(pcf::Error),
    /// Underlying I/O failure.
    Io(std::io::Error),

    // ----- Malformed arena (spec Sections 6, 8, 13) ------------------------
    /// The arena did not begin with the `"PDCP"` magic (spec Section 6).
    BadDcpMagic,
    /// The arena's `profile_version_major` is not implemented by this crate.
    UnsupportedProfileMajor(u8),
    /// A Fragment Entry carried a `kind` this version does not implement
    /// (HOLE/REF/unknown), rendering the inner partition unreadable.
    BadFragmentKind(u8),
    /// An extent's `[offset, offset+length)` range escapes `[0, arena_used)`.
    OffsetOutOfRange,
    /// Reconstructed logical content length did not match the inner entry's
    /// `used_bytes` (spec Section 8.3), or a stored data hash did not verify.
    LengthMismatch {
        /// The `used_bytes` the inner entry declared.
        expected: u64,
        /// The length actually reconstructed from the Fragment Table.
        got: u64,
    },
    /// A stored hash (inner `table_hash` or inner `data_hash`) did not verify.
    HashMismatch,

    // ----- Logical-model violations (spec Sections 2.1, 7.2, 13) -----------
    /// No inner partition (or top-level partition) with the requested uid.
    NotFound,
    /// A uid is used by more than one partition file-wide (spec Section 2.1).
    DuplicateUid,
    /// An inner partition is itself a DCP container; nesting is forbidden in
    /// v1.0 (spec Appendix B, "Nesting").
    NestedContainer,
    /// A partition uid is the PCF NIL uid.
    NilUid,
    /// A partition type is the PCF reserved type `0x00000000`.
    ReservedType,
    /// A top-level partition expected to be a DCP container is not one.
    NotADcpContainer,
    /// A logical edit addressed a position beyond the partition's content.
    PositionOutOfRange,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Pcf(e) => write!(f, "pcf error: {e}"),
            Error::Io(e) => write!(f, "i/o error: {e}"),
            Error::BadDcpMagic => write!(f, "arena does not begin with \"PDCP\" magic"),
            Error::UnsupportedProfileMajor(v) => {
                write!(f, "unsupported PCF-DCP profile major version {v}")
            }
            Error::BadFragmentKind(k) => write!(f, "unsupported fragment kind {k}"),
            Error::OffsetOutOfRange => write!(f, "extent range escapes the arena"),
            Error::LengthMismatch { expected, got } => {
                write!(f, "logical length mismatch: expected {expected}, got {got}")
            }
            Error::HashMismatch => write!(f, "stored hash does not verify"),
            Error::NotFound => write!(f, "no partition with that uid"),
            Error::DuplicateUid => write!(f, "uid is not unique file-wide"),
            Error::NestedContainer => write!(f, "an inner partition may not be a DCP container"),
            Error::NilUid => write!(f, "uid is the NIL uid"),
            Error::ReservedType => write!(f, "partition type is the reserved type 0x00000000"),
            Error::NotADcpContainer => write!(f, "partition is not a DCP container"),
            Error::PositionOutOfRange => write!(f, "logical position is past end of content"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Pcf(e) => Some(e),
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<pcf::Error> for Error {
    fn from(e: pcf::Error) -> Self {
        Error::Pcf(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;
