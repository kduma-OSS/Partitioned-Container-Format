//! Error type shared across the crate.

use std::fmt;

/// All ways a PCF operation can fail.
#[derive(Debug)]
pub enum Error {
    /// Underlying I/O failure.
    Io(std::io::Error),
    /// The file does not begin with the PCF magic.
    BadMagic,
    /// The file's major version is not implemented by this crate.
    UnsupportedMajor(u16),
    /// The header requested trailer-based table location but the trailer at the
    /// end of the file is missing or has a bad magic (e.g. a truncated file).
    BadTrailer,
    /// A hash-algorithm identifier is not in the registry.
    UnknownHashAlgo(u8),
    /// A live entry used the reserved type `0x00000000`.
    ReservedType,
    /// A live entry used the NIL UID.
    NilUid,
    /// `used_bytes` exceeded `max_length` for an entry.
    UsedExceedsMax,
    /// A label byte was outside the permitted range (>= 0x80), or too long.
    InvalidLabel,
    /// A table block failed hash verification.
    TableHashMismatch,
    /// A partition's data failed hash verification.
    DataHashMismatch,
    /// An in-place update supplied more data than the partition's reservation.
    DataTooLarge,
    /// No partition with the requested UID exists.
    NotFound,
    /// An attempt was made to add a partition whose UID already exists.
    DuplicateUid,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "i/o error: {e}"),
            Error::BadMagic => write!(f, "bad magic: not a PCF file"),
            Error::UnsupportedMajor(v) => write!(f, "unsupported major version {v}"),
            Error::BadTrailer => write!(f, "missing or invalid file trailer"),
            Error::UnknownHashAlgo(id) => write!(f, "unknown hash algorithm id {id}"),
            Error::ReservedType => write!(f, "reserved partition type used for a live entry"),
            Error::NilUid => write!(f, "NIL UID used for a live entry"),
            Error::UsedExceedsMax => write!(f, "used_bytes exceeds max_length"),
            Error::InvalidLabel => write!(f, "invalid label"),
            Error::TableHashMismatch => write!(f, "table block hash mismatch"),
            Error::DataHashMismatch => write!(f, "partition data hash mismatch"),
            Error::DataTooLarge => write!(f, "data larger than partition reservation"),
            Error::NotFound => write!(f, "partition not found"),
            Error::DuplicateUid => write!(f, "duplicate UID"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;
