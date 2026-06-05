//! Error type shared across the crate.

use std::fmt;

/// All ways a PCF-SIG operation can fail.
#[derive(Debug)]
pub enum Error {
    /// Underlying PCF container error.
    Pcf(pcf::Error),
    /// Underlying I/O failure.
    Io(std::io::Error),

    // ----- Malformed records (spec Section 15, R3..R5) ----------------------
    /// A Key Record did not begin with `"PCFKEY\0\0"`.
    BadKeyMagic,
    /// A Manifest did not begin with `"PCFSIG\0\0"`.
    BadManifestMagic,
    /// A record's profile major version is not implemented by this crate.
    UnsupportedMajor(u16),
    /// A Key Record's `key_format_id` is unknown or reserved (0).
    UnknownKeyFormat(u8),
    /// A Key Record's `key_data_length` is zero.
    EmptyKeyData,
    /// A Key Record's reserved bytes are non-zero in v1.0.
    NonZeroKeyReserved,
    /// `fingerprint` does not equal `SHA-256(key_data)`.
    FingerprintMismatch,

    /// A Manifest's `sig_algo_id` is reserved (0) or unknown.
    UnknownSigAlgo(u8),
    /// A Manifest's `manifest_hash_algo_id` is not cryptographic
    /// (must be 16, 17, or 18).
    NonCryptoManifestHash(u8),
    /// `manifest_hash_algo_id` does not match the binding required by the
    /// chosen `sig_algo_id` (spec Section 8).
    HashAlgoBindingMismatch,
    /// `flags` carries bits not defined in v1.0.
    NonZeroFlags,
    /// `signed_count` is 0.
    EmptyManifest,
    /// `trailer_length` is non-zero (reserved in v1.0).
    NonZeroTrailer,
    /// A SignedEntry's reserved span (1 B or 92 B) is non-zero.
    NonZeroEntryReserved,
    /// A SignedEntry's `data_hash_algo_id` is not cryptographic
    /// (spec Section 9).
    NonCryptoEntryHash(u8),
    /// A SignedEntry references the PCF NIL UID.
    EntryNilUid,
    /// A SignedEntry uses PCF reserved type 0x00000000.
    EntryReservedType,
    /// Two SignedEntry records share the same uid.
    DuplicateSignedUid,
    /// A SignedEntry references the enclosing PCFSIG_SIG partition's own uid.
    SelfSignedEntry,
    /// A truncation, short read, or length-field mismatch in the partition
    /// payload (manifest tail, sig_length, trailer_length).
    MalformedSignaturePartition,

    // ----- Verification outcomes (spec Section 11) --------------------------
    /// The signature did not verify against the manifest bytes.
    SignatureInvalid,
    /// The fingerprint named in the manifest does not match any PCFSIG_KEY
    /// partition in the file.
    SigningKeyNotFound,
    /// The signature algorithm is not implemented by this build.
    UnsupportedSigAlgo(u8),
    /// The key format is not implemented by this build.
    UnsupportedKeyFormat(u8),
    /// Length of `sig_bytes` does not match the algorithm's natural size.
    SignatureLengthMismatch,

    // ----- Writer-side preflight (spec Section 15, W2..W6) ------------------
    /// The Writer was asked to sign a partition whose `data_hash_algo_id`
    /// is not cryptographic (spec Section 9).
    NonCryptoTargetHash,
    /// The Writer was asked to sign a partition that does not exist in the
    /// supplied container.
    TargetPartitionMissing,
    /// The Writer was asked to write two PCFSIG_KEY partitions with the same
    /// fingerprint in one file.
    DuplicateKeyFingerprint,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Pcf(e) => write!(f, "pcf error: {e}"),
            Error::Io(e) => write!(f, "i/o error: {e}"),
            Error::BadKeyMagic => write!(f, "bad PCFSIG_KEY magic"),
            Error::BadManifestMagic => write!(f, "bad PCFSIG_SIG manifest magic"),
            Error::UnsupportedMajor(v) => write!(f, "unsupported PCF-SIG major version {v}"),
            Error::UnknownKeyFormat(id) => write!(f, "unknown key_format_id {id}"),
            Error::EmptyKeyData => write!(f, "key_data_length is zero"),
            Error::NonZeroKeyReserved => write!(f, "key record reserved bytes are non-zero"),
            Error::FingerprintMismatch => {
                write!(f, "stored key fingerprint does not match SHA-256(key_data)")
            }
            Error::UnknownSigAlgo(id) => write!(f, "unknown or reserved sig_algo_id {id}"),
            Error::NonCryptoManifestHash(id) => {
                write!(f, "manifest_hash_algo_id {id} is not cryptographic")
            }
            Error::HashAlgoBindingMismatch => write!(
                f,
                "manifest_hash_algo_id does not match the binding required by sig_algo_id"
            ),
            Error::NonZeroFlags => write!(f, "manifest flags are non-zero in v1.0"),
            Error::EmptyManifest => write!(f, "manifest signed_count is 0"),
            Error::NonZeroTrailer => write!(f, "trailer_length is non-zero in v1.0"),
            Error::NonZeroEntryReserved => {
                write!(f, "SignedEntry reserved span contains non-zero bytes")
            }
            Error::NonCryptoEntryHash(id) => {
                write!(f, "SignedEntry data_hash_algo_id {id} is not cryptographic")
            }
            Error::EntryNilUid => write!(f, "SignedEntry uses the NIL UID"),
            Error::EntryReservedType => {
                write!(f, "SignedEntry uses PCF reserved type 0x00000000")
            }
            Error::DuplicateSignedUid => write!(f, "duplicate uid in manifest"),
            Error::SelfSignedEntry => {
                write!(f, "SignedEntry references the PCFSIG_SIG partition itself")
            }
            Error::MalformedSignaturePartition => {
                write!(f, "PCFSIG_SIG partition layout is malformed")
            }
            Error::SignatureInvalid => write!(f, "signature does not verify"),
            Error::SigningKeyNotFound => {
                write!(f, "no PCFSIG_KEY partition matches signer_key_fingerprint")
            }
            Error::UnsupportedSigAlgo(id) => write!(f, "sig_algo_id {id} is not implemented"),
            Error::UnsupportedKeyFormat(id) => write!(f, "key_format_id {id} is not implemented"),
            Error::SignatureLengthMismatch => {
                write!(f, "sig_bytes length does not match the algorithm")
            }
            Error::NonCryptoTargetHash => write!(
                f,
                "cannot sign a partition whose data_hash_algo_id is not cryptographic"
            ),
            Error::TargetPartitionMissing => {
                write!(f, "partition to sign is not present in the container")
            }
            Error::DuplicateKeyFingerprint => {
                write!(f, "a PCFSIG_KEY with this fingerprint already exists")
            }
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
