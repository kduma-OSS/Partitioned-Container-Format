//! Error and result types for the PFS-MS reference implementation.

use std::fmt;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong reading, writing, or reconstructing a PFS-MS
/// filesystem. Container-level failures are wrapped from [`pcf::Error`].
#[derive(Debug)]
pub enum Error {
    /// An underlying I/O failure.
    Io(std::io::Error),
    /// A PCF container-level error (bad magic, hash mismatch, …).
    Pcf(pcf::Error),

    /// A Node Record was structurally invalid (bad magic/version/kind, a
    /// reserved flag bit set, an out-of-range or illegal name, a truncated
    /// content section, …) — spec R4.
    MalformedNode(&'static str),
    /// A Session Record was structurally invalid — spec R3.
    MalformedSession(&'static str),

    /// The backward-linked session chain was inconsistent: a HEAD block lacked
    /// its single PFS_SESSION partition, a MEMBER block carried one, the
    /// session_seq order was not strictly decreasing, or block_count did not
    /// match the chain — spec R3.
    BrokenChain(&'static str),
    /// The inter-session hash chain failed verification (a table_hash,
    /// member_blocks_digest, or prev_session_hash mismatch) — spec R8.
    ChainHashMismatch,

    /// The same node_id appeared twice within one session — spec R5.
    DuplicateNodeInSession,
    /// A liveness walk to the root encountered a cycle — spec R6.
    ParentCycle,

    /// A referenced RAW content/patch partition was missing from the file.
    MissingContent,
    /// A reconstructed file failed its full_hash or base_full_hash check, or a
    /// RAW partition failed its PCF data_hash — spec R7.
    ContentHashMismatch,
    /// A DELTA/INHERIT base could not be resolved (history is malformed).
    MissingBase,
    /// A delta used an unimplemented patch_algo_id; the affected file is
    /// unreadable but the container is not malformed on that basis (Section 9.2).
    UnsupportedPatchAlgo(u8),
    /// A file's delta chain exceeded the reader's supported depth.
    DeltaTooDeep,
    /// VCDIFF encode/decode failed.
    Vcdiff(String),

    /// A requested path did not resolve to a live node.
    NotFound,
    /// A path component was not a directory.
    NotADirectory,
    /// The target already exists where a fresh node was required.
    AlreadyExists,
    /// An operation supplied an invalid path or name.
    InvalidPath(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Pcf(e) => write!(f, "pcf error: {e}"),
            Error::MalformedNode(m) => write!(f, "malformed node record: {m}"),
            Error::MalformedSession(m) => write!(f, "malformed session record: {m}"),
            Error::BrokenChain(m) => write!(f, "broken session chain: {m}"),
            Error::ChainHashMismatch => write!(f, "inter-session hash chain mismatch"),
            Error::DuplicateNodeInSession => write!(f, "node_id appears twice in one session"),
            Error::ParentCycle => write!(f, "cycle in parent hierarchy"),
            Error::MissingContent => write!(f, "referenced content partition is missing"),
            Error::ContentHashMismatch => write!(f, "file content hash mismatch"),
            Error::MissingBase => write!(f, "delta/inherit base is missing"),
            Error::UnsupportedPatchAlgo(id) => write!(f, "unsupported patch_algo_id {id}"),
            Error::DeltaTooDeep => write!(f, "delta chain too deep"),
            Error::Vcdiff(m) => write!(f, "vcdiff error: {m}"),
            Error::NotFound => write!(f, "path not found"),
            Error::NotADirectory => write!(f, "not a directory"),
            Error::AlreadyExists => write!(f, "already exists"),
            Error::InvalidPath(m) => write!(f, "invalid path: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<pcf::Error> for Error {
    fn from(e: pcf::Error) -> Self {
        Error::Pcf(e)
    }
}
