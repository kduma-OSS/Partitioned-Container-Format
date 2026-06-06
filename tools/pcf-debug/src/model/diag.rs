//! Diagnostics produced while walking and modelling a PCF file.
//!
//! A debugger must describe broken files, not reject them. Every structural
//! anomaly we can detect is captured here as a [`Diagnostic`] rather than an
//! error that aborts the walk.

/// The class of an anomaly found in a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagKind {
    /// Two physical regions cover overlapping bytes.
    Overlap { start: u64, len: u64 },
    /// A run of bytes covered by no region (dead space / padding).
    Gap { start: u64, len: u64 },
    /// A declared region runs past the end of the file.
    Truncated { start: u64, want: u64, have: u64 },
    /// The block chain links back to a block already visited.
    ChainCycle { at_offset: u64 },
    /// A `next_table_offset` points to an earlier offset (legal under the
    /// PFS-MS append model, surfaced for information only).
    BackwardChainLink { from: u64, to: u64 },
    /// The header holds the trailer sentinel; the partition-table head was
    /// resolved from a file trailer (surfaced for information only).
    TrailerResolved {
        /// Offset of the resolved trailer.
        trailer_offset: u64,
        /// Partition-table head recorded in the trailer (0 = empty).
        head: u64,
        /// Whether the trailer flags the chain as backward-linked.
        backward: bool,
    },
    /// A partition's stored `data_hash` does not match its bytes.
    DataHashMismatch { uid: [u8; 16] },
    /// A table block's stored `table_hash` does not match its bytes.
    TableHashMismatch { block_index: usize },
    /// A live entry failed the PCF conformance checks.
    EntryInvalid { uid: [u8; 16], reason: String },
    /// The file header could not be parsed.
    BadHeader { reason: String },
    /// A table block header could not be parsed.
    BadBlock { offset: u64, reason: String },
}

/// How serious a [`Diagnostic`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    /// Short uppercase tag used in text output.
    pub fn tag(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warning => "WARN",
            Severity::Error => "ERROR",
        }
    }
}

/// One finding about a file.
#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub severity: Severity,
    pub kind: DiagKind,
    pub message: String,
}

impl Diagnostic {
    pub fn info(kind: DiagKind, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Info,
            kind,
            message: message.into(),
        }
    }
    pub fn warn(kind: DiagKind, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            kind,
            message: message.into(),
        }
    }
    pub fn error(kind: DiagKind, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            kind,
            message: message.into(),
        }
    }
}
