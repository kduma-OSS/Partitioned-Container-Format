//! The partition-decoder plugin system.
//!
//! A *decoder* turns a partition's raw bytes into a renderer-agnostic tree of
//! named fields ([`FieldNode`]). The CLI and HTML renderers both consume that
//! tree, so a decoder is written once and displayed everywhere.
//!
//! Decoders are registered statically (compiled into the binary). Adding a new
//! format means writing a module that implements [`PartitionDecoder`] and adding
//! one line to [`DecoderRegistry::with_builtins`]. The trait is deliberately
//! object-safe and the data types carry no borrowed state, so a future dynamic
//! (shared-library) backend could be added behind a feature without reworking
//! any decoder.

mod dcp;
mod pcfsig;
mod pfs;
mod raw;

pub use dcp::DcpContainerDecoder;
pub use pcfsig::{PcfSigKeyDecoder, PcfSigSignatureDecoder};
pub use pfs::{PfsNodeDecoder, PfsSessionDecoder};
pub use raw::RawDecoder;

/// A decoded field's value, kept independent of any output format.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    /// A grouping node with no value of its own.
    None,
    U64(u64),
    Bytes(Vec<u8>),
    Text(String),
    Uid([u8; 16]),
    /// A numeric code with a human name, e.g. `kind = 1 (file)`.
    Enum {
        raw: u64,
        name: String,
    },
    /// A bitset with the names of the bits that are set.
    Flags {
        raw: u64,
        set: Vec<String>,
    },
}

/// One node in a decoded field tree.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldNode {
    pub name: String,
    pub value: FieldValue,
    /// Byte range *within the partition data* this field occupies, if any.
    pub range: Option<(u64, u64)>,
    /// An optional remark, e.g. `"magic OK"` or `"reserved must be 0"`.
    pub note: Option<String>,
    pub children: Vec<FieldNode>,
}

impl FieldNode {
    /// A grouping node (no value, no range).
    pub fn group(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: FieldValue::None,
            range: None,
            note: None,
            children: Vec::new(),
        }
    }

    /// A leaf node carrying a value and the byte range it covers.
    pub fn leaf(name: impl Into<String>, value: FieldValue, range: (u64, u64)) -> Self {
        Self {
            name: name.into(),
            value,
            range: Some(range),
            note: None,
            children: Vec::new(),
        }
    }

    /// Attach a note (builder style).
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// Append a child (builder style).
    pub fn child(mut self, c: FieldNode) -> Self {
        self.children.push(c);
        self
    }

    /// Append a child in place.
    pub fn push(&mut self, c: FieldNode) {
        self.children.push(c);
    }
}

/// Metadata handed to a decoder alongside the partition's bytes.
#[derive(Debug, Clone, Copy)]
pub struct PartitionMeta<'a> {
    pub partition_type: u32,
    pub uid: &'a [u8; 16],
    pub label: &'a str,
}

/// The result of decoding one partition.
#[derive(Debug, Clone)]
pub struct Decoded {
    /// Human name of the format that was decoded, e.g. `"PFS_NODE"`.
    pub format_name: String,
    pub fields: Vec<FieldNode>,
    /// Non-fatal spec violations and remarks surfaced to the user.
    pub warnings: Vec<String>,
}

/// A sub-partition surfaced by a *container* decoder (e.g. the inner partitions
/// of a DCP container) whose reconstructed logical content should itself be
/// decoded. Returned by [`PartitionDecoder::children`] and decoded recursively
/// by [`crate::decode_recursive`].
#[derive(Debug, Clone)]
pub struct DecodedChild {
    /// The sub-partition's application type.
    pub partition_type: u32,
    /// The sub-partition's 16-byte uid.
    pub uid: [u8; 16],
    /// The sub-partition's decoded label.
    pub label: String,
    /// The sub-partition's reconstructed logical content.
    pub data: Vec<u8>,
}

/// A plugin that turns partition bytes into a field tree.
pub trait PartitionDecoder {
    /// Stable identifier, used for `--decoder` selection and HTML anchors.
    fn name(&self) -> &'static str;

    /// Cheap test: does this decoder claim the partition? May inspect the type
    /// and/or sniff a magic prefix.
    fn matches(&self, meta: &PartitionMeta, data: &[u8]) -> bool;

    /// Full decode. Must never panic: on malformed input it returns whatever
    /// fields it could read plus `warnings`.
    fn decode(&self, meta: &PartitionMeta, data: &[u8]) -> Decoded;

    /// Sub-partitions contained within this partition whose reconstructed
    /// content should itself be decoded (e.g. the inner partitions of a DCP
    /// container). The default is none; only container-like decoders override
    /// it. Must never panic: on malformed input it returns an empty list.
    fn children(&self, _meta: &PartitionMeta, _data: &[u8]) -> Vec<DecodedChild> {
        Vec::new()
    }
}

/// An ordered set of decoders. The first decoder whose `matches` returns true
/// wins; [`RawDecoder`] is always last and matches everything.
pub struct DecoderRegistry {
    decoders: Vec<Box<dyn PartitionDecoder>>,
}

impl DecoderRegistry {
    /// The registry with all built-in decoders: PFS node, PFS session, then the
    /// raw fallback.
    pub fn with_builtins() -> Self {
        Self {
            decoders: vec![
                Box::new(PfsNodeDecoder),
                Box::new(PfsSessionDecoder),
                Box::new(PcfSigKeyDecoder),
                Box::new(PcfSigSignatureDecoder),
                Box::new(DcpContainerDecoder),
                Box::new(RawDecoder),
            ],
        }
    }

    /// Insert a decoder ahead of the raw fallback.
    pub fn register(&mut self, d: Box<dyn PartitionDecoder>) {
        let insert_at = self.decoders.len().saturating_sub(1);
        self.decoders.insert(insert_at, d);
    }

    /// All decoder names, in priority order.
    pub fn names(&self) -> Vec<&'static str> {
        self.decoders.iter().map(|d| d.name()).collect()
    }

    /// Decode `data`, picking the first matching decoder.
    pub fn decode(&self, meta: &PartitionMeta, data: &[u8]) -> Decoded {
        for d in &self.decoders {
            if d.matches(meta, data) {
                return d.decode(meta, data);
            }
        }
        // RawDecoder matches everything, so this is unreachable in practice.
        RawDecoder.decode(meta, data)
    }

    /// The sub-partitions of `data`, as reported by the first matching decoder
    /// (mirrors [`Self::decode`]). Empty for non-container partitions.
    pub fn children(&self, meta: &PartitionMeta, data: &[u8]) -> Vec<DecodedChild> {
        for d in &self.decoders {
            if d.matches(meta, data) {
                return d.children(meta, data);
            }
        }
        Vec::new()
    }

    /// Decode with a specific decoder by name, if present.
    pub fn decode_with(&self, name: &str, meta: &PartitionMeta, data: &[u8]) -> Option<Decoded> {
        self.decoders
            .iter()
            .find(|d| d.name() == name)
            .map(|d| d.decode(meta, data))
    }
}

impl Default for DecoderRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}

/// Read a little-endian `u16` at `off`, or `None` if out of bounds.
pub(crate) fn le_u16(data: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(off..off + 2)?.try_into().ok()?))
}

/// Read a little-endian `u32` at `off`, or `None` if out of bounds.
pub(crate) fn le_u32(data: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?))
}

/// Read a little-endian `u64` at `off`, or `None` if out of bounds.
pub(crate) fn le_u64(data: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(off..off + 8)?.try_into().ok()?))
}

/// Read a 16-byte UID at `off`.
pub(crate) fn uid_at(data: &[u8], off: usize) -> Option<[u8; 16]> {
    data.get(off..off + 16)?.try_into().ok()
}
