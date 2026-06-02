//! Rendering: turn the shared [`Report`] into text, hexdumps, or HTML. Both the
//! text and HTML renderers consume the same model so they never diverge.

pub mod color;
pub mod hexdump;
pub mod html;
pub mod text;

use crate::model::LayoutMap;
use crate::plugin::Decoded;

/// The shared input to every renderer: the physical layout plus the per-
/// partition decoded field trees (paired with the partition UID).
pub struct Report {
    pub layout: LayoutMap,
    pub decoded: Vec<([u8; 16], Decoded)>,
}

/// Format a 16-byte UID as lowercase hex.
pub fn uid_hex(uid: &[u8; 16]) -> String {
    uid.iter().map(|b| format!("{b:02x}")).collect()
}

/// Format a label, falling back to a placeholder for unreadable labels.
pub fn label_or(entry: &pcf::PartitionEntry) -> String {
    entry.label_string().unwrap_or_else(|_| "<invalid>".into())
}
