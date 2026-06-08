//! `pcf-debug` — a read-only inspector and visualiser for Partitioned Container
//! Format (PCF) files.
//!
//! The crate is organised as a pipeline:
//!
//! 1. [`model::walk`] reads the file's physical structure defensively.
//! 2. [`model::build`] turns that into a [`model::LayoutMap`] with gaps and
//!    overlaps materialised.
//! 3. [`plugin`] decoders turn each partition's bytes into a field tree.
//! 4. [`render`] turns the shared [`render::Report`] into text, hexdumps, or
//!    HTML.
//!
//! The orchestration helper [`build_report`] runs steps 1–3; the binary in
//! `main.rs` adds argument parsing and chooses a renderer.

pub mod cli;
pub mod model;
pub mod plugin;
pub mod render;

use plugin::{Decoded, DecodedChild, DecoderRegistry, FieldNode, FieldValue, PartitionMeta};
use render::Report;

/// Maximum container nesting depth followed by [`decode_recursive`]. DCP forbids
/// nesting, so the real depth is at most 2; this is a guard against pathological
/// or hostile inputs.
pub const MAX_DECODE_DEPTH: usize = 8;

/// Read a partition's used bytes from the file image, or an empty slice when the
/// region is out of bounds or empty.
fn partition_bytes(data: &[u8], entry: &pcf::PartitionEntry, in_bounds: bool) -> Vec<u8> {
    if in_bounds && entry.used_bytes > 0 {
        let start = entry.start_offset as usize;
        let end = (entry.start_offset + entry.used_bytes) as usize;
        data[start..end].to_vec()
    } else {
        Vec::new()
    }
}

/// Build the full report (physical layout + decoded partitions) from raw bytes.
pub fn build_report(data: &[u8], verify: bool, registry: &DecoderRegistry) -> Report {
    let walk = model::walk(data, verify);
    let layout = model::build(&walk);

    let mut decoded = Vec::new();
    for b in &layout.blocks {
        for ev in &b.entries {
            let e = &ev.entry;
            let bytes = partition_bytes(data, e, ev.data_in_bounds);
            let label = e.label_string().unwrap_or_default();
            let meta = PartitionMeta {
                partition_type: e.partition_type,
                uid: &e.uid,
                label: &label,
            };
            decoded.push((e.uid, decode_recursive(registry, &meta, &bytes)));
        }
    }
    Report { layout, decoded }
}

/// Decode `data`, then recursively decode and nest any sub-partitions a
/// container decoder surfaces (e.g. the inner partitions of a DCP container).
/// The nested decodes appear as a `"decoded inner partitions"` group at the end
/// of the field tree.
pub fn decode_recursive(registry: &DecoderRegistry, meta: &PartitionMeta, data: &[u8]) -> Decoded {
    let mut dec = registry.decode(meta, data);
    attach_inner_decodes(registry, meta, data, &mut dec);
    dec
}

/// Append a `"decoded inner partitions"` group to `dec` for every sub-partition
/// the matching container decoder reports, decoding each recursively. A no-op
/// for non-container partitions. Useful when `dec` was produced by a forced
/// decoder (`--decoder`) and should still gain its nested children.
pub fn attach_inner_decodes(
    registry: &DecoderRegistry,
    meta: &PartitionMeta,
    data: &[u8],
    dec: &mut Decoded,
) {
    attach_at_depth(registry, meta, data, dec, 0);
}

fn attach_at_depth(
    registry: &DecoderRegistry,
    meta: &PartitionMeta,
    data: &[u8],
    dec: &mut Decoded,
    depth: usize,
) {
    if depth >= MAX_DECODE_DEPTH {
        return;
    }
    let kids = registry.children(meta, data);
    if kids.is_empty() {
        return;
    }
    let mut group = FieldNode::group("decoded inner partitions");
    for ch in kids {
        let cmeta = PartitionMeta {
            partition_type: ch.partition_type,
            uid: &ch.uid,
            label: &ch.label,
        };
        let mut cdec = registry.decode(&cmeta, &ch.data);
        attach_at_depth(registry, &cmeta, &ch.data, &mut cdec, depth + 1);
        group.push(child_to_field(&ch, cdec));
    }
    dec.fields.push(group);
}

/// Wrap one child's decoded field tree as a single named group, carrying its
/// uid/type as a note and preserving any decoder warnings as a sub-group.
fn child_to_field(child: &DecodedChild, dec: Decoded) -> FieldNode {
    let mut node = FieldNode::group(format!("content[{}] -> {}", child.label, dec.format_name))
        .with_note(format!(
            "uid {}  type 0x{:08X}",
            render::uid_hex(&child.uid),
            child.partition_type
        ));
    for f in dec.fields {
        node.push(f);
    }
    if !dec.warnings.is_empty() {
        let mut warns = FieldNode::group("warnings");
        for msg in dec.warnings {
            warns.push(FieldNode::leaf("warning", FieldValue::Text(msg), (0, 0)));
        }
        node.push(warns);
    }
    node
}
