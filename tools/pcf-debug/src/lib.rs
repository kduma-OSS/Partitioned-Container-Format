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

use plugin::{DecoderRegistry, PartitionMeta};
use render::Report;

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
            decoded.push((e.uid, registry.decode(&meta, &bytes)));
        }
    }
    Report { layout, decoded }
}
