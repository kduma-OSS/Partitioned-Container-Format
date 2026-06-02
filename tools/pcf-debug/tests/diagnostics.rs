//! Tests that the model surfaces structural anomalies as diagnostics instead of
//! panicking. Files are hand-built from the crate's public serialisers so the
//! anomalies are exact.

mod common;

use pcf::{encode_label, FileHeader, HashAlgo, PartitionEntry, TableBlockHeader};
use pcf_debug::build_report;
use pcf_debug::model::diag::DiagKind;
use pcf_debug::plugin::DecoderRegistry;

fn entry(uid: u8, start: u64, used: u64, max: u64) -> PartitionEntry {
    PartitionEntry {
        partition_type: 1,
        uid: [uid; 16],
        label: encode_label("p").unwrap(),
        start_offset: start,
        max_length: max,
        used_bytes: used,
        data_hash_algo: HashAlgo::None,
        data_hash: [0u8; 64],
    }
}

/// Build a file by hand: a 20-byte header, one `None`-hashed block at offset 20,
/// then `entries`, then `data_len` bytes of payload.
fn handmade(entries: &[PartitionEntry], data_len: usize) -> Vec<u8> {
    let header = FileHeader {
        version_major: 1,
        version_minor: 0,
        partition_table_offset: 20,
    };
    let block = TableBlockHeader {
        partition_count: entries.len() as u8,
        next_table_offset: 0,
        table_hash_algo: HashAlgo::None,
        table_hash: [0u8; 64],
    };
    let mut img = Vec::new();
    img.extend_from_slice(&header.to_bytes());
    img.extend_from_slice(&block.to_bytes());
    for e in entries {
        img.extend_from_slice(&e.to_bytes());
    }
    img.resize(img.len() + data_len, 0);
    img
}

#[test]
fn trailing_dead_space_is_reported_as_a_gap() {
    let mut data = common::canonical();
    data.extend_from_slice(&[0u8; 32]); // 32 bytes of trailing padding
    let report = build_report(&data, true, &DecoderRegistry::with_builtins());
    let gap = report
        .layout
        .diagnostics
        .iter()
        .find(|d| matches!(d.kind, DiagKind::Gap { .. }));
    assert!(gap.is_some(), "trailing padding should be a gap diagnostic");
}

#[test]
fn overlapping_data_regions_are_detected() {
    // Two entries' data regions intersect: [data..+10) and [data+4..+14).
    let data_base = 20 + 74 + 2 * 141; // header + block header + two entries
    let entries = [
        entry(1, data_base as u64, 10, 10),
        entry(2, data_base as u64 + 4, 10, 10),
    ];
    let img = handmade(&entries, 14);
    let report = build_report(&img, true, &DecoderRegistry::with_builtins());
    let overlap = report
        .layout
        .diagnostics
        .iter()
        .find(|d| matches!(d.kind, DiagKind::Overlap { .. }));
    assert!(
        overlap.is_some(),
        "intersecting data regions should be flagged"
    );
}

#[test]
fn data_past_eof_is_truncated_not_a_panic() {
    let data_base = 20 + 74 + 141;
    // used_bytes claims 100 bytes but only 5 exist after the entry.
    let entries = [entry(1, data_base as u64, 100, 100)];
    let img = handmade(&entries, 5);
    let report = build_report(&img, true, &DecoderRegistry::with_builtins());
    let trunc = report
        .layout
        .diagnostics
        .iter()
        .find(|d| matches!(d.kind, DiagKind::Truncated { .. }));
    assert!(
        trunc.is_some(),
        "out-of-bounds data must be a Truncated diagnostic"
    );
}

#[test]
fn short_file_does_not_panic() {
    let report = build_report(&[0u8; 4], true, &DecoderRegistry::with_builtins());
    assert!(report
        .layout
        .diagnostics
        .iter()
        .any(|d| matches!(d.kind, DiagKind::BadHeader { .. })));
}
