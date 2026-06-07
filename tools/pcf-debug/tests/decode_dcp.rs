//! Tests for the PCF-DCP container decoder, both directly (with synthesised
//! bytes) and through the full walk → registry → decode pipeline using the
//! canonical 700-byte test vector from `reference/PCF-DCP-v1.0/testdata/`.

use pcf_debug::build_report;
use pcf_debug::plugin::{
    DcpContainerDecoder, Decoded, DecoderRegistry, FieldNode, FieldValue, PartitionDecoder,
    PartitionMeta,
};

const CANONICAL: &[u8] = include_bytes!("../../../reference/PCF-DCP-v1.0/testdata/canonical.bin");

const DCP_CONTAINER_TYPE: u32 = 0xAAAC_0001;

/// Find a (possibly nested) field by name.
fn find<'a>(fields: &'a [FieldNode], name: &str) -> Option<&'a FieldNode> {
    for f in fields {
        if f.name == name {
            return Some(f);
        }
        if let Some(hit) = find(&f.children, name) {
            return Some(hit);
        }
    }
    None
}

fn find_decoded<'a>(
    report: &'a pcf_debug::render::Report,
    format_name: &str,
) -> Option<&'a Decoded> {
    report
        .decoded
        .iter()
        .find(|(_, d)| d.format_name == format_name)
        .map(|(_, d)| d)
}

#[test]
fn registry_routes_dcp_type_to_dedicated_decoder() {
    let r = DecoderRegistry::with_builtins();
    assert!(r.names().contains(&"dcp-container"));
}

#[test]
fn dcp_decoder_on_canonical_vector() {
    let report = build_report(CANONICAL, true, &DecoderRegistry::with_builtins());
    let dcp = find_decoded(&report, "DCP_CONTAINER").expect("canonical vector has a DCP_CONTAINER");

    assert!(
        dcp.warnings.is_empty(),
        "clean container has no warnings: {:?}",
        dcp.warnings
    );

    // DCP Header.
    let magic = find(&dcp.fields, "dcp_magic").unwrap();
    assert_eq!(magic.value, FieldValue::Text("PDCP".into()));
    assert_eq!(magic.note.as_deref(), Some("magic OK"));

    let ito = find(&dcp.fields, "inner_table_offset").unwrap();
    assert_eq!(ito.value, FieldValue::U64(109));
    let used = find(&dcp.fields, "arena_used").unwrap();
    assert_eq!(used.value, FieldValue::U64(465));

    // Inner partition A: two extents, reinterpreted start_offset.
    let inner_a = find(&dcp.fields, "inner[A]").unwrap();
    let start = find(&inner_a.children, "start_offset").unwrap();
    assert_eq!(start.value, FieldValue::U64(37));
    assert_eq!(
        start.note.as_deref(),
        Some("reinterpreted -> Fragment Table")
    );

    // Summary: 2 inner partitions, 3 extent references, 2 of them shared.
    let inner_count = find(&dcp.fields, "inner_partitions").unwrap();
    assert_eq!(inner_count.value, FieldValue::U64(2));
    let extents = find(&dcp.fields, "extents").unwrap();
    assert_eq!(extents.value, FieldValue::U64(3));
    let shared = find(&dcp.fields, "shared_extents").unwrap();
    assert_eq!(shared.value, FieldValue::U64(2));
}

#[test]
fn dcp_decoder_flags_shared_extent() {
    let report = build_report(CANONICAL, true, &DecoderRegistry::with_builtins());
    let dcp = find_decoded(&report, "DCP_CONTAINER").unwrap();
    // Fragment B's only extent is SHARED.
    let frags_b = find(&dcp.fields, "frags[B] @ 82").unwrap();
    let flags = find(&frags_b.children, "flags").unwrap();
    match &flags.value {
        FieldValue::Flags { raw, set } => {
            assert_eq!(*raw, 1);
            assert_eq!(set, &vec!["SHARED".to_string()]);
        }
        other => panic!("flags has wrong shape: {other:?}"),
    }
}

#[test]
fn dcp_decoder_warns_on_bad_magic() {
    let mut bytes = vec![0u8; 24];
    bytes[..4].copy_from_slice(b"XDCP");
    let uid = [0u8; 16];
    let meta = PartitionMeta {
        partition_type: DCP_CONTAINER_TYPE,
        uid: &uid,
        label: "dcp",
    };
    let d: Decoded = DcpContainerDecoder.decode(&meta, &bytes);
    assert!(d.warnings.iter().any(|w| w.contains("magic")));
}

#[test]
fn dcp_decoder_matches_by_magic_without_type() {
    let mut bytes = vec![0u8; 24];
    bytes[..4].copy_from_slice(b"PDCP");
    let uid = [0u8; 16];
    let meta = PartitionMeta {
        partition_type: 0xFFFF_FFFF,
        uid: &uid,
        label: "raw",
    };
    assert!(DcpContainerDecoder.matches(&meta, &bytes));
}
