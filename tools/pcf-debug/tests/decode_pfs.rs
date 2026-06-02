//! Tests for the PFS-MS decoders, both directly and through the full
//! walk → registry → decode pipeline.

mod common;

use pcf_debug::build_report;
use pcf_debug::plugin::{
    Decoded, DecoderRegistry, FieldNode, FieldValue, PartitionDecoder, PartitionMeta,
    PfsNodeDecoder, PfsSessionDecoder,
};

const PFS_NODE_TYPE: u32 = 0xAAAA_0001;
const PFS_SESSION_TYPE: u32 = 0xAAAA_0002;

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

#[test]
fn node_direct_fields_and_ranges() {
    let rec = common::pfs_node_direct("hello.txt");
    let uid = [0x01u8; 16];
    let meta = PartitionMeta {
        partition_type: PFS_NODE_TYPE,
        uid: &uid,
        label: "node",
    };
    let d: Decoded = PfsNodeDecoder.decode(&meta, &rec);

    assert_eq!(d.format_name, "PFS_NODE");
    assert!(
        d.warnings.is_empty(),
        "clean record has no warnings: {:?}",
        d.warnings
    );

    let magic = find(&d.fields, "record_magic").unwrap();
    assert_eq!(magic.value, FieldValue::Text("PFSN".into()));
    assert_eq!(magic.range, Some((0, 4)));

    let kind = find(&d.fields, "kind").unwrap();
    assert_eq!(
        kind.value,
        FieldValue::Enum {
            raw: 1,
            name: "file".into()
        }
    );

    let name = find(&d.fields, "name").unwrap();
    assert_eq!(name.value, FieldValue::Text("hello.txt".into()));
    assert_eq!(name.range, Some((54, 54 + 9)));

    let ck = find(&d.fields, "content_kind").unwrap();
    assert_eq!(
        ck.value,
        FieldValue::Enum {
            raw: 1,
            name: "DIRECT".into()
        }
    );

    let full_size = find(&d.fields, "full_size").unwrap();
    assert_eq!(full_size.value, FieldValue::U64(42));
}

#[test]
fn node_bad_magic_warns_without_panicking() {
    let mut rec = common::pfs_node_direct("x");
    rec[0] = b'X'; // corrupt the magic
    let uid = [0x01u8; 16];
    let meta = PartitionMeta {
        partition_type: PFS_NODE_TYPE,
        uid: &uid,
        label: "node",
    };
    let d = PfsNodeDecoder.decode(&meta, &rec);
    assert!(d.warnings.iter().any(|w| w.contains("PFSN")));
}

#[test]
fn session_fields_and_consistency() {
    let rec = common::pfs_session("test-writer");
    let uid = [0x02u8; 16];
    let meta = PartitionMeta {
        partition_type: PFS_SESSION_TYPE,
        uid: &uid,
        label: "sess",
    };
    let d = PfsSessionDecoder.decode(&meta, &rec);

    assert_eq!(d.format_name, "PFS_SESSION");
    assert!(
        d.warnings.is_empty(),
        "clean session has no warnings: {:?}",
        d.warnings
    );

    assert_eq!(
        find(&d.fields, "session_seq").unwrap().value,
        FieldValue::U64(1)
    );
    assert_eq!(
        find(&d.fields, "block_count").unwrap().value,
        FieldValue::U64(1)
    );
    assert_eq!(
        find(&d.fields, "writer").unwrap().value,
        FieldValue::Text("test-writer".into())
    );
}

#[test]
fn session_reserved_and_block_count_violations_warn() {
    let mut rec = common::pfs_session("w");
    rec[6] = 1; // reserved must be 0
    rec[89] = 0; // block_count must be >= 1
    rec[90] = 0;
    rec[91] = 0;
    rec[92] = 0;
    let uid = [0x02u8; 16];
    let meta = PartitionMeta {
        partition_type: PFS_SESSION_TYPE,
        uid: &uid,
        label: "sess",
    };
    let d = PfsSessionDecoder.decode(&meta, &rec);
    assert!(d.warnings.iter().any(|w| w.contains("reserved")));
    assert!(d.warnings.iter().any(|w| w.contains("block_count")));
}

#[test]
fn pipeline_selects_pfs_decoders_by_type() {
    let parts = vec![
        (
            PFS_NODE_TYPE,
            [0xA1u8; 16],
            "node",
            common::pfs_node_direct("a.txt"),
        ),
        (
            PFS_SESSION_TYPE,
            [0xA2u8; 16],
            "sess",
            common::pfs_session("w"),
        ),
    ];
    let data = common::wrap(&parts);
    let report = build_report(&data, true, &DecoderRegistry::with_builtins());

    let names: Vec<&str> = report
        .decoded
        .iter()
        .map(|(_, d)| d.format_name.as_str())
        .collect();
    assert!(names.contains(&"PFS_NODE"));
    assert!(names.contains(&"PFS_SESSION"));
}

#[test]
fn raw_fallback_used_for_unknown_type() {
    let parts = vec![(0x1234u32, [0xB1u8; 16], "blob", vec![1, 2, 3, 4])];
    let data = common::wrap(&parts);
    let report = build_report(&data, true, &DecoderRegistry::with_builtins());
    assert_eq!(report.decoded.len(), 1);
    assert_eq!(report.decoded[0].1.format_name, "RAW");
}
