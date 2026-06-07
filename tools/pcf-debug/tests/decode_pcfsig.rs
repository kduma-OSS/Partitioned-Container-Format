//! Tests for the PCF-SIG decoders, both directly (with synthesised bytes)
//! and through the full walk → registry → decode pipeline using the
//! canonical 966-byte test vector from `reference/PCF-SIG-v1.0/testdata/`.

use pcf_debug::build_report;
use pcf_debug::plugin::{
    Decoded, DecoderRegistry, FieldNode, FieldValue, PartitionDecoder, PartitionMeta,
    PcfSigKeyDecoder, PcfSigSignatureDecoder,
};

const CANONICAL: &[u8] = include_bytes!("../../../reference/PCF-SIG-v1.0/testdata/canonical.bin");

const PCFSIG_KEY_TYPE: u32 = 0xAAAB_0001;
const PCFSIG_SIG_TYPE: u32 = 0xAAAB_0002;

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
fn registry_routes_pcfsig_types_to_dedicated_decoders() {
    let r = DecoderRegistry::with_builtins();
    let mut names = r.names();
    names.sort();
    assert!(names.contains(&"pcfsig-key"));
    assert!(names.contains(&"pcfsig-sig"));
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
fn key_decoder_on_canonical_vector() {
    let report = build_report(CANONICAL, true, &DecoderRegistry::with_builtins());
    let key =
        find_decoded(&report, "PCFSIG_KEY").expect("canonical vector has a PCFSIG_KEY partition");

    assert!(
        key.warnings.is_empty(),
        "clean record has no warnings: {:?}",
        key.warnings
    );

    let magic = find(&key.fields, "record_magic").unwrap();
    assert_eq!(magic.value, FieldValue::Text("PCFKEY\\0\\0".into()));
    assert_eq!(magic.range, Some((0, 8)));

    let key_format = find(&key.fields, "key_format_id").unwrap();
    match &key_format.value {
        FieldValue::Enum { raw, name } => {
            assert_eq!(*raw, 1, "Ed25519 raw key");
            assert_eq!(name, "Ed25519 raw");
        }
        other => panic!("key_format_id has wrong shape: {:?}", other),
    }

    let key_data_length = find(&key.fields, "key_data_length").unwrap();
    assert_eq!(key_data_length.value, FieldValue::U64(32));

    let key_data = find(&key.fields, "key_data").unwrap();
    match &key_data.value {
        FieldValue::Bytes(b) => assert_eq!(b.len(), 32),
        other => panic!("key_data has wrong shape: {:?}", other),
    }
}

#[test]
fn signature_decoder_on_canonical_vector() {
    let report = build_report(CANONICAL, true, &DecoderRegistry::with_builtins());
    let sig =
        find_decoded(&report, "PCFSIG_SIG").expect("canonical vector has a PCFSIG_SIG partition");

    assert!(
        sig.warnings.is_empty(),
        "clean record has no warnings: {:?}",
        sig.warnings
    );

    let magic = find(&sig.fields, "manifest_magic").unwrap();
    assert_eq!(magic.value, FieldValue::Text("PCFSIG\\0\\0".into()));

    let sig_algo = find(&sig.fields, "sig_algo_id").unwrap();
    match &sig_algo.value {
        FieldValue::Enum { raw, name } => {
            assert_eq!(*raw, 1);
            assert_eq!(name, "Ed25519");
        }
        other => panic!("sig_algo_id has wrong shape: {:?}", other),
    }

    let manifest_hash = find(&sig.fields, "manifest_hash_algo_id").unwrap();
    match &manifest_hash.value {
        FieldValue::Enum { raw, name } => {
            assert_eq!(*raw, 17, "Ed25519 requires SHA-512 manifest hash");
            assert!(name.to_lowercase().contains("sha512"));
        }
        other => panic!("manifest_hash_algo_id has wrong shape: {:?}", other),
    }

    let signed_count = find(&sig.fields, "signed_count").unwrap();
    assert_eq!(signed_count.value, FieldValue::U64(1));

    let entry0 = find(&sig.fields, "entry[0]").unwrap();
    let uid_field = find(&entry0.children, "uid").unwrap();
    match &uid_field.value {
        FieldValue::Uid(u) => assert_eq!(u, &[0x11u8; 16]),
        other => panic!("entry[0].uid has wrong shape: {:?}", other),
    }
    let label_field = find(&entry0.children, "label").unwrap();
    assert_eq!(label_field.value, FieldValue::Text("alpha".into()));

    let sig_length = find(&sig.fields, "sig_length").unwrap();
    assert_eq!(
        sig_length.value,
        FieldValue::U64(64),
        "Ed25519 signature is 64 bytes"
    );

    let sig_bytes = find(&sig.fields, "sig_bytes").unwrap();
    match &sig_bytes.value {
        FieldValue::Bytes(b) => assert_eq!(b.len(), 64),
        other => panic!("sig_bytes has wrong shape: {:?}", other),
    }

    let trailer_length = find(&sig.fields, "trailer_length").unwrap();
    assert_eq!(
        trailer_length.value,
        FieldValue::U64(0),
        "v1.0 trailer must be 0"
    );
}

#[test]
fn key_decoder_warns_on_bad_magic() {
    let mut bytes = [0u8; 84];
    bytes[..8].copy_from_slice(b"XCFKEY\0\0");
    bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
    let uid = [0u8; 16];
    let meta = PartitionMeta {
        partition_type: PCFSIG_KEY_TYPE,
        uid: &uid,
        label: "key",
    };
    let d: Decoded = PcfSigKeyDecoder.decode(&meta, &bytes);
    assert!(d.warnings.iter().any(|w| w.contains("magic")));
}

#[test]
fn key_decoder_warns_on_fingerprint_mismatch() {
    // Build a syntactically-valid prefix with key_data = 0x42 * 32 but a
    // deliberately-wrong stored fingerprint.
    let mut bytes = vec![0u8; 84];
    bytes[..8].copy_from_slice(b"PCFKEY\0\0");
    bytes[8..10].copy_from_slice(&1u16.to_le_bytes()); // major
    bytes[12] = 1; // Ed25519 raw
    bytes[16..48].copy_from_slice(&[0xFFu8; 32]); // wrong fingerprint
    bytes[48..52].copy_from_slice(&32u32.to_le_bytes());
    for b in &mut bytes[52..84] {
        *b = 0x42;
    }
    let uid = [0u8; 16];
    let meta = PartitionMeta {
        partition_type: PCFSIG_KEY_TYPE,
        uid: &uid,
        label: "key",
    };
    let d = PcfSigKeyDecoder.decode(&meta, &bytes);
    assert!(d.warnings.iter().any(|w| w.contains("fingerprint")));
}

#[test]
fn signature_decoder_warns_on_non_crypto_manifest_hash() {
    // Build a one-entry manifest with manifest_hash_algo_id = 1 (CRC-32), which
    // is not cryptographic.
    let mut bytes = vec![0u8; 60 + 218 + 4 + 64 + 4];
    bytes[..8].copy_from_slice(b"PCFSIG\0\0");
    bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
    bytes[12] = 1; // sig_algo_id = Ed25519
    bytes[13] = 1; // manifest_hash_algo_id = CRC-32 (non-crypto)
    bytes[56..60].copy_from_slice(&1u32.to_le_bytes()); // signed_count = 1
                                                        // One blank SignedEntry; uid is non-NIL, type non-zero, hash crypto so only
                                                        // the manifest-hash warning fires.
    let entry_off = 60;
    bytes[entry_off] = 1; // uid[0]
    bytes[entry_off + 16..entry_off + 20].copy_from_slice(&0x10u32.to_le_bytes());
    bytes[entry_off + 60] = 16; // data_hash_algo_id = SHA-256
                                // sig tail: sig_length=64, then 64 zero bytes, then trailer_length=0
    let sig_len_off = entry_off + 218;
    bytes[sig_len_off..sig_len_off + 4].copy_from_slice(&64u32.to_le_bytes());

    let uid = [0u8; 16];
    let meta = PartitionMeta {
        partition_type: PCFSIG_SIG_TYPE,
        uid: &uid,
        label: "sig",
    };
    let d = PcfSigSignatureDecoder.decode(&meta, &bytes);
    assert!(
        d.warnings
            .iter()
            .any(|w| w.contains("manifest_hash_algo_id")),
        "warnings = {:?}",
        d.warnings
    );
}

#[test]
fn signature_decoder_warns_on_nonzero_trailer_length() {
    // Same skeleton as above but with trailer_length = 1.
    let mut bytes = vec![0u8; 60 + 218 + 4 + 64 + 4 + 1];
    bytes[..8].copy_from_slice(b"PCFSIG\0\0");
    bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
    bytes[12] = 1; // Ed25519
    bytes[13] = 17; // SHA-512
    bytes[56..60].copy_from_slice(&1u32.to_le_bytes());
    let entry_off = 60;
    bytes[entry_off] = 1;
    bytes[entry_off + 16..entry_off + 20].copy_from_slice(&0x10u32.to_le_bytes());
    bytes[entry_off + 60] = 16;
    let sig_len_off = entry_off + 218;
    bytes[sig_len_off..sig_len_off + 4].copy_from_slice(&64u32.to_le_bytes());
    let trailer_off = sig_len_off + 4 + 64;
    bytes[trailer_off..trailer_off + 4].copy_from_slice(&1u32.to_le_bytes());

    let uid = [0u8; 16];
    let meta = PartitionMeta {
        partition_type: PCFSIG_SIG_TYPE,
        uid: &uid,
        label: "sig",
    };
    let d = PcfSigSignatureDecoder.decode(&meta, &bytes);
    assert!(
        d.warnings.iter().any(|w| w.contains("trailer_length")),
        "warnings = {:?}",
        d.warnings
    );
}
