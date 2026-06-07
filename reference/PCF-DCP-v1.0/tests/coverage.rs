//! Error paths and edge cases (spec Sections 8, 13).

use std::io::Cursor;

use pcf::HashAlgo;
use pcf_dcp::{
    build_reference_vector, Arena, Chunker, DcpReader, Error, FragTableHeader, FragmentEntry,
};

#[test]
fn bad_magic_is_rejected() {
    let mut bytes = build_reference_vector().unwrap();
    // Corrupt the arena magic (file offset 0x00EB).
    bytes[0xEB] = b'X';
    // The PCF layer is still valid; the DCP arena parse must fail.
    let mut c = pcf::Container::open(Cursor::new(bytes)).unwrap();
    let e = c.entries().unwrap().into_iter().next().unwrap();
    let data = c.read_partition_data(&e).unwrap();
    assert!(matches!(Arena::parse(&data), Err(Error::BadDcpMagic)));
}

#[test]
fn unsupported_profile_major_is_rejected() {
    let mut a = Arena::new();
    a.add_inner(0x10, [1; 16], "x", b"hi", HashAlgo::Sha256, Chunker::Whole)
        .unwrap();
    let mut bytes = a.to_bytes();
    bytes[4] = 2; // profile_version_major
    assert!(matches!(
        Arena::parse(&bytes),
        Err(Error::UnsupportedProfileMajor(2))
    ));
}

#[test]
fn reserved_and_nil_and_nested_are_rejected() {
    let mut a = Arena::new();
    assert!(matches!(
        a.add_inner(0, [1; 16], "x", b"", HashAlgo::None, Chunker::Whole),
        Err(Error::ReservedType)
    ));
    assert!(matches!(
        a.add_inner(
            0xAAAC_0001,
            [1; 16],
            "x",
            b"",
            HashAlgo::None,
            Chunker::Whole
        ),
        Err(Error::NestedContainer)
    ));
    assert!(matches!(
        a.add_inner(0x10, [0; 16], "x", b"", HashAlgo::None, Chunker::Whole),
        Err(Error::NilUid)
    ));
}

#[test]
fn duplicate_uid_within_arena_is_rejected() {
    let mut a = Arena::new();
    a.add_inner(0x10, [1; 16], "x", b"a", HashAlgo::None, Chunker::Whole)
        .unwrap();
    assert!(matches!(
        a.add_inner(0x10, [1; 16], "y", b"b", HashAlgo::None, Chunker::Whole),
        Err(Error::DuplicateUid)
    ));
}

#[test]
fn bad_fragment_kind_renders_partition_unreadable() {
    // Hand-build a fragment entry with a reserved kind and walk it.
    let fe = FragmentEntry {
        extent_offset: 24,
        extent_length: 1,
        kind: 2, // HOLE (reserved)
        flags: 0,
    };
    assert!(!fe.is_data());
    let frags = vec![fe];
    let arena = vec![0u8; 64];
    assert!(matches!(
        pcf_dcp::reconstruct(&arena, &frags, 64),
        Err(Error::BadFragmentKind(2))
    ));
}

#[test]
fn offset_out_of_range_is_rejected() {
    let fe = FragmentEntry {
        extent_offset: 60,
        extent_length: 100, // runs past arena_used
        kind: 1,
        flags: 0,
    };
    assert!(matches!(
        pcf_dcp::reconstruct(&[0u8; 64], &[fe], 64),
        Err(Error::OffsetOutOfRange)
    ));
}

#[test]
fn empty_inner_is_allowed() {
    let mut a = Arena::new();
    a.add_inner(
        0x10,
        [1; 16],
        "empty",
        b"",
        HashAlgo::Sha256,
        Chunker::Whole,
    )
    .unwrap();
    let info = a.inner_info(&[1; 16]).unwrap();
    assert_eq!(info.used_bytes, 0);
    assert_eq!(info.extents.len(), 0);
    assert_eq!(a.content(&[1; 16]).unwrap(), b"");
    // Round-trips through serialise/parse.
    let bytes = a.to_bytes();
    let parsed = Arena::parse(&bytes).unwrap();
    assert_eq!(parsed.content(&[1; 16]).unwrap(), b"");
}

#[test]
fn many_inners_chain_the_inner_table() {
    // More than 255 inner partitions force a multi-block inner table.
    let mut a = Arena::new();
    for i in 0..300u32 {
        let mut uid = [0u8; 16];
        uid[0..4].copy_from_slice(&i.to_le_bytes());
        uid[15] = 1; // keep non-NIL even when i == 0
        a.add_inner(
            0x10,
            uid,
            "n",
            &i.to_le_bytes(),
            HashAlgo::Sha256,
            Chunker::Whole,
        )
        .unwrap();
    }
    assert_eq!(a.len(), 300);
    let bytes = a.to_bytes();
    let parsed = Arena::parse(&bytes).unwrap();
    assert_eq!(parsed.len(), 300);
    // Spot-check a late partition.
    let mut uid = [0u8; 16];
    uid[0..4].copy_from_slice(&299u32.to_le_bytes());
    uid[15] = 1;
    assert_eq!(parsed.content(&uid).unwrap(), 299u32.to_le_bytes());

    // The whole thing is a valid PCF + DCP file.
    let mut w = pcf_dcp::DcpWriter::new();
    w.add_container([0xDC; 16], "big", a).unwrap();
    let image = w.to_image().unwrap();
    let mut r = DcpReader::open(Cursor::new(image)).unwrap();
    r.verify().unwrap();
}

#[test]
fn many_extents_chain_the_fragment_table() {
    // More than 255 extents in one partition force a multi-block fragment table.
    let mut a = Arena::new();
    let content = vec![0xAB; 300];
    a.add_inner(
        0x10,
        [1; 16],
        "frag",
        &content,
        HashAlgo::Sha256,
        Chunker::Fixed(1),
    )
    .unwrap();
    let info = a.inner_info(&[1; 16]).unwrap();
    // Fixed(1) with identical bytes deduplicates to a single shared extent, so
    // assert the *logical* length instead, then force distinct extents.
    assert_eq!(info.used_bytes, 300);

    let mut b = Arena::new();
    let distinct: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
    // 300 distinct-ish single-byte chunks; some repeat (values wrap mod 256),
    // but the fragment list still has 300 entries.
    b.add_inner(
        0x10,
        [2; 16],
        "frag2",
        &distinct,
        HashAlgo::Sha256,
        Chunker::Fixed(1),
    )
    .unwrap();
    let bytes = b.to_bytes();
    let parsed = Arena::parse(&bytes).unwrap();
    assert_eq!(parsed.content(&[2; 16]).unwrap(), distinct);
}

#[test]
fn fragtable_header_count_bounds() {
    let h = FragTableHeader {
        next_fragtable_offset: 7,
        fragment_count: 255,
    };
    assert_eq!(FragTableHeader::from_bytes(&h.to_bytes()), h);
}

#[test]
fn verify_detects_global_uid_collision() {
    // A top-level partition sharing a uid with an inner partition is a file-wide
    // collision (spec Section 2.1).
    let mut a = Arena::new();
    a.add_inner(
        0x10,
        [0xB2; 16],
        "B",
        b"World!",
        HashAlgo::Sha256,
        Chunker::Whole,
    )
    .unwrap();
    let mut w = pcf_dcp::DcpWriter::new();
    w.add_container([0xDC; 16], "dcp", a).unwrap();
    // Add a top-level plain partition with the SAME uid as the inner one.
    w.add_plain(0x10, [0xB2; 16], "dup", b"x".to_vec(), HashAlgo::Sha256)
        .unwrap();
    let image = w.to_image().unwrap();
    let mut r = DcpReader::open(Cursor::new(image)).unwrap();
    assert!(matches!(r.verify(), Err(Error::DuplicateUid)));
}
