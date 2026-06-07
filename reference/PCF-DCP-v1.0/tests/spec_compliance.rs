//! Conformance tests tying the implementation to specific sections of
//! `specs/PCF-DCP-spec-v1.0.txt`, culminating in the byte-exact Section 17
//! test vector.

use std::io::Cursor;

use pcf::{Container, HashAlgo};
use pcf_dcp::{
    build_reference_vector, Arena, Chunker, DcpHeader, DcpReader, FragTableHeader, FragmentEntry,
    DCP_CONTAINER_TYPE, DCP_HEADER_SIZE, FRAGMENT_ENTRY_SIZE, FRAGTABLE_HEADER_SIZE,
};

/// The canonical 700-byte file, byte-for-byte equal to the spec's Section 17
/// hex dump (verified during development).
const CANONICAL: &[u8] = include_bytes!("../testdata/canonical.bin");

#[test]
fn structure_sizes_match_appendix_a() {
    assert_eq!(DCP_HEADER_SIZE, 24);
    assert_eq!(FRAGTABLE_HEADER_SIZE, 9);
    assert_eq!(FRAGMENT_ENTRY_SIZE, 18);
    assert_eq!(DCP_CONTAINER_TYPE, 0xAAAC_0001);
}

#[test]
fn header_roundtrip_and_magic() {
    let h = DcpHeader {
        profile_version_major: 1,
        profile_version_minor: 0,
        flags: 0,
        inner_table_offset: 109,
        arena_used: 465,
    };
    let b = h.to_bytes();
    assert_eq!(&b[0..4], b"PDCP");
    assert_eq!(DcpHeader::from_bytes(&b).unwrap(), h);
}

#[test]
fn fragment_records_roundtrip() {
    let e = FragmentEntry {
        extent_offset: 31,
        extent_length: 6,
        kind: 1,
        flags: 1,
    };
    assert_eq!(FragmentEntry::from_bytes(&e.to_bytes()), e);
    let h = FragTableHeader {
        next_fragtable_offset: 0,
        fragment_count: 2,
    };
    assert_eq!(FragTableHeader::from_bytes(&h.to_bytes()), h);
}

#[test]
fn reconstruction_equals_logical_content() {
    let mut arena = Arena::new();
    arena
        .add_inner(
            0x10,
            [1; 16],
            "x",
            b"Hello, World!",
            HashAlgo::Sha256,
            Chunker::Fixed(7),
        )
        .unwrap();
    assert_eq!(arena.content(&[1; 16]).unwrap(), b"Hello, World!");
    // Two extents, total used_bytes 13.
    let info = arena.inner_info(&[1; 16]).unwrap();
    assert_eq!(info.used_bytes, 13);
    assert_eq!(info.extents.len(), 2);
}

#[test]
fn data_hash_is_invariant_under_fragmentation() {
    // The same content chunked differently yields the same data_hash (it covers
    // logical content only — spec Section 8.3 / 9.1).
    let mk = |c: Chunker| {
        let mut a = Arena::new();
        a.add_inner(0x10, [7; 16], "x", b"abcdefghij", HashAlgo::Sha256, c)
            .unwrap();
        a.inner_info(&[7; 16]).unwrap().data_hash
    };
    assert_eq!(mk(Chunker::Whole), mk(Chunker::Fixed(3)));
    assert_eq!(mk(Chunker::Whole), HashAlgo::Sha256.compute(b"abcdefghij"));
}

#[test]
fn dedup_sets_shared_on_all_aliases_rule_f1() {
    let mut arena = Arena::new();
    arena
        .add_inner(
            0x10,
            [0xA1; 16],
            "A",
            b"Hello, World!",
            HashAlgo::Sha256,
            Chunker::Fixed(7),
        )
        .unwrap();
    arena
        .add_inner(
            0x10,
            [0xB2; 16],
            "B",
            b"World!",
            HashAlgo::Sha256,
            Chunker::Whole,
        )
        .unwrap();

    let a = arena.inner_info(&[0xA1; 16]).unwrap();
    let b = arena.inner_info(&[0xB2; 16]).unwrap();
    // A: "Hello, " private, "World!" shared.
    assert!(!a.extents[0].shared);
    assert!(a.extents[1].shared);
    // B: single extent, shared, deduplicated onto A's second extent.
    assert_eq!(b.extents.len(), 1);
    assert!(b.extents[0].shared);
    // B's data_hash equals a standalone SHA-256("World!") — promotion invariant.
    assert_eq!(b.data_hash, HashAlgo::Sha256.compute(b"World!"));
}

#[test]
fn canonical_vector_is_byte_exact_700() {
    let image = build_reference_vector().unwrap();
    assert_eq!(image.len(), 700, "spec Section 17 total file size");
    assert_eq!(
        image, CANONICAL,
        "must reproduce the Section 17 bytes exactly"
    );
}

#[test]
fn canonical_vector_key_offsets() {
    let image = build_reference_vector().unwrap();
    // Top-level: file header partition_table_offset = 20, one entry of type DCP.
    assert_eq!(&image[0..8], &pcf::MAGIC);
    // Arena begins at file offset 0x00EB (235).
    assert_eq!(&image[0xEB..0xEF], b"PDCP");
    assert_eq!(image[0xEF], 1); // profile_version_major
    assert_eq!(image[0xF0], 0); // profile_version_minor (the spec dump's 01 was a typo)
                                // inner_table_offset = 109 (arena-rel), arena_used = 465.
    assert_eq!(
        u64::from_le_bytes(image[0xF3..0xFB].try_into().unwrap()),
        109
    );
    assert_eq!(
        u64::from_le_bytes(image[0xFB..0x103].try_into().unwrap()),
        465
    );
    // Shared flags: A[1] at 0x013C and B[0] at 0x0157 are 1; A[0] at 0x012A is 0.
    assert_eq!(image[0x012A], 0);
    assert_eq!(image[0x013C], 1);
    assert_eq!(image[0x0157], 1);
}

#[test]
fn canonical_vector_is_valid_pcf() {
    // A generic PCF reader sees one valid partition and the table hash verifies.
    let image = build_reference_vector().unwrap();
    let mut c = Container::open(Cursor::new(image)).unwrap();
    c.verify().unwrap();
    let entries = c.entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].partition_type, DCP_CONTAINER_TYPE);
    assert_eq!(entries[0].used_bytes, 465);
    assert_eq!(entries[0].data_hash_algo, HashAlgo::None);
}

#[test]
fn canonical_vector_is_valid_dcp() {
    let image = build_reference_vector().unwrap();
    let mut r = DcpReader::open(Cursor::new(image)).unwrap();
    r.verify().unwrap();
    assert_eq!(r.read_inner(&[0xA1; 16]).unwrap(), b"Hello, World!");
    assert_eq!(r.read_inner(&[0xB2; 16]).unwrap(), b"World!");
}

#[test]
fn parse_roundtrips_canonical_arena_byte_exact() {
    // Parsing the canonical arena and re-serialising reproduces it exactly,
    // because the test vector is already in canonical layout.
    let mut c = Container::open(Cursor::new(CANONICAL.to_vec())).unwrap();
    let entry = c.entries().unwrap().into_iter().next().unwrap();
    let data = c.read_partition_data(&entry).unwrap();
    let arena = Arena::parse(&data).unwrap();
    assert_eq!(arena.to_bytes(), data);
}
