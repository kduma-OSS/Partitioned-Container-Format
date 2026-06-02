//! Targeted tests exercising error paths and algorithm variants that the
//! happy-path roundtrip suite does not touch. Together with `roundtrip.rs`
//! these aim for full line coverage of the crate.

use std::io::Cursor;

use pcf::{
    compute_table_hash, decode_label, encode_label, Container, Error, FileHeader, HashAlgo,
    PartitionEntry, TableBlockHeader, HASH_FIELD_SIZE, HEADER_SIZE, LABEL_SIZE, MAGIC, NIL_UID,
    TABLE_HEADER_SIZE, TYPE_RAW, TYPE_RESERVED, VERSION_MAJOR, VERSION_MINOR,
};

fn uid(n: u8) -> [u8; 16] {
    let mut u = [0u8; 16];
    u[0] = n;
    u[15] = 0xAA;
    u
}

// ---- header.rs -----------------------------------------------------------

#[test]
fn header_rejects_unsupported_major() {
    let mut bytes = FileHeader {
        version_major: 1,
        version_minor: 0,
        partition_table_offset: 20,
    }
    .to_bytes();
    // Bump the major to 2.
    bytes[8] = 0x02;
    match FileHeader::from_bytes(&bytes) {
        Err(Error::UnsupportedMajor(v)) => assert_eq!(v, 2),
        other => panic!("expected UnsupportedMajor, got {other:?}"),
    }
}

#[test]
fn header_minor_higher_than_implementation_is_accepted() {
    let mut bytes = FileHeader {
        version_major: 1,
        version_minor: 0,
        partition_table_offset: 20,
    }
    .to_bytes();
    bytes[10] = 0x05; // minor = 5
    let h = FileHeader::from_bytes(&bytes).expect("higher minor must parse");
    assert_eq!(h.version_minor, 5);
}

// ---- entry.rs ------------------------------------------------------------

#[test]
fn entry_validate_used_exceeds_max() {
    let e = PartitionEntry {
        partition_type: 1,
        uid: uid(1),
        label: encode_label("x").unwrap(),
        start_offset: 100,
        max_length: 10,
        used_bytes: 11,
        data_hash_algo: HashAlgo::None,
        data_hash: [0u8; HASH_FIELD_SIZE],
    };
    assert!(matches!(e.validate(), Err(Error::UsedExceedsMax)));
    // free_bytes saturates rather than underflowing.
    assert_eq!(e.free_bytes(), 0);
}

#[test]
fn encode_label_rejects_non_ascii_and_nul() {
    // Embedded NUL.
    assert!(matches!(encode_label("a\0b"), Err(Error::InvalidLabel)));
    // A multi-byte UTF-8 char's leading byte is >= 0x80, so it's rejected.
    assert!(matches!(encode_label("é"), Err(Error::InvalidLabel)));
}

#[test]
fn decode_label_rejects_high_bit_byte() {
    let mut l = [0u8; LABEL_SIZE];
    l[0] = b'a';
    l[1] = 0x80; // not 0 and >= 0x80
    assert!(matches!(decode_label(&l), Err(Error::InvalidLabel)));
}

// ---- hash.rs -------------------------------------------------------------

#[test]
fn hash_unknown_id_is_error() {
    assert!(matches!(
        HashAlgo::from_id(99),
        Err(Error::UnknownHashAlgo(99))
    ));
}

#[test]
fn hash_digest_len_matches_registry() {
    assert_eq!(HashAlgo::None.digest_len(), 0);
    assert_eq!(HashAlgo::Crc32.digest_len(), 4);
    assert_eq!(HashAlgo::Crc32c.digest_len(), 4);
    assert_eq!(HashAlgo::Crc64.digest_len(), 8);
    assert_eq!(HashAlgo::Md5.digest_len(), 16);
    assert_eq!(HashAlgo::Sha1.digest_len(), 20);
    assert_eq!(HashAlgo::Sha256.digest_len(), 32);
    assert_eq!(HashAlgo::Sha512.digest_len(), 64);
    assert_eq!(HashAlgo::Blake3.digest_len(), 32);
}

#[test]
fn md5_empty_string_matches_canonical_digest() {
    let f = HashAlgo::Md5.compute(b"");
    let expect = [
        0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42,
        0x7e,
    ];
    assert_eq!(&f[..16], &expect);
    assert!(f[16..].iter().all(|&b| b == 0));
    assert!(HashAlgo::Md5.verify(b"", &f));
}

#[test]
fn sha1_empty_string_matches_canonical_digest() {
    let f = HashAlgo::Sha1.compute(b"");
    let expect = [
        0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18,
        0x90, 0xaf, 0xd8, 0x07, 0x09,
    ];
    assert_eq!(&f[..20], &expect);
    assert!(f[20..].iter().all(|&b| b == 0));
    assert!(HashAlgo::Sha1.verify(b"", &f));
}

#[test]
fn sha512_empty_string_matches_canonical_digest() {
    let f = HashAlgo::Sha512.compute(b"");
    let expect: [u8; 64] = [
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80,
        0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c,
        0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87,
        0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a,
        0xf9, 0x27, 0xda, 0x3e,
    ];
    assert_eq!(&f[..64], &expect);
    assert!(HashAlgo::Sha512.verify(b"", &f));
}

#[test]
fn blake3_known_vector() {
    // BLAKE3 of the empty string (32-byte digest).
    let f = HashAlgo::Blake3.compute(b"");
    let expect = [
        0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9,
        0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f,
        0x32, 0x62,
    ];
    assert_eq!(&f[..32], &expect);
    assert!(f[32..].iter().all(|&b| b == 0));
    assert!(HashAlgo::Blake3.verify(b"", &f));
}

#[test]
fn hash_verify_rejects_wrong_data() {
    let stored = HashAlgo::Sha256.compute(b"correct");
    assert!(!HashAlgo::Sha256.verify(b"tampered", &stored));
}

// ---- error.rs ------------------------------------------------------------

#[test]
fn every_error_variant_has_a_display_form() {
    use std::error::Error as _;
    let io_err = std::io::Error::other("boom");
    let cases: Vec<Error> = vec![
        Error::Io(io_err),
        Error::BadMagic,
        Error::UnsupportedMajor(7),
        Error::UnknownHashAlgo(42),
        Error::ReservedType,
        Error::NilUid,
        Error::UsedExceedsMax,
        Error::InvalidLabel,
        Error::TableHashMismatch,
        Error::DataHashMismatch,
        Error::DataTooLarge,
        Error::NotFound,
        Error::DuplicateUid,
    ];
    for e in &cases {
        let s = format!("{e}");
        assert!(!s.is_empty(), "Display for {e:?} produced an empty string");
        // Also exercise Debug.
        let _ = format!("{e:?}");
    }
    // Io error has a source; the others do not.
    assert!(cases[0].source().is_some());
    for e in &cases[1..] {
        assert!(e.source().is_none(), "no source expected for {e:?}");
    }

    // From<std::io::Error> conversion path.
    let io = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
    let converted: Error = io.into();
    assert!(matches!(converted, Error::Io(_)));
}

// ---- container.rs --------------------------------------------------------

#[test]
fn header_and_into_storage_accessors() {
    let c = Container::create(Cursor::new(Vec::new())).unwrap();
    let h = c.header();
    assert_eq!(h.version_major, VERSION_MAJOR);
    assert_eq!(h.version_minor, VERSION_MINOR);
    assert_eq!(h.partition_table_offset, HEADER_SIZE);
    let _: Cursor<Vec<u8>> = c.into_storage();
}

#[test]
fn empty_partition_reads_back_as_empty() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(7, uid(1), "empty", b"", 0, HashAlgo::Sha256)
        .unwrap();
    let e = c.entries().unwrap();
    assert_eq!(c.read_partition_data(&e[0]).unwrap(), b"");
    c.verify().unwrap();

    // Updating to empty data must hit the `is_empty()` fast path.
    c.update_partition_data(&uid(1), b"").unwrap();
    c.verify().unwrap();
}

#[test]
fn update_not_found() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(1, uid(1), "x", b"x", 0, HashAlgo::Sha256)
        .unwrap();
    assert!(matches!(
        c.update_partition_data(&uid(99), b"y"),
        Err(Error::NotFound)
    ));
}

#[test]
fn open_rejects_bad_magic_and_unsupported_major() {
    let mut bad = vec![0u8; 20];
    assert!(matches!(
        Container::open(Cursor::new(bad.clone())),
        Err(Error::BadMagic)
    ));

    // Valid magic but bumped major.
    bad[..8].copy_from_slice(&MAGIC);
    bad[8] = 9;
    bad[9] = 0;
    assert!(matches!(
        Container::open(Cursor::new(bad)),
        Err(Error::UnsupportedMajor(9))
    ));
}

#[test]
fn table_hash_corruption_is_detected() {
    let mut bytes = {
        let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
        c.add_partition(1, uid(1), "p", b"payload", 0, HashAlgo::Sha256)
            .unwrap();
        c.into_storage().into_inner()
    };
    // Flip a byte inside the table_hash field (offset HEADER_SIZE + 10).
    let pos = (HEADER_SIZE + 10) as usize;
    bytes[pos] ^= 0xFF;

    let mut c = Container::open(Cursor::new(bytes)).unwrap();
    assert!(matches!(c.verify(), Err(Error::TableHashMismatch)));
}

#[test]
fn compaction_with_more_than_one_table_block() {
    // 260 partitions force two table blocks in the compacted image (capacity
    // per block is 255), exercising the `num_blocks > 1` arm of compaction
    // and the `next_table_offset` linkage between fresh blocks.
    let mut c = Container::create_with(Cursor::new(Vec::new()), 255, HashAlgo::Sha256).unwrap();
    for i in 0..260u32 {
        let mut u = [0u8; 16];
        u[0..4].copy_from_slice(&i.to_le_bytes());
        u[15] = 0x55;
        c.add_partition(i + 1, u, "p", &[i as u8], 0, HashAlgo::Crc32)
            .unwrap();
    }
    let image = c.compacted_image().unwrap();
    let mut c2 = Container::open(Cursor::new(image)).unwrap();
    c2.verify().unwrap();
    assert_eq!(c2.entries().unwrap().len(), 260);
}

#[test]
fn verify_with_none_algorithm_skips_hash_check() {
    // When table_hash_algo == None, the `verifies()` branch in `verify()` is
    // skipped — this covers the fall-through path of that conditional.
    let mut c = Container::create_with(Cursor::new(Vec::new()), 4, HashAlgo::None).unwrap();
    c.add_partition(1, uid(1), "p", b"abc", 0, HashAlgo::None)
        .unwrap();
    c.verify().unwrap();
}

#[test]
fn compact_empty_container_is_valid() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    let image = c.compacted_image().unwrap();

    let mut c2 = Container::open(Cursor::new(image)).unwrap();
    c2.verify().unwrap();
    assert!(c2.entries().unwrap().is_empty());
}

// ---- table.rs: also exercise the next_table_offset variation -------------

#[test]
fn compute_table_hash_changes_with_next_offset() {
    let entries: [PartitionEntry; 0] = [];
    let a = compute_table_hash(HashAlgo::Sha256, 0, &entries);
    let b = compute_table_hash(HashAlgo::Sha256, 4096, &entries);
    assert_ne!(a, b);
}

#[test]
fn table_block_header_with_none_hash() {
    let h = TableBlockHeader {
        partition_count: 0,
        next_table_offset: 0,
        table_hash_algo: HashAlgo::None,
        table_hash: [0u8; HASH_FIELD_SIZE],
    };
    let parsed = TableBlockHeader::from_bytes(&h.to_bytes()).unwrap();
    assert_eq!(parsed.table_hash_algo, HashAlgo::None);
}

// ---- parse-time propagation of an unknown algorithm id -----------------

#[test]
fn entry_from_bytes_propagates_unknown_algo_id() {
    let mut b = [0u8; 141];
    // valid type, uid, etc. — only the algo byte matters here.
    b[0..4].copy_from_slice(&1u32.to_le_bytes());
    b[4] = 0x01;
    b[76] = 99; // unknown
    let r = pcf::PartitionEntry::from_bytes(&b);
    assert!(matches!(r, Err(Error::UnknownHashAlgo(99))));
}

#[test]
fn table_header_from_bytes_propagates_unknown_algo_id() {
    let mut b = [0u8; 74];
    b[9] = 100;
    let r = pcf::TableBlockHeader::from_bytes(&b);
    assert!(matches!(r, Err(Error::UnknownHashAlgo(100))));
}

// ---- spec section 15: byte-exact test vector ----------------------------

#[test]
fn spec_section_15_test_vector_matches_byte_for_byte() {
    // Build the exact container described in the spec.
    let mut c = Container::create_with(Cursor::new(Vec::new()), 8, HashAlgo::Sha256).unwrap();
    c.add_partition(
        0x0000_0010,
        [0x11u8; 16],
        "alpha",
        b"Hello, PCF!",
        0,
        HashAlgo::Sha256,
    )
    .unwrap();
    c.add_partition(
        TYPE_RAW,
        [0x22u8; 16],
        "raw",
        &[0u8, 1, 2, 3, 4, 5, 6, 7],
        0,
        HashAlgo::Crc32c,
    )
    .unwrap();
    let image = c.compacted_image().unwrap();
    assert_eq!(image.len(), 395, "spec mandates a 395-byte canonical file");

    // The 395-byte expected image, transcribed from spec section 15.
    let mut expect = vec![0u8; 395];
    // Header (20 B).
    expect[..8].copy_from_slice(&MAGIC);
    expect[8..10].copy_from_slice(&1u16.to_le_bytes());
    expect[10..12].copy_from_slice(&0u16.to_le_bytes());
    expect[12..20].copy_from_slice(&20u64.to_le_bytes());
    // Table block header @ 0x14.
    expect[20] = 2; // partition_count
    expect[21..29].copy_from_slice(&0u64.to_le_bytes()); // next_table_offset
    expect[29] = 16; // SHA-256
    let table_hash_bytes = [
        0xF5, 0xEB, 0xFE, 0x8C, 0x26, 0xB1, 0x70, 0xF7, 0xC9, 0x7C, 0xF9, 0x2E, 0xD2, 0x4C, 0xF6,
        0x1E, 0x04, 0x2B, 0xBD, 0xFA, 0xC5, 0x09, 0x9B, 0xC7, 0x80, 0x1F, 0x0E, 0x81, 0x0F, 0xC3,
        0x27, 0xB6,
    ];
    expect[30..62].copy_from_slice(&table_hash_bytes);
    // Entry 0 @ 0x5E.
    let e0 = 0x5E;
    expect[e0..e0 + 4].copy_from_slice(&0x0000_0010u32.to_le_bytes());
    expect[e0 + 4..e0 + 20].copy_from_slice(&[0x11u8; 16]);
    expect[e0 + 20..e0 + 25].copy_from_slice(b"alpha");
    expect[e0 + 52..e0 + 60].copy_from_slice(&376u64.to_le_bytes());
    expect[e0 + 60..e0 + 68].copy_from_slice(&11u64.to_le_bytes());
    expect[e0 + 68..e0 + 76].copy_from_slice(&11u64.to_le_bytes());
    expect[e0 + 76] = 16; // SHA-256
    let data_hash_alpha = [
        0xDC, 0x02, 0xCF, 0x82, 0xCE, 0xC2, 0x34, 0x05, 0x61, 0x7A, 0xD4, 0xBF, 0x90, 0x1C, 0x09,
        0x75, 0xB6, 0x4A, 0x4B, 0xE5, 0x7C, 0x30, 0x3A, 0x8F, 0x5C, 0xF0, 0xA2, 0xC2, 0x51, 0xCB,
        0x90, 0xBC,
    ];
    expect[e0 + 77..e0 + 77 + 32].copy_from_slice(&data_hash_alpha);
    // Entry 1 @ 0xEB.
    let e1 = 0xEB;
    expect[e1..e1 + 4].copy_from_slice(&TYPE_RAW.to_le_bytes());
    expect[e1 + 4..e1 + 20].copy_from_slice(&[0x22u8; 16]);
    expect[e1 + 20..e1 + 23].copy_from_slice(b"raw");
    expect[e1 + 52..e1 + 60].copy_from_slice(&387u64.to_le_bytes());
    expect[e1 + 60..e1 + 68].copy_from_slice(&8u64.to_le_bytes());
    expect[e1 + 68..e1 + 76].copy_from_slice(&8u64.to_le_bytes());
    expect[e1 + 76] = 2; // CRC-32C
    expect[e1 + 77..e1 + 81].copy_from_slice(&0x8A2C_BC3Bu32.to_le_bytes());
    // Data region @ 0x178.
    expect[0x178..0x178 + 11].copy_from_slice(b"Hello, PCF!");
    expect[0x183..0x183 + 8].copy_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7]);

    assert_eq!(
        image, expect,
        "compacted image does not match spec section 15"
    );
}

// ---- guard against silent regressions in the consts module -------------

#[test]
fn consts_match_appendix_a() {
    assert_eq!(HEADER_SIZE, 20);
    assert_eq!(TABLE_HEADER_SIZE, 74);
    assert_eq!(HASH_FIELD_SIZE, 64);
    assert_eq!(LABEL_SIZE, 32);
    assert_eq!(TYPE_RESERVED, 0x0000_0000);
    assert_eq!(TYPE_RAW, 0xFFFF_FFFF);
    assert_eq!(NIL_UID, [0u8; 16]);
}
