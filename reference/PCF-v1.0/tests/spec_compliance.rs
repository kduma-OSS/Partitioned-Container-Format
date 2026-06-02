//! Spec-conformance tests — every assertion in this file traces back to a
//! specific MUST/SHALL clause of `PCF-spec-v1.0.txt`. The file is organised by
//! spec section so reviewers can pair each test with its normative source.

use std::io::Cursor;

use pcf::{
    compute_table_hash, decode_label, encode_label, Container, Error, FileHeader, HashAlgo,
    PartitionEntry, TableBlockHeader, ENTRY_SIZE, HASH_FIELD_SIZE, HEADER_SIZE, LABEL_SIZE, MAGIC,
    NIL_UID, TABLE_HEADER_SIZE, TYPE_RAW, TYPE_RESERVED, UID_SIZE, VERSION_MAJOR, VERSION_MINOR,
};

fn uid(n: u8) -> [u8; 16] {
    let mut u = [0u8; 16];
    u[0] = n;
    u[15] = 0xAA;
    u
}

// =========================================================================
// Section 2.3 — Data Types and Byte Order
// =========================================================================

/// "All multi-byte integers are unsigned and are encoded in LITTLE-ENDIAN."
#[test]
fn s2_3_integers_are_little_endian() {
    let h = FileHeader {
        version_major: 0x0201,
        version_minor: 0x0403,
        partition_table_offset: 0x0807_0605_0403_0201,
    }
    .to_bytes();
    assert_eq!(&h[8..10], &[0x01, 0x02]);
    assert_eq!(&h[10..12], &[0x03, 0x04]);
    assert_eq!(
        &h[12..20],
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    );
}

// =========================================================================
// Section 4 — File Header (20 bytes)
// =========================================================================

/// "The file MUST begin with the following 20-byte header."
#[test]
fn s4_header_is_exactly_20_bytes() {
    assert_eq!(HEADER_SIZE, 20);
    let h = FileHeader {
        version_major: 1,
        version_minor: 0,
        partition_table_offset: 20,
    };
    assert_eq!(h.to_bytes().len(), 20);
}

/// "magic MUST be exactly the following 8 bytes: 0x89 'K' 'P' 'R' 'T' 0x0D 0x0A 0x1A."
#[test]
fn s4_magic_bytes_match_specification() {
    assert_eq!(MAGIC, [0x89, 0x4B, 0x50, 0x52, 0x54, 0x0D, 0x0A, 0x1A]);
}

/// "A Reader MUST reject any file whose first 8 bytes do not match exactly."
#[test]
fn s4_reader_rejects_bad_magic() {
    let mut bytes = vec![0u8; 20];
    bytes[..8].copy_from_slice(b"NOTAPCF!");
    assert!(matches!(
        Container::open(Cursor::new(bytes)),
        Err(Error::BadMagic)
    ));
}

/// "A Reader MUST reject a file whose version_major it does not implement."
#[test]
fn s4_reader_rejects_unsupported_major() {
    let h = FileHeader {
        version_major: 2,
        version_minor: 0,
        partition_table_offset: 20,
    };
    let mut bytes = h.to_bytes().to_vec();
    bytes.resize(20, 0);
    assert!(matches!(
        Container::open(Cursor::new(bytes)),
        Err(Error::UnsupportedMajor(2))
    ));
}

// =========================================================================
// Section 5.1 — Table Block Header (74 bytes)
// =========================================================================

/// "Each Table Block begins with the following 74-byte header."
#[test]
fn s5_1_block_header_is_74_bytes() {
    assert_eq!(TABLE_HEADER_SIZE, 74);
    let h = TableBlockHeader {
        partition_count: 0,
        next_table_offset: 0,
        table_hash_algo: HashAlgo::Sha256,
        table_hash: [0u8; HASH_FIELD_SIZE],
    };
    assert_eq!(h.to_bytes().len(), 74);
}

/// "partition_count: Number of Partition Entries stored in THIS block, in
///  the range 0..255."
#[test]
fn s5_1_partition_count_is_a_u8() {
    let h = TableBlockHeader {
        partition_count: 255,
        next_table_offset: 0,
        table_hash_algo: HashAlgo::Sha256,
        table_hash: [0u8; HASH_FIELD_SIZE],
    };
    let parsed = TableBlockHeader::from_bytes(&h.to_bytes()).unwrap();
    assert_eq!(parsed.partition_count, 255);
}

/// "A Reader MUST stop chain traversal when it reads 0."
#[test]
fn s5_1_chain_traversal_stops_at_zero() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(1, uid(1), "only", b"x", 0, HashAlgo::Sha256)
        .unwrap();
    // After one block, traversal should return exactly one entry.
    assert_eq!(c.entries().unwrap().len(), 1);
}

// =========================================================================
// Section 5.2 — Partition Entry (141 bytes)
// =========================================================================

/// "Each Partition Entry is a fixed-size 141-byte record."
#[test]
fn s5_2_entry_is_141_bytes() {
    assert_eq!(ENTRY_SIZE, 141);
    let e = PartitionEntry {
        partition_type: 1,
        uid: uid(1),
        label: encode_label("x").unwrap(),
        start_offset: 0,
        max_length: 0,
        used_bytes: 0,
        data_hash_algo: HashAlgo::None,
        data_hash: [0u8; HASH_FIELD_SIZE],
    };
    assert_eq!(e.to_bytes().len(), 141);
}

/// "used_bytes MUST be <= max_length."
#[test]
fn s5_2_used_must_not_exceed_max() {
    let e = PartitionEntry {
        partition_type: 1,
        uid: uid(1),
        label: encode_label("x").unwrap(),
        start_offset: 0,
        max_length: 10,
        used_bytes: 11,
        data_hash_algo: HashAlgo::None,
        data_hash: [0u8; HASH_FIELD_SIZE],
    };
    assert!(matches!(e.validate(), Err(Error::UsedExceedsMax)));
}

/// "The free byte count is the derived value (max_length - used_bytes) and is
///  NOT stored."
#[test]
fn s5_2_free_bytes_is_derived() {
    let e = PartitionEntry {
        partition_type: 1,
        uid: uid(1),
        label: encode_label("x").unwrap(),
        start_offset: 0,
        max_length: 100,
        used_bytes: 30,
        data_hash_algo: HashAlgo::None,
        data_hash: [0u8; HASH_FIELD_SIZE],
    };
    assert_eq!(e.free_bytes(), 70);
}

// =========================================================================
// Section 5.3 — Overflow Table Blocks
// =========================================================================

/// "Because partition_count is a u8, a single Table Block holds at most 255
///  entries. Additional partitions are stored in further Table Blocks linked by
///  next_table_offset."
#[test]
fn s5_3_more_than_255_partitions_use_an_overflow_chain() {
    // Build 260 entries, then compact: must produce two chained blocks.
    let mut c = Container::create_with(Cursor::new(Vec::new()), 255, HashAlgo::Sha256).unwrap();
    for i in 0..260u32 {
        let mut u = [0u8; 16];
        u[0..4].copy_from_slice(&i.to_le_bytes());
        u[15] = 0xCC;
        c.add_partition(i + 1, u, "x", &[i as u8], 0, HashAlgo::Crc32c)
            .unwrap();
    }
    let image = c.compacted_image().unwrap();
    // The first block at offset 20 reports 255 entries and a non-zero next.
    let next = u64::from_le_bytes(image[21..29].try_into().unwrap());
    assert_eq!(image[20], 255);
    assert_ne!(next, 0);
    // The second block reports the remaining 5 entries with next = 0.
    let second_off = next as usize;
    assert_eq!(image[second_off], 5);
    let second_next = u64::from_le_bytes(image[second_off + 1..second_off + 9].try_into().unwrap());
    assert_eq!(second_next, 0);
}

/// "A block with partition_count = 0 is valid."
#[test]
fn s5_3_empty_block_is_valid() {
    // The empty compaction case: 0 partitions ⇒ one block, partition_count=0.
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    let image = c.compacted_image().unwrap();
    let mut c2 = Container::open(Cursor::new(image.clone())).unwrap();
    c2.verify().unwrap();
    assert_eq!(image[20], 0, "partition_count of empty block must be 0");
    assert!(c2.entries().unwrap().is_empty());
}

// =========================================================================
// Section 7.1 — Reserved Partition Types
// =========================================================================

/// "0x00000000 RESERVED / INVALID. MUST NOT be used for a live partition."
#[test]
fn s7_1_type_zero_is_rejected_by_writer() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    assert!(matches!(
        c.add_partition(TYPE_RESERVED, uid(1), "x", b"x", 0, HashAlgo::Sha256),
        Err(Error::ReservedType)
    ));
}

/// "A type of 0 in an entry counted by partition_count indicates a malformed
///  file."
#[test]
fn s7_1_type_zero_in_an_existing_entry_fails_validate() {
    let e = PartitionEntry {
        partition_type: 0,
        uid: uid(1),
        label: encode_label("x").unwrap(),
        start_offset: 0,
        max_length: 0,
        used_bytes: 0,
        data_hash_algo: HashAlgo::None,
        data_hash: [0u8; HASH_FIELD_SIZE],
    };
    assert!(matches!(e.validate(), Err(Error::ReservedType)));
}

/// "0xFFFFFFFE is the highest application-defined type."
#[test]
fn s7_1_max_application_type_is_accepted() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(0xFFFF_FFFE, uid(1), "edge", b"x", 0, HashAlgo::Sha256)
        .unwrap();
    c.verify().unwrap();
    assert_eq!(c.entries().unwrap()[0].partition_type, 0xFFFF_FFFE);
}

/// "0xFFFFFFFF RAW / BLOB. A partition whose meaning is not constrained by
///  the format."
#[test]
fn s7_1_raw_type_is_allowed() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(TYPE_RAW, uid(1), "raw", b"\x00\xff", 0, HashAlgo::Crc32c)
        .unwrap();
    c.verify().unwrap();
}

// =========================================================================
// Section 7.2 — Reserved UID
// =========================================================================

/// "The all-zero UID is the NIL UID and MUST NOT be used for a live
///  partition."
#[test]
fn s7_2_nil_uid_is_rejected() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    assert!(matches!(
        c.add_partition(1, NIL_UID, "x", b"x", 0, HashAlgo::Sha256),
        Err(Error::NilUid)
    ));
}

#[test]
fn s7_2_nil_uid_in_existing_entry_fails_validate() {
    let e = PartitionEntry {
        partition_type: 1,
        uid: NIL_UID,
        label: encode_label("x").unwrap(),
        start_offset: 0,
        max_length: 0,
        used_bytes: 0,
        data_hash_algo: HashAlgo::None,
        data_hash: [0u8; HASH_FIELD_SIZE],
    };
    assert!(matches!(e.validate(), Err(Error::NilUid)));
}

// =========================================================================
// Section 8.1 — Hash Algorithm Registry
// =========================================================================

#[test]
fn s8_1_every_registered_id_maps_back_to_itself() {
    for &id in &[0u8, 1, 2, 3, 4, 5, 16, 17, 18] {
        assert_eq!(HashAlgo::from_id(id).unwrap().id(), id);
    }
}

/// "Identifiers 6..15 are reserved for future non-cryptographic algorithms;
///  19 and above are reserved for future cryptographic algorithms."
#[test]
fn s8_1_reserved_ids_are_rejected() {
    for id in 6u8..=15 {
        assert!(matches!(
            HashAlgo::from_id(id),
            Err(Error::UnknownHashAlgo(_))
        ));
    }
    for id in 19u8..=30 {
        assert!(matches!(
            HashAlgo::from_id(id),
            Err(Error::UnknownHashAlgo(_))
        ));
    }
}

/// "CRC-64/XZ ... Check value for the ASCII input '123456789' is
///  0x995DC9BBDF1939FA."
#[test]
fn s8_1_crc64_xz_canonical_check_value() {
    let f = HashAlgo::Crc64.compute(b"123456789");
    let mut v = [0u8; 8];
    v.copy_from_slice(&f[..8]);
    assert_eq!(u64::from_le_bytes(v), 0x995D_C9BB_DF19_39FA);
}

// =========================================================================
// Section 8.2 — Hash Field Encoding
// =========================================================================

/// "Every hash field is a fixed 64-byte field."
#[test]
fn s8_2_hash_field_size_is_64() {
    assert_eq!(HASH_FIELD_SIZE, 64);
}

/// "The standard digest byte stream is written starting at byte 0 of the
///  field; bytes beyond the digest length are 0x00."
#[test]
fn s8_2_digests_are_left_aligned_and_zero_padded() {
    for algo in [
        HashAlgo::Md5,
        HashAlgo::Sha1,
        HashAlgo::Sha256,
        HashAlgo::Sha512,
        HashAlgo::Blake3,
    ] {
        let f = algo.compute(b"some content");
        let n = algo.digest_len();
        assert!(
            f[n..].iter().all(|&b| b == 0),
            "{algo:?} did not zero-pad bytes after offset {n}"
        );
    }
}

/// "CRC algorithms: The CRC value is encoded as a little-endian integer of
///  its width (4 or 8 bytes) starting at byte 0; remaining bytes are 0x00."
#[test]
fn s8_2_crcs_are_little_endian_left_aligned_and_zero_padded() {
    let f32 = HashAlgo::Crc32.compute(b"abc");
    assert!(f32[4..].iter().all(|&b| b == 0));
    let f32c = HashAlgo::Crc32c.compute(b"abc");
    assert!(f32c[4..].iter().all(|&b| b == 0));
    let f64 = HashAlgo::Crc64.compute(b"abc");
    assert!(f64[8..].iter().all(|&b| b == 0));
}

/// "Algorithm 0 (none): All 64 bytes MUST be 0x00, and the hash MUST NOT be
///  verified."
#[test]
fn s8_2_none_is_all_zero_and_always_verifies() {
    let f = HashAlgo::None.compute(b"anything");
    assert!(f.iter().all(|&b| b == 0));
    // ANY 64-byte field is considered valid under "none".
    let mut anything = [0xFFu8; HASH_FIELD_SIZE];
    anything[0] = 0; // even garbage data with non-zero tail
    assert!(HashAlgo::None.verify(b"data", &anything));
}

/// "A Reader compares only the meaningful bytes for the indicated algorithm."
#[test]
fn s8_2_reader_compares_only_significant_bytes() {
    // Tail bytes after the significant digest MUST NOT affect verify().
    let mut f = HashAlgo::Crc32c.compute(b"hello");
    f[10] = 0x99; // garbage in the unused tail
    assert!(HashAlgo::Crc32c.verify(b"hello", &f));
}

// =========================================================================
// Section 8.3 — Partition Data Hash
// =========================================================================

/// "data_hash is computed over the partition's USED data only."
#[test]
fn s8_3_data_hash_covers_used_bytes_only_and_ignores_reservation() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(1, uid(1), "p", b"hello", 1024, HashAlgo::Sha256)
        .unwrap();
    let e = c.entries().unwrap();
    let expected = HashAlgo::Sha256.compute(b"hello");
    assert_eq!(e[0].data_hash, expected);
    c.verify().unwrap();
}

/// "When used_bytes == 0, the hash is the digest (or CRC) of the empty input."
#[test]
fn s8_3_empty_partition_hashes_the_empty_input() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(1, uid(1), "p", b"", 0, HashAlgo::Sha256)
        .unwrap();
    let e = c.entries().unwrap();
    assert_eq!(e[0].used_bytes, 0);
    let expected = HashAlgo::Sha256.compute(b"");
    assert_eq!(e[0].data_hash, expected);
    c.verify().unwrap();
}

// =========================================================================
// Section 8.4 — Table Block Hash
// =========================================================================

/// "The table_hash_algo_id byte IS included in the input."
#[test]
fn s8_4_table_hash_depends_on_algo_id() {
    // Two table hashes with the same logical state but different algorithms
    // must differ — proving the algo id is part of the hashed input.
    let entries: [PartitionEntry; 0] = [];
    let h_sha = compute_table_hash(HashAlgo::Sha256, 0, &entries);
    let h_blake = compute_table_hash(HashAlgo::Blake3, 0, &entries);
    assert_ne!(&h_sha[..32], &h_blake[..32]);
}

/// "For the purpose of computation the 64-byte table_hash field itself is
///  treated as all-zero." — exercised by full roundtrip: computed hash equals
/// stored hash after we read the block, which requires the same convention.
#[test]
fn s8_4_table_hash_field_is_treated_as_zero_during_computation() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(1, uid(1), "p", b"abc", 0, HashAlgo::Sha256)
        .unwrap();
    // verify() reads the stored block, recomputes with the field zeroed,
    // and compares. If we used a different convention these wouldn't match.
    c.verify().unwrap();
}

// =========================================================================
// Section 8.5 — Hash Cascade
// =========================================================================

/// "Modifying a partition's data has a cascading effect: recompute the
///  entry's data_hash, recompute the enclosing Table Block's table_hash."
#[test]
fn s8_5_update_cascades_to_table_hash() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(1, uid(1), "p", b"old", 100, HashAlgo::Sha256)
        .unwrap();
    c.update_partition_data(&uid(1), b"new value").unwrap();
    // verify exercises both the new entry data_hash AND the new table_hash.
    c.verify().unwrap();
}

// =========================================================================
// Section 9 — Versioning
// =========================================================================

/// "A Reader implementing major version M ... SHOULD accept a higher minor,
///  ignoring features it does not understand."
#[test]
fn s9_higher_minor_is_accepted() {
    let mut bytes = vec![0u8; 20 + 74];
    bytes[..8].copy_from_slice(&MAGIC);
    bytes[8..10].copy_from_slice(&VERSION_MAJOR.to_le_bytes());
    bytes[10..12].copy_from_slice(&999u16.to_le_bytes()); // a future minor
    bytes[12..20].copy_from_slice(&20u64.to_le_bytes());
    // Empty block with HashAlgo::None — no hash verification needed.
    bytes[20] = 0; // partition_count
    bytes[21..29].copy_from_slice(&0u64.to_le_bytes()); // next_table_offset
    bytes[29] = 0; // table_hash_algo = none
                   // bytes[30..94] already zero (table_hash)
    let mut c = Container::open(Cursor::new(bytes)).unwrap();
    assert_eq!(c.header().version_minor, 999);
    c.verify().unwrap();
}

// =========================================================================
// Section 10 — Labels
// =========================================================================

/// "0x00 is the terminator and padding byte."
#[test]
fn s10_label_is_null_terminated() {
    let l = encode_label("abc").unwrap();
    assert_eq!(&l[..3], b"abc");
    assert!(l[3..].iter().all(|&b| b == 0));
    assert_eq!(decode_label(&l).unwrap(), "abc");
}

/// "A 32-character label therefore has no terminator."
#[test]
fn s10_full_32_byte_label_has_no_terminator() {
    let s = "a".repeat(32);
    let l = encode_label(&s).unwrap();
    assert_eq!(l[31], b'a');
    assert_eq!(decode_label(&l).unwrap(), s);
}

/// "An empty label is all 0x00."
#[test]
fn s10_empty_label_is_all_zero() {
    let l = encode_label("").unwrap();
    assert!(l.iter().all(|&b| b == 0));
    assert_eq!(decode_label(&l).unwrap(), "");
}

/// "A byte >= 0x80 anywhere in the field renders the label invalid; a Reader
///  MUST treat such an entry as malformed."
#[test]
fn s10_high_bit_byte_in_label_is_rejected() {
    let mut l = [0u8; LABEL_SIZE];
    l[0] = b'a';
    l[1] = 0xFF;
    assert!(matches!(decode_label(&l), Err(Error::InvalidLabel)));
}

// =========================================================================
// Section 12 — Conformance and Validation
// =========================================================================

/// "C4. For each Table Block, verify table_hash unless its table_hash_algo_id
///  is 0."
#[test]
fn c4_table_hash_skipped_when_algo_is_none() {
    let mut c = Container::create_with(Cursor::new(Vec::new()), 4, HashAlgo::None).unwrap();
    c.add_partition(1, uid(1), "p", b"abc", 0, HashAlgo::Sha256)
        .unwrap();

    // Tamper with the table_hash field — verify() must still succeed because
    // the table hash algo is none.
    let mut bytes = c.into_storage().into_inner();
    let hash_field_start = (HEADER_SIZE + 10) as usize;
    for i in 0..HASH_FIELD_SIZE {
        bytes[hash_field_start + i] = 0xFF;
    }
    let mut c2 = Container::open(Cursor::new(bytes)).unwrap();
    c2.verify().unwrap();
}

/// "C8. When verifying partition data, verify data_hash unless
///  data_hash_algo_id is 0."
#[test]
fn c8_data_hash_skipped_when_algo_is_none() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(1, uid(1), "p", b"original", 64, HashAlgo::None)
        .unwrap();
    // Overwrite partition data — verify() must still succeed because data
    // hash algo is None.
    c.update_partition_data(&uid(1), b"different bytes")
        .unwrap();
    c.verify().unwrap();
}

/// "W2. Assign each live partition a unique, non-NIL UID within the file."
#[test]
fn w2_duplicate_uid_is_rejected() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(1, uid(1), "a", b"a", 0, HashAlgo::Sha256)
        .unwrap();
    assert!(matches!(
        c.add_partition(2, uid(1), "b", b"b", 0, HashAlgo::Sha256),
        Err(Error::DuplicateUid)
    ));
}

/// "W5. Zero-fill unused bytes of every fixed-size field (label tail,
///  hash tail)."
#[test]
fn w5_label_and_hash_tails_are_zero_filled_on_write() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(1, uid(1), "ab", b"x", 0, HashAlgo::Crc32c)
        .unwrap();
    let image = c.compacted_image().unwrap();
    // Entry 0 starts at offset HEADER_SIZE + TABLE_HEADER_SIZE.
    let e0 = (HEADER_SIZE + TABLE_HEADER_SIZE) as usize;
    // Label tail bytes [22..52) should be 0 after the "ab" prefix.
    assert!(image[e0 + 22..e0 + 52].iter().all(|&b| b == 0));
    // Hash tail bytes [77+4 .. 77+64) for CRC-32C should be 0.
    assert!(image[e0 + 77 + 4..e0 + 77 + 64].iter().all(|&b| b == 0));
}

// =========================================================================
// Section 15 — Test Vectors (byte-exact)
// =========================================================================

/// "An implementation that builds the same logical container and emits its
///  canonical (compacted) form MUST produce these exact bytes."
///
/// This is the same test as in coverage.rs, but anchored here so reviewers
/// chasing spec compliance find it immediately under section 15.
#[test]
fn s15_canonical_test_vector_is_395_bytes() {
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
    assert_eq!(image.len(), 395);
    // Spot-check the magic + first table block byte.
    assert_eq!(&image[..8], &MAGIC);
    assert_eq!(image[20], 2); // partition_count
                              // Spot-check final data bytes.
    assert_eq!(&image[0x178..0x178 + 11], b"Hello, PCF!");
    assert_eq!(&image[0x183..0x183 + 8], &[0, 1, 2, 3, 4, 5, 6, 7]);
}

// =========================================================================
// Appendix A — Field Layout Summary
// =========================================================================

#[test]
fn appendix_a_consts_are_authoritative() {
    assert_eq!(UID_SIZE, 16);
    assert_eq!(LABEL_SIZE, 32);
    assert_eq!(HASH_FIELD_SIZE, 64);
    assert_eq!(HEADER_SIZE, 20);
    assert_eq!(TABLE_HEADER_SIZE, 74);
    assert_eq!(ENTRY_SIZE, 141);
    assert_eq!(VERSION_MAJOR, 1);
    assert_eq!(VERSION_MINOR, 0);
}
