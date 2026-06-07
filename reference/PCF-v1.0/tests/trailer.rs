//! Tests for the optional end-of-file trailer (spec section 4, "File Trailer").

use std::io::Cursor;

use pcf::{
    Container, Error, HashAlgo, Trailer, CHAIN_BACKWARD, CHAIN_FORWARD, HEADER_SIZE,
    PT_OFFSET_TRAILER, TRAILER_SIZE,
};

fn uid(n: u8) -> [u8; 16] {
    let mut u = [0u8; 16];
    u[0] = n;
    u[15] = 0xAA;
    u
}

#[test]
fn finalize_with_trailer_roundtrips() {
    let bytes = {
        let mut c = Container::create_with(Cursor::new(Vec::new()), 4, HashAlgo::Sha256).unwrap();
        c.add_partition(0x10, uid(1), "alpha", b"Hello, PCF!", 0, HashAlgo::Sha256)
            .unwrap();
        c.add_partition(
            0xFFFF_FFFF,
            uid(2),
            "raw",
            b"\x00\x01\x02",
            0,
            HashAlgo::Crc32c,
        )
        .unwrap();
        c.finalize_with_trailer().unwrap();
        c.into_storage().into_inner()
    };

    // The header now holds the sentinel rather than a real offset.
    let hdr_off = u64::from_le_bytes(bytes[12..20].try_into().unwrap());
    assert_eq!(hdr_off, PT_OFFSET_TRAILER);

    // The last TRAILER_SIZE bytes are a valid trailer that points at the head.
    let n = bytes.len();
    let tb: [u8; 20] = bytes[n - TRAILER_SIZE as usize..].try_into().unwrap();
    let t = Trailer::from_bytes(&tb).unwrap();
    assert_eq!(t.partition_table_offset, HEADER_SIZE);
    assert_eq!(t.chain_flags, CHAIN_FORWARD);

    // Re-open resolves the head via the trailer and reads everything back.
    let mut c = Container::open(Cursor::new(bytes)).unwrap();
    assert_eq!(c.header().partition_table_offset, PT_OFFSET_TRAILER);
    assert_eq!(c.table_head(), HEADER_SIZE);
    assert!(!c.chain_is_backward());
    c.verify().unwrap();
    let e = c.entries().unwrap();
    assert_eq!(e.len(), 2);
    assert_eq!(c.read_partition_data(&e[0]).unwrap(), b"Hello, PCF!");
    assert_eq!(c.read_partition_data(&e[1]).unwrap(), b"\x00\x01\x02");
}

#[test]
fn finalize_with_trailer_over_overflow_chain() {
    // First-block capacity 2 forces overflow blocks for 5 partitions; the
    // trailer must still resolve the (forward) chain head correctly.
    let bytes = {
        let mut c = Container::create_with(Cursor::new(Vec::new()), 2, HashAlgo::Sha256).unwrap();
        for i in 1..=5u8 {
            c.add_partition(
                i as u32,
                uid(i),
                &format!("p{i}"),
                &[i; 8],
                0,
                HashAlgo::Sha256,
            )
            .unwrap();
        }
        c.finalize_with_trailer().unwrap();
        c.into_storage().into_inner()
    };

    let mut c = Container::open(Cursor::new(bytes)).unwrap();
    c.verify().unwrap();
    assert_eq!(c.entries().unwrap().len(), 5);
}

#[test]
fn backward_flag_is_reported() {
    // Build a forward file, then re-publish its head through a trailer marked
    // BACKWARD. Chain traversal is mechanically identical; only the reported
    // direction changes.
    let mut bytes = {
        let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
        c.add_partition(1, uid(1), "only", b"data", 0, HashAlgo::Sha256)
            .unwrap();
        c.into_storage().into_inner()
    };
    let head = u64::from_le_bytes(bytes[12..20].try_into().unwrap());
    let t = Trailer {
        partition_table_offset: head,
        chain_flags: CHAIN_BACKWARD,
    };
    bytes.extend_from_slice(&t.to_bytes());
    bytes[12..20].copy_from_slice(&PT_OFFSET_TRAILER.to_le_bytes());

    let mut c = Container::open(Cursor::new(bytes)).unwrap();
    assert_eq!(c.table_head(), head);
    assert!(c.chain_is_backward());
    c.verify().unwrap();
    assert_eq!(c.entries().unwrap().len(), 1);
}

#[test]
fn missing_trailer_is_rejected() {
    // Header claims trailer mode but the file is too short / has no valid
    // trailer.
    let mut bytes = {
        let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
        c.add_partition(1, uid(1), "p", b"x", 0, HashAlgo::Sha256)
            .unwrap();
        c.into_storage().into_inner()
    };
    bytes[12..20].copy_from_slice(&PT_OFFSET_TRAILER.to_le_bytes());
    // No trailer appended → trailing bytes are partition data, not the magic.
    assert!(matches!(
        Container::open(Cursor::new(bytes)),
        Err(Error::BadTrailer)
    ));
}

#[test]
fn header_only_sentinel_file_is_rejected() {
    // A bare 20-byte header in trailer mode: file_len == TRAILER_SIZE, so the
    // "trailer" read overlaps the header and fails the magic check.
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(1, uid(1), "p", b"x", 0, HashAlgo::Sha256)
        .unwrap();
    let full = c.into_storage().into_inner();
    let mut header_only = full[..20].to_vec();
    header_only[12..20].copy_from_slice(&PT_OFFSET_TRAILER.to_le_bytes());
    assert!(matches!(
        Container::open(Cursor::new(header_only)),
        Err(Error::BadTrailer)
    ));
}

#[test]
fn aborted_append_is_recovered() {
    // A complete trailer-mode file followed by an aborted append (garbage with
    // no trailer magic): the reader scans back past the garbage to the last
    // valid trailer and sees the committed state.
    let mut bytes = {
        let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
        c.add_partition(1, uid(1), "p", b"committed", 0, HashAlgo::Sha256)
            .unwrap();
        c.finalize_with_trailer().unwrap();
        c.into_storage().into_inner()
    };
    bytes.extend_from_slice(&[0xABu8; 500]); // aborted append, no trailer magic

    let mut c = Container::open(Cursor::new(bytes)).unwrap();
    assert_eq!(c.table_head(), HEADER_SIZE);
    c.verify().unwrap();
    let e = c.entries().unwrap();
    assert_eq!(c.read_partition_data(&e[0]).unwrap(), b"committed");
}

#[test]
fn spurious_trailer_magic_in_tail_is_skipped() {
    // The backward scan must skip windows that carry the magic but whose
    // recorded head does not reference a parseable block, and keep scanning
    // down to the genuine trailer. Two crafted fakes exercise both rejection
    // paths: an out-of-range (overflowing) head and an in-range non-block head.
    let mut bytes = {
        let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
        c.add_partition(1, uid(1), "p", b"real", 0, HashAlgo::Sha256)
            .unwrap();
        c.finalize_with_trailer().unwrap();
        c.into_storage().into_inner()
    };
    // Fake A (lower): magic present, head points into the header (offset 5),
    // which does not parse as a table block → rejected.
    let fake_a = Trailer {
        partition_table_offset: 5,
        chain_flags: CHAIN_FORWARD,
    };
    bytes.extend_from_slice(&fake_a.to_bytes());
    // Fake B (at EOF): magic present, head offset overflows on +header → rejected.
    let fake_b = Trailer {
        partition_table_offset: u64::MAX,
        chain_flags: CHAIN_FORWARD,
    };
    bytes.extend_from_slice(&fake_b.to_bytes());

    let mut c = Container::open(Cursor::new(bytes)).unwrap();
    // Resolved to the genuine trailer below both fakes.
    assert_eq!(c.table_head(), HEADER_SIZE);
    c.verify().unwrap();
    assert_eq!(c.entries().unwrap().len(), 1);
}

#[test]
fn bad_trailer_error_displays() {
    // Exercise the Display arm for the new error variant.
    let s = format!("{}", Error::BadTrailer);
    assert!(s.contains("trailer"));
}

#[test]
fn trailer_mode_compacts_back_to_header_mode() {
    let bytes = {
        let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
        c.add_partition(1, uid(1), "a", b"AAAA", 16, HashAlgo::Sha256)
            .unwrap();
        c.finalize_with_trailer().unwrap();
        c.into_storage().into_inner()
    };

    let mut c = Container::open(Cursor::new(bytes)).unwrap();
    let compacted = c.compacted_image().unwrap();
    // Compaction always emits the canonical header-pointer form.
    let off = u64::from_le_bytes(compacted[12..20].try_into().unwrap());
    assert_eq!(off, HEADER_SIZE);

    let mut c2 = Container::open(Cursor::new(compacted)).unwrap();
    assert_eq!(c2.table_head(), HEADER_SIZE);
    assert!(!c2.chain_is_backward());
    c2.verify().unwrap();
    assert_eq!(c2.entries().unwrap().len(), 1);
}
