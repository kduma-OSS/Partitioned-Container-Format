//! End-to-end tests for the `pcf` reference crate.

use std::io::Cursor;

use pcf::{Container, Error, HashAlgo};

fn uid(n: u8) -> [u8; 16] {
    let mut u = [0u8; 16];
    u[0] = n;
    u[15] = 0xAA; // ensure non-nil even if n == 0
    u
}

#[test]
fn create_add_read_verify() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(
        0x10,
        uid(1),
        "alpha",
        b"first payload",
        16,
        HashAlgo::Sha256,
    )
    .unwrap();
    c.add_partition(
        0xFFFF_FFFF,
        uid(2),
        "blob",
        b"raw bytes",
        0,
        HashAlgo::Crc32c,
    )
    .unwrap();

    c.verify().unwrap();
    let entries = c.entries().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].label_string().unwrap(), "alpha");
    assert_eq!(
        c.read_partition_data(&entries[0]).unwrap(),
        b"first payload"
    );
    assert_eq!(c.read_partition_data(&entries[1]).unwrap(), b"raw bytes");
    assert_eq!(entries[0].free_bytes(), 16);
}

#[test]
fn reopen_roundtrip() {
    let bytes = {
        let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
        c.add_partition(1, uid(1), "one", b"aaaa", 8, HashAlgo::Sha256)
            .unwrap();
        c.add_partition(2, uid(2), "two", b"bbbbbb", 0, HashAlgo::Crc64)
            .unwrap();
        c.into_storage().into_inner()
    };

    let mut c = Container::open(Cursor::new(bytes)).unwrap();
    c.verify().unwrap();
    let e = c.entries().unwrap();
    assert_eq!(e.len(), 2);
    assert_eq!(c.read_partition_data(&e[1]).unwrap(), b"bbbbbb");
}

#[test]
fn update_in_place_and_cascade() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(1, uid(1), "p", b"short", 100, HashAlgo::Sha256)
        .unwrap();
    c.update_partition_data(&uid(1), b"a longer replacement payload")
        .unwrap();
    c.verify().unwrap();
    let e = c.entries().unwrap();
    assert_eq!(
        c.read_partition_data(&e[0]).unwrap(),
        b"a longer replacement payload"
    );

    // Exceeding the reservation must fail.
    let too_big = vec![0u8; 1000];
    assert!(matches!(
        c.update_partition_data(&uid(1), &too_big),
        Err(Error::DataTooLarge)
    ));
}

#[test]
fn remove_partition_works() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(1, uid(1), "a", b"AAAA", 0, HashAlgo::Sha256)
        .unwrap();
    c.add_partition(2, uid(2), "b", b"BBBB", 0, HashAlgo::Sha256)
        .unwrap();
    c.add_partition(3, uid(3), "c", b"CCCC", 0, HashAlgo::Sha256)
        .unwrap();

    c.remove_partition(&uid(2)).unwrap();
    c.verify().unwrap();
    let labels: Vec<String> = c
        .entries()
        .unwrap()
        .iter()
        .map(|e| e.label_string().unwrap())
        .collect();
    assert_eq!(labels, vec!["a".to_string(), "c".to_string()]);

    assert!(matches!(c.remove_partition(&uid(2)), Err(Error::NotFound)));
}

#[test]
fn overflow_chain() {
    // First block capacity of 3 forces overflow blocks for 10 partitions.
    let mut c = Container::create_with(Cursor::new(Vec::new()), 3, HashAlgo::Sha256).unwrap();
    for i in 1..=10u8 {
        let payload = vec![i; (i as usize) + 1];
        c.add_partition(
            i as u32,
            uid(i),
            &format!("part{i}"),
            &payload,
            4,
            HashAlgo::Sha256,
        )
        .unwrap();
    }
    c.verify().unwrap();
    let e = c.entries().unwrap();
    assert_eq!(e.len(), 10);
    for (idx, entry) in e.iter().enumerate() {
        let i = (idx + 1) as u8;
        assert_eq!(
            c.read_partition_data(entry).unwrap(),
            vec![i; (i as usize) + 1]
        );
    }
}

#[test]
fn duplicate_uid_rejected() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(1, uid(1), "x", b"x", 0, HashAlgo::Sha256)
        .unwrap();
    assert!(matches!(
        c.add_partition(2, uid(1), "y", b"y", 0, HashAlgo::Sha256),
        Err(Error::DuplicateUid)
    ));
}

#[test]
fn reserved_type_and_nil_uid_rejected() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    assert!(matches!(
        c.add_partition(0, uid(1), "x", b"x", 0, HashAlgo::Sha256),
        Err(Error::ReservedType)
    ));
    assert!(matches!(
        c.add_partition(1, [0u8; 16], "x", b"x", 0, HashAlgo::Sha256),
        Err(Error::NilUid)
    ));
}

#[test]
fn corruption_is_detected() {
    let mut bytes = {
        let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
        c.add_partition(1, uid(1), "p", b"important data", 0, HashAlgo::Sha256)
            .unwrap();
        c.into_storage().into_inner()
    };
    // Flip a byte in the partition data region (near the end of the file).
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;

    let mut c = Container::open(Cursor::new(bytes)).unwrap();
    assert!(matches!(c.verify(), Err(Error::DataHashMismatch)));
}

#[test]
fn compaction_reclaims_space_and_stays_valid() {
    let mut c = Container::create_with(Cursor::new(Vec::new()), 8, HashAlgo::Sha256).unwrap();
    for i in 1..=5u8 {
        c.add_partition(
            i as u32,
            uid(i),
            &format!("f{i}"),
            &[i; 32],
            4096,
            HashAlgo::Sha256,
        )
        .unwrap();
    }
    // Remove a couple to create dead space.
    c.remove_partition(&uid(2)).unwrap();
    c.remove_partition(&uid(4)).unwrap();

    let original_len = c.compacted_image().unwrap(); // also a smoke test
    let _ = original_len;

    let mut compacted_buf = Vec::new();
    c.compact_into(&mut compacted_buf).unwrap();

    let mut c2 = Container::open(Cursor::new(compacted_buf.clone())).unwrap();
    c2.verify().unwrap();
    let e = c2.entries().unwrap();
    assert_eq!(e.len(), 3);
    // After compaction every reservation equals the used size.
    for entry in &e {
        assert_eq!(entry.max_length, entry.used_bytes);
        assert_eq!(entry.free_bytes(), 0);
    }
    // The surviving partitions keep their data.
    let labels: Vec<String> = e.iter().map(|x| x.label_string().unwrap()).collect();
    assert_eq!(labels, vec!["f1", "f3", "f5"]);
}
