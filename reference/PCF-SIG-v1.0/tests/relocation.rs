//! Relocation-stability tests (spec Section 4.2).
//!
//! A signature MUST remain valid across operations that change a partition's
//! file layout but not its contents:
//!
//!   - PCF compaction (rebuilds the whole file, trims `max_length`, picks
//!     fresh `start_offset` values)
//!   - reservation growth (different `max_length` and `start_offset`)
//!   - Table Block chain reorganisation (entries split across more blocks)
//!
//! Conversely, any change to the protected fields (data, label, type,
//! data_hash_algo, used_bytes) MUST invalidate the signature; that side is
//! covered by `tamper.rs`.

use std::io::Cursor;

use pcf::{Container, HashAlgo};
use pcf_sig::{
    sign_partitions, verify_all_with_recheck, EntryVerdict, ManifestVerdict, SigningMaterial,
};

fn uid(n: u8) -> [u8; 16] {
    let mut u = [0u8; 16];
    u[0] = n;
    u[15] = 0xAA;
    u
}

fn build_signed_container() -> (Vec<u8>, SigningMaterial) {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    // Three partitions, each with generous `max_length` so we can later
    // verify reservation growth does not affect signatures.
    c.add_partition(
        0x10,
        uid(1),
        "alpha",
        b"alpha payload",
        1024,
        HashAlgo::Sha256,
    )
    .unwrap();
    c.add_partition(
        0x11,
        uid(2),
        "beta",
        b"beta payload",
        1024,
        HashAlgo::Sha512,
    )
    .unwrap();
    c.add_partition(
        0x12,
        uid(3),
        "gamma",
        b"gamma payload",
        1024,
        HashAlgo::Blake3,
    )
    .unwrap();

    let signer = SigningMaterial::ed25519_from_seed(&[0x10u8; 32]);
    sign_partitions(
        &mut c,
        &signer,
        &[uid(1), uid(2), uid(3)],
        uid(0xA1),
        uid(0xA0),
        0,
        "sig",
        "key",
    )
    .unwrap();

    (c.into_storage().into_inner(), signer)
}

#[test]
fn signature_survives_pcf_compaction() {
    let (bytes, _signer) = build_signed_container();
    // First confirm the freshly written container verifies.
    {
        let mut c = Container::open(Cursor::new(bytes.clone())).unwrap();
        let reports = verify_all_with_recheck(&mut c).unwrap();
        assert_eq!(reports.len(), 1);
        assert!(matches!(reports[0].verdict, ManifestVerdict::Valid));
        for e in &reports[0].entries {
            assert!(matches!(e.verdict, EntryVerdict::Valid));
        }
    }

    // Compact. PCF::compacted_image rebuilds the file with tight max_length
    // and packs partitions immediately after the (single) table block. Every
    // entry's start_offset changes; max_length is trimmed to used_bytes.
    let compacted = {
        let mut c = Container::open(Cursor::new(bytes)).unwrap();
        c.compacted_image().unwrap()
    };
    let mut c2 = Container::open(Cursor::new(compacted)).unwrap();
    c2.verify().unwrap(); // PCF cascade still consistent

    // Sanity: confirm start_offset and max_length actually changed for at
    // least one entry.
    let entries = c2.entries().unwrap();
    let alpha = entries.iter().find(|e| e.uid == uid(1)).unwrap();
    assert_eq!(alpha.used_bytes, 13);
    assert_eq!(alpha.max_length, 13); // trimmed by compaction

    // PCF-SIG signature MUST still verify with full recheck.
    let reports = verify_all_with_recheck(&mut c2).unwrap();
    assert_eq!(reports.len(), 1);
    assert!(matches!(reports[0].verdict, ManifestVerdict::Valid));
    assert_eq!(reports[0].entries.len(), 3);
    for e in &reports[0].entries {
        assert!(
            matches!(e.verdict, EntryVerdict::Valid),
            "uid {:?} should still verify after compaction, got {:?}",
            e.uid,
            e.verdict
        );
    }
}

#[test]
fn signature_survives_table_block_chain_growth() {
    // Build a container with a very small first-block capacity so adding
    // more partitions after the signature forces overflow blocks. The
    // existing signature MUST still verify.
    let mut c = Container::create_with(Cursor::new(Vec::new()), 2, HashAlgo::Sha256).unwrap();
    c.add_partition(0x10, uid(1), "alpha", b"alpha", 0, HashAlgo::Sha256)
        .unwrap();

    let signer = SigningMaterial::ed25519_from_seed(&[0x20u8; 32]);
    sign_partitions(
        &mut c,
        &signer,
        &[uid(1)],
        uid(0xA1),
        uid(0xA0),
        0,
        "sig",
        "key",
    )
    .unwrap();
    // The first table block has capacity 2; we have 3 partitions so far
    // (alpha + key + sig). Adding more forces overflow blocks.
    for i in 0..6u8 {
        c.add_partition(0x20, uid(0x40 + i), "extra", &[i; 4], 0, HashAlgo::Sha256)
            .unwrap();
    }
    c.verify().unwrap();

    let reports = verify_all_with_recheck(&mut c).unwrap();
    assert_eq!(reports.len(), 1);
    assert!(matches!(reports[0].verdict, ManifestVerdict::Valid));
    assert_eq!(reports[0].entries.len(), 1);
    assert!(matches!(reports[0].entries[0].verdict, EntryVerdict::Valid));
}

#[test]
fn signature_survives_inplace_update_of_unsigned_partition() {
    // Updating an UNSIGNED partition's data must not affect the signature
    // of a sibling SIGNED partition.
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(0x10, uid(1), "signed", b"locked", 0, HashAlgo::Sha256)
        .unwrap();
    c.add_partition(0x11, uid(2), "free", b"original", 64, HashAlgo::Sha256)
        .unwrap();
    let signer = SigningMaterial::ed25519_from_seed(&[0x30u8; 32]);
    sign_partitions(
        &mut c,
        &signer,
        &[uid(1)],
        uid(0xA1),
        uid(0xA0),
        0,
        "sig",
        "key",
    )
    .unwrap();

    c.update_partition_data(&uid(2), b"replaced payload data")
        .unwrap();
    c.verify().unwrap();

    let reports = verify_all_with_recheck(&mut c).unwrap();
    assert!(matches!(reports[0].verdict, ManifestVerdict::Valid));
    assert!(matches!(reports[0].entries[0].verdict, EntryVerdict::Valid));
}
