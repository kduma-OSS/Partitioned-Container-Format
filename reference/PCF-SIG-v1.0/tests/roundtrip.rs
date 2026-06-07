//! End-to-end roundtrip tests: build a container with a signed partition,
//! reopen it, verify.

use std::io::Cursor;

use pcf::{Container, HashAlgo};
use pcf_sig::{
    sign_partitions, verify_all, DataRecheck, EntryVerdict, ManifestVerdict, SigningMaterial,
};

fn uid(n: u8) -> [u8; 16] {
    let mut u = [0u8; 16];
    u[0] = n;
    u[15] = 0xAA; // non-NIL guard
    u
}

#[test]
fn sign_and_verify_single_partition() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    let alpha = uid(1);
    c.add_partition(0x10, alpha, "alpha", b"hello", 0, HashAlgo::Sha256)
        .unwrap();

    let signer = SigningMaterial::ed25519_from_seed(&[0x42u8; 32]);
    sign_partitions(
        &mut c,
        &signer,
        &[alpha],
        uid(0xA1),
        uid(0xA0),
        1_700_000_000,
        "pcfsig",
        "pcfkey",
    )
    .unwrap();

    c.verify().unwrap();
    let reports = verify_all(&mut c, DataRecheck::Skip).unwrap();
    assert_eq!(reports.len(), 1);
    assert!(matches!(reports[0].verdict, ManifestVerdict::Valid));
    assert_eq!(reports[0].entries.len(), 1);
    assert_eq!(reports[0].entries[0].uid, alpha);
    assert!(matches!(reports[0].entries[0].verdict, EntryVerdict::Valid));
    assert_eq!(reports[0].signed_at_unix_seconds, 1_700_000_000);
    assert_eq!(reports[0].signer_key_fingerprint, signer.fingerprint());
}

#[test]
fn reopen_after_serialise_then_verify() {
    let bytes = {
        let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
        c.add_partition(0x10, uid(1), "alpha", b"hello", 0, HashAlgo::Sha256)
            .unwrap();
        c.add_partition(0x11, uid(2), "beta", b"world", 0, HashAlgo::Blake3)
            .unwrap();
        let signer = SigningMaterial::ed25519_from_seed(&[0x01u8; 32]);
        sign_partitions(
            &mut c,
            &signer,
            &[uid(1), uid(2)],
            uid(0xA1),
            uid(0xA0),
            0,
            "sig",
            "key",
        )
        .unwrap();
        c.into_storage().into_inner()
    };

    let mut c = Container::open(Cursor::new(bytes)).unwrap();
    c.verify().unwrap();
    let reports = verify_all(&mut c, DataRecheck::Recompute).unwrap();
    assert_eq!(reports.len(), 1);
    assert!(matches!(reports[0].verdict, ManifestVerdict::Valid));
    let mut covered: Vec<_> = reports[0].entries.iter().map(|e| e.uid).collect();
    covered.sort();
    let mut expected = vec![uid(1), uid(2)];
    expected.sort();
    assert_eq!(covered, expected);
    for er in &reports[0].entries {
        assert!(matches!(er.verdict, EntryVerdict::Valid));
    }
}

#[test]
fn key_partition_is_deduplicated() {
    // Two sign operations with the same signer must produce ONE PCFSIG_KEY.
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(0x10, uid(1), "a", b"a", 0, HashAlgo::Sha256)
        .unwrap();
    c.add_partition(0x10, uid(2), "b", b"b", 0, HashAlgo::Sha256)
        .unwrap();

    let signer = SigningMaterial::ed25519_from_seed(&[0x03u8; 32]);
    sign_partitions(
        &mut c,
        &signer,
        &[uid(1)],
        uid(0xA1),
        uid(0xA0),
        0,
        "sig1",
        "k",
    )
    .unwrap();
    sign_partitions(
        &mut c,
        &signer,
        &[uid(2)],
        uid(0xA2),
        uid(0xA3), // distinct uid; would-be second key partition
        0,
        "sig2",
        "k2",
    )
    .unwrap();

    let entries = c.entries().unwrap();
    let key_partitions: Vec<_> = entries
        .iter()
        .filter(|e| e.partition_type == pcf_sig::TYPE_PCFSIG_KEY)
        .collect();
    assert_eq!(key_partitions.len(), 1);
    // The first add wrote uid 0xA0; the second sign must have reused it.
    assert_eq!(key_partitions[0].uid, uid(0xA0));

    let reports = verify_all(&mut c, DataRecheck::Skip).unwrap();
    assert_eq!(reports.len(), 2);
    for r in &reports {
        assert!(matches!(r.verdict, ManifestVerdict::Valid));
    }
}

#[test]
fn refuses_to_sign_weak_hash_partition() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    let alpha = uid(1);
    c.add_partition(0x10, alpha, "alpha", b"x", 0, HashAlgo::Crc32c)
        .unwrap();
    let signer = SigningMaterial::ed25519_from_seed(&[0x04u8; 32]);
    let r = sign_partitions(
        &mut c,
        &signer,
        &[alpha],
        uid(0xA1),
        uid(0xA0),
        0,
        "sig",
        "key",
    );
    assert!(matches!(r, Err(pcf_sig::Error::NonCryptoTargetHash)));
}

#[test]
fn refuses_self_reference() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    let alpha = uid(1);
    c.add_partition(0x10, alpha, "alpha", b"x", 0, HashAlgo::Sha256)
        .unwrap();
    let signer = SigningMaterial::ed25519_from_seed(&[0x05u8; 32]);
    let sig_uid = uid(0xA1);
    let r = sign_partitions(
        &mut c,
        &signer,
        &[alpha, sig_uid], // sig_uid present in covered set
        sig_uid,
        uid(0xA0),
        0,
        "sig",
        "key",
    );
    assert!(matches!(r, Err(pcf_sig::Error::SelfSignedEntry)));
}

#[test]
fn refuses_duplicate_target_uid() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    let alpha = uid(1);
    c.add_partition(0x10, alpha, "alpha", b"x", 0, HashAlgo::Sha256)
        .unwrap();
    let signer = SigningMaterial::ed25519_from_seed(&[0x06u8; 32]);
    let r = sign_partitions(
        &mut c,
        &signer,
        &[alpha, alpha],
        uid(0xA1),
        uid(0xA0),
        0,
        "sig",
        "key",
    );
    assert!(matches!(r, Err(pcf_sig::Error::DuplicateSignedUid)));
}

#[test]
fn missing_target_partition_is_rejected() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    let signer = SigningMaterial::ed25519_from_seed(&[0x07u8; 32]);
    let r = sign_partitions(
        &mut c,
        &signer,
        &[uid(0xEE)],
        uid(0xA1),
        uid(0xA0),
        0,
        "sig",
        "key",
    );
    assert!(matches!(r, Err(pcf_sig::Error::TargetPartitionMissing)));
}
