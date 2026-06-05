//! Multi-signer tests (spec Section 4.4, Section 12).
//!
//! A file may carry any number of PCFSIG_SIG partitions; each is reported
//! independently. Signers' key partitions are deduplicated by fingerprint
//! (Section 4.3).

use std::io::Cursor;

use pcf::{Container, HashAlgo};
use pcf_sig::{
    sign_partitions, verify_all, DataRecheck, EntryVerdict, ManifestVerdict, SigningMaterial,
    TYPE_PCFSIG_KEY,
};

fn uid(n: u8) -> [u8; 16] {
    let mut u = [0u8; 16];
    u[0] = n;
    u[15] = 0xAA;
    u
}

#[test]
fn two_signers_each_sign_their_own_partition() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(0x10, uid(1), "alpha", b"alpha", 0, HashAlgo::Sha256)
        .unwrap();
    c.add_partition(0x11, uid(2), "beta", b"beta", 0, HashAlgo::Sha256)
        .unwrap();

    let signer_a = SigningMaterial::ed25519_from_seed(&[0x01u8; 32]);
    let signer_b = SigningMaterial::ed25519_from_seed(&[0x02u8; 32]);

    sign_partitions(
        &mut c,
        &signer_a,
        &[uid(1)],
        uid(0xA1),
        uid(0xA0),
        0,
        "sigA",
        "keyA",
    )
    .unwrap();
    sign_partitions(
        &mut c,
        &signer_b,
        &[uid(2)],
        uid(0xB1),
        uid(0xB0),
        0,
        "sigB",
        "keyB",
    )
    .unwrap();

    let reports = verify_all(&mut c, DataRecheck::Skip).unwrap();
    assert_eq!(reports.len(), 2);
    for r in &reports {
        assert!(matches!(r.verdict, ManifestVerdict::Valid));
        assert_eq!(r.entries.len(), 1);
        assert!(matches!(r.entries[0].verdict, EntryVerdict::Valid));
    }
    let mut fingerprints: Vec<_> = reports.iter().map(|r| r.signer_key_fingerprint).collect();
    fingerprints.sort();
    let mut expected = vec![signer_a.fingerprint(), signer_b.fingerprint()];
    expected.sort();
    assert_eq!(fingerprints, expected);
}

#[test]
fn overlapping_coverage_is_independent() {
    // Two signers each cover {alpha, beta, gamma}; the verifier reports both
    // as independently valid.
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(0x10, uid(1), "alpha", b"a", 0, HashAlgo::Sha256)
        .unwrap();
    c.add_partition(0x10, uid(2), "beta", b"b", 0, HashAlgo::Sha256)
        .unwrap();
    c.add_partition(0x10, uid(3), "gamma", b"g", 0, HashAlgo::Sha256)
        .unwrap();

    let a = SigningMaterial::ed25519_from_seed(&[0x10u8; 32]);
    let b = SigningMaterial::ed25519_from_seed(&[0x20u8; 32]);

    sign_partitions(
        &mut c,
        &a,
        &[uid(1), uid(2), uid(3)],
        uid(0xA1),
        uid(0xA0),
        0,
        "sigA",
        "keyA",
    )
    .unwrap();
    sign_partitions(
        &mut c,
        &b,
        &[uid(1), uid(2), uid(3)],
        uid(0xB1),
        uid(0xB0),
        0,
        "sigB",
        "keyB",
    )
    .unwrap();

    let reports = verify_all(&mut c, DataRecheck::Skip).unwrap();
    assert_eq!(reports.len(), 2);
    for r in &reports {
        assert!(matches!(r.verdict, ManifestVerdict::Valid));
        assert_eq!(r.entries.len(), 3);
        for er in &r.entries {
            assert!(matches!(er.verdict, EntryVerdict::Valid));
        }
    }
}

#[test]
fn same_signer_with_two_signatures_dedupes_key() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(0x10, uid(1), "alpha", b"a", 0, HashAlgo::Sha256)
        .unwrap();
    c.add_partition(0x11, uid(2), "beta", b"b", 0, HashAlgo::Sha256)
        .unwrap();

    let signer = SigningMaterial::ed25519_from_seed(&[0xAAu8; 32]);
    sign_partitions(
        &mut c,
        &signer,
        &[uid(1)],
        uid(0xA1),
        uid(0xA0),
        0,
        "sig1",
        "key",
    )
    .unwrap();
    sign_partitions(
        &mut c,
        &signer,
        &[uid(2)],
        uid(0xA2),
        uid(0xA3), // would be a second key partition; must be ignored
        0,
        "sig2",
        "key",
    )
    .unwrap();

    let key_partitions: Vec<_> = c
        .entries()
        .unwrap()
        .into_iter()
        .filter(|e| e.partition_type == TYPE_PCFSIG_KEY)
        .collect();
    assert_eq!(
        key_partitions.len(),
        1,
        "one signer, one key partition (deduplication)"
    );

    let reports = verify_all(&mut c, DataRecheck::Skip).unwrap();
    assert_eq!(reports.len(), 2);
    for r in &reports {
        assert!(matches!(r.verdict, ManifestVerdict::Valid));
        assert_eq!(r.signer_key_fingerprint, signer.fingerprint());
    }
}
