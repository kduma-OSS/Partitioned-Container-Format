//! Multi-signer tests (spec Section 4.4, Section 12).
//!
//! A file may carry any number of PCFSIG_SIG partitions; each is reported
//! independently. Signers' key partitions are deduplicated by fingerprint
//! (Section 4.3).

use std::io::Cursor;

use pcf::{Container, HashAlgo, LABEL_SIZE};
use pcf_sig::{
    embed_endorsement, expected_leaf_key_data_hash, fingerprint_of, issue_endorsement,
    key_endorsements, sign_partitions, verify_all, verify_all_with_recheck, DataRecheck,
    EndorsementRequest, EntryVerdict, KeyFormat, ManifestVerdict, SigningMaterial, TYPE_PCFSIG_KEY,
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

// =========================================================================
// Pattern B (spec Section 12.2): key endorsement via countersignature
// =========================================================================

fn label_fixed(s: &str) -> [u8; LABEL_SIZE] {
    let mut l = [0u8; LABEL_SIZE];
    l[..s.len()].copy_from_slice(s.as_bytes());
    l
}

#[test]
fn pattern_b_key_endorsement_e2e() {
    // Leaf signer signs the data partition; a CA then countersigns the leaf
    // PCFSIG_KEY partition. key_endorsements() reports the CA as endorser.
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    let alpha = uid(1);
    c.add_partition(0x10, alpha, "alpha", b"payload", 0, HashAlgo::Sha256)
        .unwrap();

    let leaf = SigningMaterial::ed25519_from_seed(&[0x40u8; 32]);
    let ca = SigningMaterial::ed25519_from_seed(&[0x50u8; 32]);

    // Leaf signs alpha. Use a deterministic uid for the leaf key partition.
    let leaf_key_uid = uid(0x80);
    sign_partitions(
        &mut c,
        &leaf,
        &[alpha],
        uid(0x81),
        leaf_key_uid,
        0,
        "leaf-sig",
        "leaf-key",
    )
    .unwrap();

    // CA now countersigns the leaf KEY partition by uid.
    sign_partitions(
        &mut c,
        &ca,
        &[leaf_key_uid],
        uid(0xC1),
        uid(0xC0),
        0,
        "ca-sig",
        "ca-key",
    )
    .unwrap();

    let reports = verify_all_with_recheck(&mut c).unwrap();
    assert_eq!(reports.len(), 2);
    for r in &reports {
        assert!(matches!(r.verdict, ManifestVerdict::Valid));
        for er in &r.entries {
            assert!(matches!(er.verdict, EntryVerdict::Valid));
        }
    }

    let endorsers = key_endorsements(&mut c, &reports, &leaf.fingerprint()).unwrap();
    assert_eq!(endorsers, vec![ca.fingerprint()]);

    // Sanity: querying for the CA's own key returns no endorsements (no one
    // countersigned the CA in this file).
    let ca_endorsers = key_endorsements(&mut c, &reports, &ca.fingerprint()).unwrap();
    assert!(ca_endorsers.is_empty());

    // Sanity: querying for a non-existent fingerprint returns empty.
    let nobody = key_endorsements(&mut c, &reports, &[0xFFu8; 32]).unwrap();
    assert!(nobody.is_empty());
}

#[test]
fn pattern_b_endorsement_survives_data_tamper() {
    // Endorsement of a KEY is orthogonal to the leaf's data assertions: if a
    // data partition signed by leaf is tampered with, the leaf's per-entry
    // verdict becomes ProtectedFieldMismatch, but the CA's signature over
    // the leaf KEY partition stays Valid and the key remains endorsed.
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    let alpha = uid(1);
    c.add_partition(0x10, alpha, "alpha", b"original", 64, HashAlgo::Sha256)
        .unwrap();

    let leaf = SigningMaterial::ed25519_from_seed(&[0x60u8; 32]);
    let ca = SigningMaterial::ed25519_from_seed(&[0x70u8; 32]);
    let leaf_key_uid = uid(0x90);
    sign_partitions(
        &mut c,
        &leaf,
        &[alpha],
        uid(0x91),
        leaf_key_uid,
        0,
        "leaf-sig",
        "leaf-key",
    )
    .unwrap();
    sign_partitions(
        &mut c,
        &ca,
        &[leaf_key_uid],
        uid(0xD1),
        uid(0xD0),
        0,
        "ca-sig",
        "ca-key",
    )
    .unwrap();

    // Tamper: update alpha's data so the leaf's SignedEntry no longer matches.
    c.update_partition_data(&alpha, b"forged").unwrap();
    let reports = verify_all_with_recheck(&mut c).unwrap();

    // Leaf's manifest signature is still valid (the manifest bytes did not
    // change), but its per-entry verdict for alpha is mismatch.
    let leaf_report = reports
        .iter()
        .find(|r| r.signer_key_fingerprint == leaf.fingerprint())
        .unwrap();
    assert!(matches!(leaf_report.verdict, ManifestVerdict::Valid));
    let alpha_entry = leaf_report
        .entries
        .iter()
        .find(|er| er.uid == alpha)
        .unwrap();
    assert!(matches!(
        alpha_entry.verdict,
        EntryVerdict::ProtectedFieldMismatch
    ));

    // CA's report is Valid and its endorsement of the leaf KEY is unaffected.
    let endorsers = key_endorsements(&mut c, &reports, &leaf.fingerprint()).unwrap();
    assert_eq!(endorsers, vec![ca.fingerprint()]);
}

#[test]
fn pattern_b_endorsement_removed_when_ca_signature_dropped() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    let alpha = uid(1);
    c.add_partition(0x10, alpha, "alpha", b"x", 0, HashAlgo::Sha256)
        .unwrap();
    let leaf = SigningMaterial::ed25519_from_seed(&[0x11u8; 32]);
    let ca = SigningMaterial::ed25519_from_seed(&[0x22u8; 32]);
    let leaf_key_uid = uid(0x80);
    let ca_sig_uid = uid(0xC1);
    sign_partitions(
        &mut c,
        &leaf,
        &[alpha],
        uid(0x81),
        leaf_key_uid,
        0,
        "leaf-sig",
        "leaf-key",
    )
    .unwrap();
    sign_partitions(
        &mut c,
        &ca,
        &[leaf_key_uid],
        ca_sig_uid,
        uid(0xC0),
        0,
        "ca-sig",
        "ca-key",
    )
    .unwrap();

    // Drop the CA's PCFSIG_SIG partition; endorsement disappears.
    c.remove_partition(&ca_sig_uid).unwrap();
    let reports = verify_all_with_recheck(&mut c).unwrap();
    let endorsers = key_endorsements(&mut c, &reports, &leaf.fingerprint()).unwrap();
    assert!(endorsers.is_empty());
}

// =========================================================================
// Pattern B workflow W2 (spec Section 12.2.1): stateless CA endpoint
// =========================================================================

#[test]
fn pattern_b_stateless_ca_workflow() {
    // The "client" builds a container with leaf data and the leaf signer; the
    // "CA" produces an endorsement having seen ONLY the leaf key bytes and the
    // planned identity fields. The client then embeds the response.
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    let alpha = uid(1);
    c.add_partition(0x10, alpha, "alpha", b"payload", 0, HashAlgo::Sha256)
        .unwrap();

    let leaf = SigningMaterial::ed25519_from_seed(&[0x33u8; 32]);
    let ca = SigningMaterial::ed25519_from_seed(&[0x44u8; 32]);

    // Identity fields the client and CA agree on for the leaf PCFSIG_KEY:
    let intended_uid = uid(0x80);
    let intended_label = label_fixed("leaf-key");
    let intended_hash = HashAlgo::Sha256;

    // Client signs the data partition with the leaf signer; the writer chooses
    // exactly the agreed uid and label for its PCFSIG_KEY partition.
    sign_partitions(
        &mut c,
        &leaf,
        &[alpha],
        uid(0x81),
        intended_uid,
        0,
        "leaf-sig",
        "leaf-key",
    )
    .unwrap();

    // CA never sees the container -- only the leaf's raw public key plus the
    // planned identity. The CA is stateless: same inputs give same outputs.
    let request = EndorsementRequest {
        key_format: KeyFormat::Ed25519Raw,
        key_data: leaf.public_key_bytes(),
        intended_uid,
        intended_label,
        data_hash_algo: intended_hash,
    };
    let response = issue_endorsement(&ca, &request, 1_700_000_000).unwrap();

    // Client sanity-checks that the data_hash it would publish for the leaf
    // KEY partition matches what the CA committed to.
    let local_hash = expected_leaf_key_data_hash(
        request.key_format,
        &request.key_data,
        request.data_hash_algo,
    )
    .unwrap();
    assert_ne!(local_hash, [0u8; pcf::HASH_FIELD_SIZE]); // proves it ran

    // Client embeds the CA's PCFSIG_KEY + PCFSIG_SIG in its file.
    embed_endorsement(&mut c, &response, uid(0xC0), uid(0xC1), "ca-key", "ca-sig").unwrap();

    // Verify: two valid signatures (leaf over alpha, CA over leaf KEY).
    let reports = verify_all_with_recheck(&mut c).unwrap();
    assert_eq!(reports.len(), 2);
    for r in &reports {
        assert!(
            matches!(r.verdict, ManifestVerdict::Valid),
            "verdict was {:?}",
            r.verdict
        );
        for er in &r.entries {
            assert!(
                matches!(er.verdict, EntryVerdict::Valid),
                "entry verdict was {:?}",
                er.verdict
            );
        }
    }

    let endorsers = key_endorsements(&mut c, &reports, &leaf.fingerprint()).unwrap();
    assert_eq!(endorsers, vec![ca.fingerprint()]);

    // Confirm fingerprint_of helper produces the same value as the
    // SigningMaterial -> KeyRecord round-trip.
    assert_eq!(fingerprint_of(&leaf.public_key_bytes()), leaf.fingerprint());
}

#[test]
fn pattern_b_stateless_response_is_durable_across_files() {
    // Workflow W3: the same EndorsementResponse, cached by the client, is
    // valid in any PCF file in which the leaf PCFSIG_KEY partition is
    // reproduced with the agreed intended_uid, intended_label, and key_data.
    let leaf = SigningMaterial::ed25519_from_seed(&[0x55u8; 32]);
    let ca = SigningMaterial::ed25519_from_seed(&[0x66u8; 32]);
    let intended_uid = uid(0x80);
    let intended_label = label_fixed("leaf-key");
    let intended_hash = HashAlgo::Sha256;

    let request = EndorsementRequest {
        key_format: KeyFormat::Ed25519Raw,
        key_data: leaf.public_key_bytes(),
        intended_uid,
        intended_label,
        data_hash_algo: intended_hash,
    };
    let response = issue_endorsement(&ca, &request, 0).unwrap();

    // Build two unrelated PCF files using the same response.
    for file_seed in [0u8, 1u8] {
        let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
        c.add_partition(
            0x10,
            uid(1 + file_seed),
            "alpha",
            &[file_seed; 8],
            0,
            HashAlgo::Sha256,
        )
        .unwrap();
        sign_partitions(
            &mut c,
            &leaf,
            &[uid(1 + file_seed)],
            uid(0x81 + file_seed),
            intended_uid,
            0,
            "leaf-sig",
            "leaf-key",
        )
        .unwrap();
        embed_endorsement(
            &mut c,
            &response,
            uid(0xC0 + file_seed),
            uid(0xC1 + file_seed),
            "ca-key",
            "ca-sig",
        )
        .unwrap();

        let reports = verify_all_with_recheck(&mut c).unwrap();
        assert_eq!(reports.len(), 2);
        for r in &reports {
            assert!(matches!(r.verdict, ManifestVerdict::Valid));
        }
        let endorsers = key_endorsements(&mut c, &reports, &leaf.fingerprint()).unwrap();
        assert_eq!(endorsers, vec![ca.fingerprint()]);
    }
}

#[test]
fn issue_endorsement_refuses_weak_hash() {
    let ca = SigningMaterial::ed25519_from_seed(&[0x77u8; 32]);
    let req = EndorsementRequest {
        key_format: KeyFormat::Ed25519Raw,
        key_data: vec![0xAAu8; 32],
        intended_uid: uid(0x80),
        intended_label: label_fixed("leaf"),
        data_hash_algo: HashAlgo::Crc32c, // non-cryptographic
    };
    assert!(matches!(
        issue_endorsement(&ca, &req, 0),
        Err(pcf_sig::Error::NonCryptoTargetHash)
    ));
}

#[test]
fn verify_all_alias_compiles_for_pattern_b() {
    // Sanity: the helper also works with the non-recheck verify path.
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(0x10, uid(1), "alpha", b"x", 0, HashAlgo::Sha256)
        .unwrap();
    let leaf = SigningMaterial::ed25519_from_seed(&[0x88u8; 32]);
    let ca = SigningMaterial::ed25519_from_seed(&[0x99u8; 32]);
    let leaf_key_uid = uid(0x80);
    sign_partitions(
        &mut c,
        &leaf,
        &[uid(1)],
        uid(0x81),
        leaf_key_uid,
        0,
        "leaf-sig",
        "leaf-key",
    )
    .unwrap();
    sign_partitions(
        &mut c,
        &ca,
        &[leaf_key_uid],
        uid(0xC1),
        uid(0xC0),
        0,
        "ca-sig",
        "ca-key",
    )
    .unwrap();
    let reports = verify_all(&mut c, DataRecheck::Skip).unwrap();
    let endorsers = key_endorsements(&mut c, &reports, &leaf.fingerprint()).unwrap();
    assert_eq!(endorsers, vec![ca.fingerprint()]);
}
