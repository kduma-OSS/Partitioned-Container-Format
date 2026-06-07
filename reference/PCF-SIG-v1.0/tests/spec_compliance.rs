//! Spec-conformance tests — every assertion in this file traces back to a
//! specific MUST/SHALL clause of `PCF-SIG-spec-v1.0.txt`. The file is
//! organised by spec section so reviewers can pair each test with its
//! normative source.

use std::io::Cursor;

use pcf::{Container, HashAlgo};
use pcf_sig::{
    compute_fingerprint, sign_partitions, verify_all, DataRecheck, EntryVerdict, Error, KeyFormat,
    KeyRecord, Manifest, ManifestVerdict, SigAlgo, SignaturePartition, SigningMaterial,
    UnverifiableReason, FINGERPRINT_SIZE, KEY_MAGIC, MANIFEST_PREFIX_SIZE, PROFILE_VERSION_MAJOR,
    PROFILE_VERSION_MINOR, SIGNED_ENTRY_SIZE, SIG_MAGIC, TYPE_PCFSIG_KEY, TYPE_PCFSIG_SIG,
};

fn uid(n: u8) -> [u8; 16] {
    let mut u = [0u8; 16];
    u[0] = n;
    u[15] = 0xAA;
    u
}

// =========================================================================
// Section 5 — Partition Types and Reserved Values
// =========================================================================

/// "0xAAAB0001 PCFSIG_KEY ... 0xAAAB0002 PCFSIG_SIG"
#[test]
fn s5_reserved_type_values_match_spec() {
    assert_eq!(TYPE_PCFSIG_KEY, 0xAAAB_0001);
    assert_eq!(TYPE_PCFSIG_SIG, 0xAAAB_0002);
}

// =========================================================================
// Section 6.1 — Key Record layout
// =========================================================================

/// `record_magic` "MUST be the eight bytes \"PCFKEY\\0\\0\""
#[test]
fn s6_1_key_magic_matches_spec() {
    assert_eq!(KEY_MAGIC, *b"PCFKEY\0\0");
}

/// "This document defines major 1, minor 0."
#[test]
fn s6_1_profile_version_constants() {
    assert_eq!(PROFILE_VERSION_MAJOR, 1);
    assert_eq!(PROFILE_VERSION_MINOR, 0);
}

/// "A Reader MUST treat a PCFSIG_KEY partition whose data does not begin
/// with this magic as malformed."
#[test]
fn s6_1_reader_rejects_bad_key_magic() {
    let mut bytes = KeyRecord::new(KeyFormat::Ed25519Raw, vec![0x10u8; 32])
        .unwrap()
        .to_bytes();
    bytes[0] = b'X';
    assert!(matches!(
        KeyRecord::from_bytes(&bytes),
        Err(Error::BadKeyMagic)
    ));
}

/// "A Reader MUST reject a record whose major is not implemented."
#[test]
fn s6_1_reader_rejects_unknown_key_major() {
    let mut bytes = KeyRecord::new(KeyFormat::Ed25519Raw, vec![0x10u8; 32])
        .unwrap()
        .to_bytes();
    bytes[8] = 2;
    assert!(matches!(
        KeyRecord::from_bytes(&bytes),
        Err(Error::UnsupportedMajor(2))
    ));
}

/// "key_format_id ... MUST NOT appear" for id 0.
#[test]
fn s6_2_key_format_zero_rejected() {
    let mut bytes = KeyRecord::new(KeyFormat::Ed25519Raw, vec![0x10u8; 32])
        .unwrap()
        .to_bytes();
    bytes[12] = 0;
    assert!(matches!(
        KeyRecord::from_bytes(&bytes),
        Err(Error::UnknownKeyFormat(0))
    ));
}

/// "reserved ... MUST be 0"
#[test]
fn s6_1_reserved_bytes_rejected_when_non_zero() {
    let mut bytes = KeyRecord::new(KeyFormat::Ed25519Raw, vec![0x10u8; 32])
        .unwrap()
        .to_bytes();
    bytes[14] = 1;
    assert!(matches!(
        KeyRecord::from_bytes(&bytes),
        Err(Error::NonZeroKeyReserved)
    ));
}

// =========================================================================
// Section 6.3 — Fingerprint
// =========================================================================

/// "fingerprint is computed as SHA-256 over key_data exactly as stored"
#[test]
fn s6_3_fingerprint_is_sha256_of_key_data() {
    let key = vec![0xAAu8; 32];
    let rec = KeyRecord::new(KeyFormat::Ed25519Raw, key.clone()).unwrap();
    assert_eq!(rec.fingerprint, compute_fingerprint(&key));
}

/// "A Reader MUST recompute and compare this field; a mismatch renders the
/// record malformed."
#[test]
fn s6_3_reader_rejects_fingerprint_mismatch() {
    let mut bytes = KeyRecord::new(KeyFormat::Ed25519Raw, vec![0x10u8; 32])
        .unwrap()
        .to_bytes();
    bytes[16] ^= 0x01;
    assert!(matches!(
        KeyRecord::from_bytes(&bytes),
        Err(Error::FingerprintMismatch)
    ));
}

// =========================================================================
// Section 7.1 — Manifest layout
// =========================================================================

/// `manifest_magic` "MUST be the eight bytes \"PCFSIG\\0\\0\""
#[test]
fn s7_1_manifest_magic_matches_spec() {
    assert_eq!(SIG_MAGIC, *b"PCFSIG\0\0");
}

/// "60 + 218 * signed_count bytes"
#[test]
fn s7_1_manifest_byte_lengths_match_spec() {
    assert_eq!(MANIFEST_PREFIX_SIZE, 60);
    assert_eq!(SIGNED_ENTRY_SIZE, 218);
}

/// "MUST be 0 ... v1.0 Writers MUST write 0; v1.0 Verifiers MUST reject a
/// manifest with non-zero flags."
#[test]
fn s7_1_non_zero_flags_rejected() {
    let key = vec![0u8; 32];
    let signer = SigningMaterial::ed25519_from_seed(&[0x12u8; 32]);
    let _ = (key, signer);
    // Build a minimal valid manifest and flip flags.
    let entry = pcf_sig::SignedEntry {
        uid: uid(1),
        partition_type: 0x10,
        label: [0u8; 32],
        used_bytes: 0,
        data_hash_algo: HashAlgo::Sha256,
        data_hash: HashAlgo::Sha256.compute(b""),
    };
    let mut bytes = Manifest::new(
        SigAlgo::Ed25519,
        HashAlgo::Sha512,
        [0u8; 32],
        0,
        vec![entry],
    )
    .to_bytes();
    bytes[14] = 1;
    assert!(matches!(
        Manifest::from_bytes(&bytes),
        Err(Error::NonZeroFlags)
    ));
}

/// "MUST be at least 1; a manifest with zero entries is malformed."
#[test]
fn s7_1_zero_signed_count_rejected() {
    let entry = pcf_sig::SignedEntry {
        uid: uid(1),
        partition_type: 0x10,
        label: [0u8; 32],
        used_bytes: 0,
        data_hash_algo: HashAlgo::Sha256,
        data_hash: HashAlgo::Sha256.compute(b""),
    };
    let mut bytes = Manifest::new(
        SigAlgo::Ed25519,
        HashAlgo::Sha512,
        [0u8; 32],
        0,
        vec![entry],
    )
    .to_bytes();
    bytes[56..60].copy_from_slice(&0u32.to_le_bytes());
    bytes.truncate(MANIFEST_PREFIX_SIZE);
    assert!(matches!(
        Manifest::from_bytes(&bytes),
        Err(Error::EmptyManifest)
    ));
}

// =========================================================================
// Section 7.3 — Signature and trailer
// =========================================================================

/// "trailer_length ... v1.0, MUST be 0; Verifiers MUST reject a non-zero
/// value."
#[test]
fn s7_3_non_zero_trailer_rejected() {
    let entry = pcf_sig::SignedEntry {
        uid: uid(1),
        partition_type: 0x10,
        label: [0u8; 32],
        used_bytes: 0,
        data_hash_algo: HashAlgo::Sha256,
        data_hash: HashAlgo::Sha256.compute(b""),
    };
    let m = Manifest::new(
        SigAlgo::Ed25519,
        HashAlgo::Sha512,
        [0u8; 32],
        0,
        vec![entry],
    );
    let mb = m.to_bytes();
    let mut out = Vec::new();
    out.extend_from_slice(&mb);
    out.extend_from_slice(&(64u32).to_le_bytes());
    out.extend_from_slice(&[0u8; 64]);
    out.extend_from_slice(&(1u32).to_le_bytes()); // illegal non-zero trailer length
    out.push(0);
    assert!(matches!(
        SignaturePartition::from_bytes(&out),
        Err(Error::NonZeroTrailer)
    ));
}

// =========================================================================
// Section 8 — Algorithm registry / hash binding
// =========================================================================

/// "Ed25519 ... manifest_hash_algo_id MUST be 17."
#[test]
fn s8_ed25519_requires_sha512_manifest_hash() {
    assert_eq!(
        SigAlgo::Ed25519.required_manifest_hash(),
        Some(HashAlgo::Sha512)
    );
}

/// "A conforming PCF-SIG implementation MUST support sig_algo_id = 1 (Ed25519)."
#[test]
fn s8_ed25519_is_implemented() {
    assert!(SigAlgo::Ed25519.is_implemented());
}

// =========================================================================
// Section 9 — Cryptographic Hash Requirement
// =========================================================================

/// "data_hash_algo_id of each covered partition MUST be one of 16 (SHA-256),
/// 17 (SHA-512), 18 (BLAKE3)."
#[test]
fn s9_writer_refuses_to_sign_weak_hash() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(0x10, uid(1), "a", b"x", 0, HashAlgo::Crc32c)
        .unwrap();
    let signer = SigningMaterial::ed25519_from_seed(&[0x77u8; 32]);
    let r = sign_partitions(
        &mut c,
        &signer,
        &[uid(1)],
        uid(0xA1),
        uid(0xA0),
        0,
        "sig",
        "key",
    );
    assert!(matches!(r, Err(Error::NonCryptoTargetHash)));
}

// =========================================================================
// Section 11 — Verification Procedure
// =========================================================================

/// "report this signature as 'unverifiable: signing key not in file'"
#[test]
fn s11_v4_signature_without_key_is_unverifiable() {
    // Build a container with a valid signature, then remove the key
    // partition so verification has no key to look up.
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(0x10, uid(1), "a", b"x", 0, HashAlgo::Sha256)
        .unwrap();
    let signer = SigningMaterial::ed25519_from_seed(&[0x88u8; 32]);
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
    c.remove_partition(&uid(0xA0)).unwrap();

    let reports = verify_all(&mut c, DataRecheck::Skip).unwrap();
    assert_eq!(reports.len(), 1);
    assert!(matches!(
        reports[0].verdict,
        ManifestVerdict::Unverifiable(UnverifiableReason::NoMatchingKey)
    ));
}

/// "If P exists, confirm field-for-field ... Any mismatch is a per-entry
/// verification failure for e"
#[test]
fn s11_v7_field_mismatch_is_per_entry_failure() {
    // Built by tamper.rs already; this test just confirms the spec mapping.
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    let alpha = uid(1);
    c.add_partition(0x10, alpha, "alpha", b"x", 64, HashAlgo::Sha256)
        .unwrap();
    let signer = SigningMaterial::ed25519_from_seed(&[0x99u8; 32]);
    sign_partitions(
        &mut c,
        &signer,
        &[alpha],
        uid(0xA1),
        uid(0xA0),
        0,
        "sig",
        "key",
    )
    .unwrap();
    c.update_partition_data(&alpha, b"yyy").unwrap();
    let reports = verify_all(&mut c, DataRecheck::Skip).unwrap();
    assert!(matches!(reports[0].verdict, ManifestVerdict::Valid));
    assert!(matches!(
        reports[0].entries[0].verdict,
        EntryVerdict::ProtectedFieldMismatch
    ));
}

// =========================================================================
// Section 15 — Conformance
// =========================================================================

/// "Treat as malformed any PCFSIG_KEY ... whose recomputed SHA-256(key_data)
/// does not equal its stored fingerprint" (R3)
#[test]
fn s15_r3_fingerprint_cross_check_is_mandatory() {
    let mut bytes = KeyRecord::new(KeyFormat::Ed25519Raw, vec![0x10u8; 32])
        .unwrap()
        .to_bytes();
    bytes[17] ^= 0x01;
    assert!(matches!(
        KeyRecord::from_bytes(&bytes),
        Err(Error::FingerprintMismatch)
    ));
}

/// "Reject any Manifest containing the NIL UID ... in a SignedEntry" (R5)
#[test]
fn s15_r5_nil_uid_entry_rejected() {
    let mut bytes = [0u8; SIGNED_ENTRY_SIZE];
    bytes[16..20].copy_from_slice(&0x10u32.to_le_bytes());
    bytes[60] = HashAlgo::Sha256.id();
    bytes[62..126].copy_from_slice(&HashAlgo::Sha256.compute(b""));
    assert!(matches!(
        pcf_sig::SignedEntry::from_bytes(&bytes),
        Err(Error::EntryNilUid)
    ));
}

/// "report this signature as ... Unverifiable, not as MALFORMED." (R9)
#[test]
fn s15_r9_unknown_sig_algo_is_unverifiable() {
    // Tweak a serialised manifest's sig_algo_id to a recognised-but-
    // unimplemented value (2 = RSA-PSS-SHA-256). Manifest::from_bytes will
    // accept it (registry-wise), but the verifier reports Unverifiable.
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    c.add_partition(0x10, uid(1), "a", b"x", 0, HashAlgo::Sha256)
        .unwrap();
    let signer = SigningMaterial::ed25519_from_seed(&[0x55u8; 32]);
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

    // Locate the PCFSIG_SIG partition and patch sig_algo_id + matching
    // manifest_hash_algo_id in the file bytes.
    let entries = c.entries().unwrap();
    let sig_entry = entries
        .iter()
        .find(|e| e.partition_type == TYPE_PCFSIG_SIG)
        .unwrap()
        .clone();
    let start = sig_entry.start_offset as usize;
    let mut bytes = c.into_storage().into_inner();
    bytes[start + 12] = SigAlgo::RsaPssSha256.id();
    bytes[start + 13] = HashAlgo::Sha256.id();
    let mut c2 = Container::open(Cursor::new(bytes)).unwrap();
    let reports = verify_all(&mut c2, DataRecheck::Skip).unwrap();
    assert!(matches!(
        reports[0].verdict,
        ManifestVerdict::Unverifiable(UnverifiableReason::UnsupportedSigAlgo(2))
    ));
}

// =========================================================================
// Section 7.4 — Protected vs Unprotected Fields (the central property)
// =========================================================================

/// Unprotected fields (`start_offset`, `max_length`) MUST NOT affect
/// signature validity (the relocation-stability property).
#[test]
fn s7_4_compaction_preserves_signature() {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    let alpha = uid(1);
    c.add_partition(0x10, alpha, "alpha", b"payload", 1024, HashAlgo::Sha256)
        .unwrap();
    let signer = SigningMaterial::ed25519_from_seed(&[0xCCu8; 32]);
    sign_partitions(
        &mut c,
        &signer,
        &[alpha],
        uid(0xA1),
        uid(0xA0),
        0,
        "sig",
        "key",
    )
    .unwrap();
    let original_alpha = c
        .entries()
        .unwrap()
        .into_iter()
        .find(|e| e.uid == alpha)
        .unwrap();

    let compacted = c.compacted_image().unwrap();
    let mut c2 = Container::open(Cursor::new(compacted)).unwrap();
    let new_alpha = c2
        .entries()
        .unwrap()
        .into_iter()
        .find(|e| e.uid == alpha)
        .unwrap();

    // Unprotected fields changed.
    assert_ne!(original_alpha.max_length, new_alpha.max_length);
    // Protected fields did not.
    assert_eq!(original_alpha.uid, new_alpha.uid);
    assert_eq!(original_alpha.partition_type, new_alpha.partition_type);
    assert_eq!(original_alpha.label, new_alpha.label);
    assert_eq!(original_alpha.used_bytes, new_alpha.used_bytes);
    assert_eq!(original_alpha.data_hash_algo, new_alpha.data_hash_algo);
    assert_eq!(original_alpha.data_hash, new_alpha.data_hash);

    let reports = verify_all(&mut c2, DataRecheck::Skip).unwrap();
    assert!(matches!(reports[0].verdict, ManifestVerdict::Valid));
    assert!(matches!(reports[0].entries[0].verdict, EntryVerdict::Valid));
}

/// Spec Section 6.3: fingerprint field size constant matches "32 B".
#[test]
fn s6_3_fingerprint_size_constant_is_32() {
    assert_eq!(FINGERPRINT_SIZE, 32);
}
