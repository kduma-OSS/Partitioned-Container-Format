//! Tamper-detection tests (spec Section 7.4, Section 11 V7).
//!
//! Any modification of a PROTECTED field of a covered partition must produce
//! a per-entry `ProtectedFieldMismatch` or `DataHashRecomputationMismatch`
//! verdict; modifying an UNPROTECTED field (start_offset, max_length) must
//! NOT.

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

fn build() -> (Container<Cursor<Vec<u8>>>, [u8; 16]) {
    let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
    let alpha = uid(1);
    c.add_partition(
        0x10,
        alpha,
        "alpha",
        b"original payload",
        64,
        HashAlgo::Sha256,
    )
    .unwrap();
    let signer = SigningMaterial::ed25519_from_seed(&[0x33u8; 32]);
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
    (c, alpha)
}

#[test]
fn baseline_verifies() {
    let (mut c, _alpha) = build();
    let reports = verify_all_with_recheck(&mut c).unwrap();
    assert!(matches!(reports[0].verdict, ManifestVerdict::Valid));
    assert!(matches!(reports[0].entries[0].verdict, EntryVerdict::Valid));
}

#[test]
fn altering_data_invalidates_entry() {
    // `update_partition_data` correctly updates the partition's data_hash on
    // disk, so the per-entry verdict becomes ProtectedFieldMismatch (the
    // SignedEntry's data_hash no longer matches the live data_hash).
    let (mut c, alpha) = build();
    c.update_partition_data(&alpha, b"forged payload bytes")
        .unwrap();
    let reports = verify_all_with_recheck(&mut c).unwrap();
    // Manifest signature itself still verifies; only the per-entry check
    // catches the tamper (this is the central property: PCF-SIG sees the
    // mismatch even when a malicious Writer cooperatively updated
    // data_hash).
    assert!(matches!(reports[0].verdict, ManifestVerdict::Valid));
    assert!(matches!(
        reports[0].entries[0].verdict,
        EntryVerdict::ProtectedFieldMismatch
    ));
}

#[test]
fn covered_partition_removed_is_reported_missing() {
    let (mut c, alpha) = build();
    c.remove_partition(&alpha).unwrap();
    let reports = verify_all_with_recheck(&mut c).unwrap();
    assert!(matches!(reports[0].verdict, ManifestVerdict::Valid));
    assert!(matches!(
        reports[0].entries[0].verdict,
        EntryVerdict::MissingPartition
    ));
}

#[test]
fn malicious_data_hash_overwrite_is_detected() {
    // Simulate a Writer that flipped the partition's stored bytes without
    // updating data_hash (PCF would reject this at `verify()`, but we want
    // to confirm PCF-SIG catches it via its data_hash check). We patch the
    // file bytes directly.
    let (mut c, alpha) = build();
    let entries = c.entries().unwrap();
    let alpha_entry = entries.iter().find(|e| e.uid == alpha).unwrap().clone();

    let mut bytes = c.into_storage().into_inner();
    // Corrupt the first byte of alpha's data region.
    bytes[alpha_entry.start_offset as usize] ^= 0xFF;

    // PCF's own verify will fail because data_hash no longer matches the
    // bytes; we therefore re-open WITHOUT calling Container::verify, and ask
    // PCF-SIG to recompute hashes (DataRecheck::Recompute).
    let mut c2 = Container::open(Cursor::new(bytes)).unwrap();
    let reports = verify_all_with_recheck(&mut c2).unwrap();
    assert!(matches!(reports[0].verdict, ManifestVerdict::Valid));
    // The Manifest signature is still cryptographically valid (we did not
    // touch any signature bytes). The recheck pass catches the data
    // corruption.
    assert!(matches!(
        reports[0].entries[0].verdict,
        EntryVerdict::DataHashRecomputationMismatch
    ));
}

#[test]
fn altering_signature_bytes_invalidates_manifest() {
    let (mut c, _alpha) = build();
    let entries = c.entries().unwrap();
    let sig_entry = entries
        .iter()
        .find(|e| e.partition_type == pcf_sig::TYPE_PCFSIG_SIG)
        .unwrap()
        .clone();

    let mut bytes = c.into_storage().into_inner();
    // Flip a byte well inside sig_bytes (manifest is at the start; sig
    // length is u32 at offset manifest_len; sig bytes follow). The exact
    // offset doesn't matter — we just flip near the end of the used region.
    let last = (sig_entry.start_offset + sig_entry.used_bytes - 8) as usize;
    bytes[last] ^= 0x01;

    let mut c2 = Container::open(Cursor::new(bytes)).unwrap();
    let reports = verify_all_with_recheck(&mut c2).unwrap();
    assert!(matches!(reports[0].verdict, ManifestVerdict::Invalid));
}
