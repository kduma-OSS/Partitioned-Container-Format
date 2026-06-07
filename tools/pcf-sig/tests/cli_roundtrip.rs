//! End-to-end tests for the `pcf-sig-cli` library half: keygen, incremental
//! signing, verification, trust matching, and tamper detection — all driven
//! through real PCF files on disk.

use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use pcf::{Container, HashAlgo, PartitionEntry};
use pcf_sig::{EntryVerdict, ManifestVerdict};
use pcf_sig_cli::{keygen, list_keys, sign_file, verify_file};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A unique scratch path under the OS temp dir.
fn tmp(suffix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!(
        "pcfsig-test-{}-{}-{}",
        std::process::id(),
        n,
        suffix
    ));
    p
}

/// Create a PCF file with `count` ordinary partitions named p0..pN.
fn make_pcf(path: &std::path::Path, count: u8) -> Vec<[u8; 16]> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .unwrap();
    let mut c = Container::create(f).unwrap();
    let mut uids = Vec::new();
    for i in 0..count {
        let mut uid = [0u8; 16];
        uid[0] = i + 1;
        let data = vec![i; 32 + i as usize];
        c.add_partition(
            0x10 + i as u32,
            uid,
            &format!("p{i}"),
            &data,
            0,
            HashAlgo::Sha256,
        )
        .unwrap();
        uids.push(uid);
    }
    c.into_storage().flush().unwrap();
    uids
}

/// Append one more ordinary partition to an existing PCF file; returns its uid.
fn append_partition(path: &std::path::Path, idx: u8) -> [u8; 16] {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut c = Container::open(f).unwrap();
    let mut uid = [0u8; 16];
    uid[0] = idx + 1;
    let data = vec![idx; 48];
    c.add_partition(
        0x10 + idx as u32,
        uid,
        &format!("p{idx}"),
        &data,
        0,
        HashAlgo::Sha256,
    )
    .unwrap();
    c.into_storage().flush().unwrap();
    uid
}

fn entries(path: &std::path::Path) -> Vec<PartitionEntry> {
    let f = std::fs::File::open(path).unwrap();
    Container::open(f).unwrap().entries().unwrap()
}

#[test]
fn keygen_writes_two_32_byte_files() {
    let sk = tmp("a.key");
    let pk = tmp("a.pub");
    let s = keygen(sk.to_str().unwrap(), pk.to_str().unwrap()).unwrap();
    assert_eq!(std::fs::read(&sk).unwrap().len(), 32);
    assert_eq!(std::fs::read(&pk).unwrap().len(), 32);
    assert_eq!(s.fingerprint.len(), 32);
    // Refuses to overwrite.
    assert!(keygen(sk.to_str().unwrap(), pk.to_str().unwrap()).is_err());
    let _ = std::fs::remove_file(&sk);
    let _ = std::fs::remove_file(&pk);
}

#[test]
fn sign_then_verify_roundtrip_with_trust() {
    let sk = tmp("rt.key");
    let pk = tmp("rt.pub");
    keygen(sk.to_str().unwrap(), pk.to_str().unwrap()).unwrap();
    let pcf = tmp("rt.pcf");
    make_pcf(&pcf, 2);

    let s = sign_file(
        pcf.to_str().unwrap(),
        sk.to_str().unwrap(),
        None,
        false,
        "pcfsig",
        "pcfkey",
    )
    .unwrap();
    assert_eq!(s.signed_uids.len(), 2);
    assert!(s.sig_partition_uid.is_some());

    let v = verify_file(pcf.to_str().unwrap(), Some(pk.as_path()), true).unwrap();
    assert_eq!(v.reports.len(), 1);
    assert_eq!(v.reports[0].verdict, ManifestVerdict::Valid);
    assert!(v.reports[0]
        .entries
        .iter()
        .all(|e| e.verdict == EntryVerdict::Valid));
    assert!(v.trusted_match);

    // Exactly one PCFSIG_KEY partition was written.
    assert_eq!(list_keys(pcf.to_str().unwrap()).unwrap().len(), 1);

    for p in [&sk, &pk, &pcf] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn signing_is_incremental() {
    let sk = tmp("inc.key");
    let pk = tmp("inc.pub");
    keygen(sk.to_str().unwrap(), pk.to_str().unwrap()).unwrap();
    let pcf = tmp("inc.pcf");
    make_pcf(&pcf, 2);

    // First pass signs both.
    let s1 = sign_file(
        pcf.to_str().unwrap(),
        sk.to_str().unwrap(),
        None,
        false,
        "pcfsig",
        "pcfkey",
    )
    .unwrap();
    assert_eq!(s1.signed_uids.len(), 2);

    // Second pass with no changes is a no-op.
    let s2 = sign_file(
        pcf.to_str().unwrap(),
        sk.to_str().unwrap(),
        None,
        false,
        "pcfsig",
        "pcfkey",
    )
    .unwrap();
    assert!(s2.sig_partition_uid.is_none());
    assert_eq!(s2.skipped_already_signed, 2);

    // Add a partition: only the new one gets signed.
    append_partition(&pcf, 2);
    let s3 = sign_file(
        pcf.to_str().unwrap(),
        sk.to_str().unwrap(),
        None,
        false,
        "pcfsig",
        "pcfkey",
    )
    .unwrap();
    assert_eq!(s3.signed_uids.len(), 1);
    assert_eq!(s3.skipped_already_signed, 2);

    // Two signatures now; both valid.
    let v = verify_file(pcf.to_str().unwrap(), None, true).unwrap();
    assert_eq!(v.reports.len(), 2);
    assert!(v
        .reports
        .iter()
        .all(|r| r.verdict == ManifestVerdict::Valid));

    // --resign covers everything again in one fresh signature.
    let s4 = sign_file(
        pcf.to_str().unwrap(),
        sk.to_str().unwrap(),
        None,
        true,
        "pcfsig",
        "pcfkey",
    )
    .unwrap();
    assert_eq!(s4.signed_uids.len(), 3);

    for p in [&sk, &pk, &pcf] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn tampered_partition_is_detected() {
    let sk = tmp("tmp.key");
    let pk = tmp("tmp.pub");
    keygen(sk.to_str().unwrap(), pk.to_str().unwrap()).unwrap();
    let pcf = tmp("tmp.pcf");
    let uids = make_pcf(&pcf, 2);
    sign_file(
        pcf.to_str().unwrap(),
        sk.to_str().unwrap(),
        None,
        false,
        "pcfsig",
        "pcfkey",
    )
    .unwrap();

    // Corrupt the first partition's data bytes in place (without touching the
    // table entry's recorded data_hash).
    let target = entries(&pcf)
        .into_iter()
        .find(|e| e.uid == uids[0])
        .unwrap();
    {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&pcf)
            .unwrap();
        f.seek(SeekFrom::Start(target.start_offset)).unwrap();
        f.write_all(&[0xFF]).unwrap();
        f.flush().unwrap();
    }

    let v = verify_file(pcf.to_str().unwrap(), Some(pk.as_path()), true).unwrap();
    let entry = v.reports[0]
        .entries
        .iter()
        .find(|e| e.uid == uids[0])
        .unwrap();
    assert_eq!(entry.verdict, EntryVerdict::DataHashRecomputationMismatch);

    for p in [&sk, &pk, &pcf] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn refuses_to_sign_pfs_files() {
    let sk = tmp("pfs.key");
    let pk = tmp("pfs.pub");
    keygen(sk.to_str().unwrap(), pk.to_str().unwrap()).unwrap();

    // A PCF file carrying a PFS_SESSION-typed partition looks like a PFS-MS
    // archive; signing it by appending partitions would corrupt its chain.
    let pcf = tmp("pfs.pcf");
    {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&pcf)
            .unwrap();
        let mut c = Container::create(f).unwrap();
        c.add_partition(0xAAAA_0002, [9u8; 16], "session", b"x", 0, HashAlgo::Sha256)
            .unwrap();
        c.into_storage().flush().unwrap();
    }

    let err = sign_file(
        pcf.to_str().unwrap(),
        sk.to_str().unwrap(),
        None,
        false,
        "s",
        "k",
    )
    .unwrap_err();
    assert!(err.to_string().contains("PFS-MS"));

    for p in [&sk, &pk, &pcf] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn wrong_trusted_key_does_not_match() {
    let sk = tmp("w1.key");
    let pk = tmp("w1.pub");
    keygen(sk.to_str().unwrap(), pk.to_str().unwrap()).unwrap();
    let other_pk = tmp("w2.pub");
    let other_sk = tmp("w2.key");
    keygen(other_sk.to_str().unwrap(), other_pk.to_str().unwrap()).unwrap();

    let pcf = tmp("w.pcf");
    make_pcf(&pcf, 1);
    sign_file(
        pcf.to_str().unwrap(),
        sk.to_str().unwrap(),
        None,
        false,
        "pcfsig",
        "pcfkey",
    )
    .unwrap();

    let v = verify_file(pcf.to_str().unwrap(), Some(other_pk.as_path()), true).unwrap();
    assert!(v.reports[0].verdict == ManifestVerdict::Valid);
    assert!(!v.trusted_match);

    for p in [&sk, &pk, &other_pk, &other_sk, &pcf] {
        let _ = std::fs::remove_file(p);
    }
}
