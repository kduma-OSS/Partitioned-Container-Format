//! PFS-aware signing: a signature rides in a dedicated PFS session, so the
//! session chain stays valid, signing is incremental, and a PCF-SIG verifier
//! accepts the result.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use pcf::HashAlgo;
use pcf_sig::{EntryVerdict, ManifestVerdict};
use pfs_ms::{sign_archive, FsReader, FsWriter};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn tmp(suffix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!(
        "pfs-sign-test-{}-{}-{}",
        std::process::id(),
        n,
        suffix
    ));
    p
}

/// Write a 32-byte Ed25519 seed to a fresh key file.
fn keyfile(name: &str) -> PathBuf {
    let p = tmp(name);
    std::fs::write(&p, [7u8; 32]).unwrap();
    p
}

/// Build a small PFS-MS file on disk with two files.
fn make_fs(path: &std::path::Path) {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .unwrap();
    let mut w = FsWriter::mkfs(f, HashAlgo::Sha256).unwrap();
    w.put_file("a.txt", b"hello").unwrap();
    w.put_file("b.txt", b"world").unwrap();
    w.into_storage().sync_all().unwrap();
}

fn open_fs(path: &std::path::Path) -> FsReader<std::fs::File> {
    FsReader::open(std::fs::File::open(path).unwrap()).unwrap()
}

#[test]
fn sign_keeps_chain_valid_and_verifies() {
    let pcf = tmp("rt.pcf");
    make_fs(&pcf);
    let key = keyfile("rt.key");

    let out = sign_archive(&pcf, &key, false).unwrap();
    assert!(out.sig_partition_uid.is_some());
    assert!(!out.signed_uids.is_empty());

    // PFS session-chain integrity survives the signature session.
    open_fs(&pcf).verify().unwrap();
    // Files still readable.
    assert_eq!(open_fs(&pcf).read_path("a.txt").unwrap(), b"hello");

    // PCF-SIG verifier accepts the signature over the content/node partitions.
    let v = pcf_sig_cli::verify_file(pcf.to_str().unwrap(), None, true).unwrap();
    assert_eq!(v.reports.len(), 1);
    assert_eq!(v.reports[0].verdict, ManifestVerdict::Valid);
    assert!(v.reports[0]
        .entries
        .iter()
        .all(|e| e.verdict == EntryVerdict::Valid));

    for p in [&pcf, &key] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn signing_is_incremental_and_converges() {
    let pcf = tmp("inc.pcf");
    make_fs(&pcf);
    let key = keyfile("inc.key");

    let first = sign_archive(&pcf, &key, false).unwrap();
    assert!(first.sig_partition_uid.is_some());

    // Nothing changed: re-signing is a no-op (no new signature session).
    let again = sign_archive(&pcf, &key, false).unwrap();
    assert!(again.sig_partition_uid.is_none());
    assert!(again.skipped_already_signed > 0);

    // Add a file, then sign only the new content/node.
    {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&pcf)
            .unwrap();
        let mut w = FsWriter::open(f).unwrap();
        w.put_file("c.txt", b"!!!").unwrap();
        w.into_storage().sync_all().unwrap();
    }
    let third = sign_archive(&pcf, &key, false).unwrap();
    assert!(third.sig_partition_uid.is_some());
    assert!(third.skipped_already_signed > 0);

    // Chain still valid; two signatures now, both valid.
    open_fs(&pcf).verify().unwrap();
    let v = pcf_sig_cli::verify_file(pcf.to_str().unwrap(), None, true).unwrap();
    assert_eq!(v.reports.len(), 2);
    assert!(v
        .reports
        .iter()
        .all(|r| r.verdict == ManifestVerdict::Valid));

    for p in [&pcf, &key] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn key_partition_is_deduplicated_across_signatures() {
    let pcf = tmp("dedup.pcf");
    make_fs(&pcf);
    let key = keyfile("dedup.key");

    sign_archive(&pcf, &key, false).unwrap();
    // Force a second signature over the same partitions.
    sign_archive(&pcf, &key, true).unwrap();

    // Despite two signature sessions, only one PCFSIG_KEY exists.
    let keys = pcf_sig_cli::list_keys(pcf.to_str().unwrap()).unwrap();
    assert_eq!(keys.len(), 1);

    for p in [&pcf, &key] {
        let _ = std::fs::remove_file(p);
    }
}
