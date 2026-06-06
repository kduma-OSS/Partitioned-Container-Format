//! Integration tests for `pcf-compact`.
//!
//! Drive the library API directly — no subprocess spawning. The test pattern
//! for compaction mirrors `reference/PCF-v1.0/tests/roundtrip.rs:220-255`.

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use pcf::{Container, HashAlgo};
use pcf_compact::{atomic_write, compact_bytes, format_size, CompactError};

fn uid(n: u8) -> [u8; 16] {
    let mut u = [0u8; 16];
    u[15] = n;
    u
}

/// Build a sample PCF container with `num` 32-byte partitions (each reserving
/// 4 KiB), then remove the UIDs in `holes` to create dead space.
fn build_sample(num: u8, holes: &[u8]) -> Vec<u8> {
    let mut c = Container::create_with(Cursor::new(Vec::new()), 8, HashAlgo::Sha256).unwrap();
    for i in 1..=num {
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
    for &h in holes {
        c.remove_partition(&uid(h)).unwrap();
    }
    c.into_storage().into_inner()
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn tmpdir() -> TmpDir {
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!("pcf-compact-{pid}-{nanos}-{seq}"));
    fs::create_dir_all(&p).unwrap();
    TmpDir(p)
}

struct TmpDir(PathBuf);
impl TmpDir {
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn count_temp_residue(dir: &Path) -> usize {
    fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .contains(".pcf-compact.tmp.")
        })
        .count()
}

#[test]
fn round_trip_compacts_and_verifies() {
    let bytes = build_sample(5, &[2, 4]);
    let original_len = bytes.len();

    let compacted = compact_bytes(&bytes, true, true).expect("compact");
    assert!(
        compacted.len() < original_len,
        "compaction should reclaim space: {} -> {}",
        original_len,
        compacted.len()
    );

    let mut c2 = Container::open(Cursor::new(compacted)).unwrap();
    c2.verify().unwrap();
    let entries = c2.entries().unwrap();
    assert_eq!(entries.len(), 3);
    for e in &entries {
        assert_eq!(e.max_length, e.used_bytes, "reservation should be trimmed");
    }
    let labels: Vec<String> = entries.iter().map(|e| e.label_string().unwrap()).collect();
    assert_eq!(labels, vec!["f1", "f3", "f5"]);
}

#[test]
fn in_place_overwrites_atomically() {
    let dir = tmpdir();
    let path = dir.path().join("sample.pcf");
    let bytes = build_sample(5, &[2, 4]);
    fs::write(&path, &bytes).unwrap();

    let compacted = compact_bytes(&bytes, true, true).unwrap();
    atomic_write(&path, &compacted).unwrap();

    let on_disk = fs::read(&path).unwrap();
    assert_eq!(on_disk, compacted);
    assert_eq!(
        count_temp_residue(dir.path()),
        0,
        "no temp files should be left behind"
    );
}

#[test]
fn output_to_separate_path_leaves_input_untouched() {
    let dir = tmpdir();
    let in_path = dir.path().join("in.pcf");
    let out_path = dir.path().join("out.pcf");
    let bytes = build_sample(5, &[2, 4]);
    fs::write(&in_path, &bytes).unwrap();

    let compacted = compact_bytes(&bytes, true, true).unwrap();
    atomic_write(&out_path, &compacted).unwrap();

    assert_eq!(fs::read(&in_path).unwrap(), bytes, "input untouched");
    assert_eq!(
        fs::read(&out_path).unwrap(),
        compacted,
        "output is compacted"
    );
}

#[test]
fn no_verify_still_produces_valid_image() {
    let bytes = build_sample(3, &[]);
    let compacted = compact_bytes(&bytes, false, false).unwrap();
    let mut c = Container::open(Cursor::new(compacted)).unwrap();
    c.verify().unwrap();
}

#[test]
fn empty_container_compacts_to_minimal_size() {
    let bytes = build_sample(0, &[]);
    let compacted = compact_bytes(&bytes, true, true).unwrap();
    // HEADER_SIZE (20) + TABLE_HEADER_SIZE (74) = 94 bytes for one empty
    // table block.
    assert_eq!(compacted.len(), 94);
    let mut c = Container::open(Cursor::new(compacted)).unwrap();
    c.verify().unwrap();
    assert!(c.entries().unwrap().is_empty());
}

#[test]
fn already_compact_is_idempotent() {
    let bytes = build_sample(3, &[]);
    let first = compact_bytes(&bytes, true, true).unwrap();
    let second = compact_bytes(&first, true, true).unwrap();
    assert_eq!(first, second);
}

#[test]
fn corrupt_input_rejected_when_verifying() {
    let mut bytes = build_sample(1, &[]);
    // Flip a byte in the data region (last byte of file is partition data).
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;

    let err = compact_bytes(&bytes, true, false).unwrap_err();
    assert!(
        matches!(err, CompactError::Pcf(pcf::Error::DataHashMismatch)),
        "expected DataHashMismatch, got {err:?}"
    );
}

#[test]
fn format_size_smoke() {
    assert_eq!(format_size(0), "0 B");
    assert_eq!(format_size(1024), "1 KiB");
    assert_eq!(format_size(1536), "1.5 KiB");
}
