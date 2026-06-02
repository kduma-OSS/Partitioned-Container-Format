//! End-to-end tests for the directory <-> archive tooling.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use pfs_ms::{create_archive, extract_archive, update_archive, FsReader, SyncOptions};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique temporary directory, removed on drop (no external dev-dependency).
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("pfs-test-{}-{n}-{nanos}", std::process::id()));
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Collect (relative path -> file content) and the set of directory paths.
fn snapshot_dir(root: &Path) -> (BTreeMap<String, Vec<u8>>, Vec<String>) {
    let mut files = BTreeMap::new();
    let mut dirs = Vec::new();
    fn walk(
        dir: &Path,
        prefix: &str,
        files: &mut BTreeMap<String, Vec<u8>>,
        dirs: &mut Vec<String>,
    ) {
        let mut entries: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap()).collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let name = e.file_name().to_string_lossy().into_owned();
            let rel = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let ft = e.file_type().unwrap();
            if ft.is_dir() {
                dirs.push(rel.clone());
                walk(&e.path(), &rel, files, dirs);
            } else if ft.is_file() {
                files.insert(rel, fs::read(e.path()).unwrap());
            }
        }
    }
    walk(root, "", &mut files, &mut dirs);
    dirs.sort();
    (files, dirs)
}

fn write(path: &Path, content: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::File::create(path).unwrap().write_all(content).unwrap();
}

fn head_seq(archive: &Path) -> u64 {
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(archive)
        .unwrap();
    let mut r = FsReader::open(f).unwrap();
    r.list_sessions()
        .unwrap()
        .iter()
        .map(|s| s.session_seq)
        .max()
        .unwrap()
}

#[test]
fn create_then_extract_roundtrips() {
    let tmp = TempDir::new();
    let src = tmp.path().join("src");
    let archive = tmp.path().join("a.pfs");
    let out = tmp.path().join("out");

    write(&src.join("readme.md"), b"top-level\n");
    write(&src.join("docs/guide.txt"), b"a guide\n");
    write(&src.join("docs/deep/nested.bin"), &[0u8, 1, 2, 3, 4, 5]);
    fs::create_dir_all(src.join("empty")).unwrap(); // an empty directory

    create_archive(&archive, &src, &SyncOptions::default()).unwrap();
    extract_archive(&archive, &out, None, true).unwrap();

    let (sf, sd) = snapshot_dir(&src);
    let (of, od) = snapshot_dir(&out);
    assert_eq!(sf, of, "file set/content must match");
    assert_eq!(sd, od, "directory set must match (incl. the empty dir)");
}

#[test]
fn create_rejects_existing_archive() {
    let tmp = TempDir::new();
    let src = tmp.path().join("src");
    write(&src.join("f"), b"x");
    let archive = tmp.path().join("a.pfs");
    create_archive(&archive, &src, &SyncOptions::default()).unwrap();
    // Second create on the same path must fail.
    assert!(create_archive(&archive, &src, &SyncOptions::default()).is_err());
}

#[test]
fn update_adds_and_modifies() {
    let tmp = TempDir::new();
    let src = tmp.path().join("src");
    let archive = tmp.path().join("a.pfs");
    let out = tmp.path().join("out");

    write(&src.join("a.txt"), b"v1\n");
    create_archive(&archive, &src, &SyncOptions::default()).unwrap();

    write(&src.join("a.txt"), b"v2 changed\n");
    write(&src.join("sub/b.txt"), b"new file\n");
    update_archive(&archive, &src, &SyncOptions::default()).unwrap();

    extract_archive(&archive, &out, None, true).unwrap();
    assert_eq!(fs::read(out.join("a.txt")).unwrap(), b"v2 changed\n");
    assert_eq!(fs::read(out.join("sub/b.txt")).unwrap(), b"new file\n");
}

#[test]
fn update_with_delete_mirrors_removals() {
    let tmp = TempDir::new();
    let src = tmp.path().join("src");
    let archive = tmp.path().join("a.pfs");
    let out = tmp.path().join("out");

    write(&src.join("keep.txt"), b"keep\n");
    write(&src.join("gone.txt"), b"gone\n");
    create_archive(&archive, &src, &SyncOptions::default()).unwrap();

    fs::remove_file(src.join("gone.txt")).unwrap();
    let opts = SyncOptions {
        delete: true,
        ..SyncOptions::default()
    };
    update_archive(&archive, &src, &opts).unwrap();

    extract_archive(&archive, &out, None, true).unwrap();
    assert!(out.join("keep.txt").exists());
    assert!(
        !out.join("gone.txt").exists(),
        "mirror must remove deleted files"
    );
}

#[test]
fn extract_point_in_time() {
    let tmp = TempDir::new();
    let src = tmp.path().join("src");
    let archive = tmp.path().join("a.pfs");
    let out_old = tmp.path().join("old");
    let out_new = tmp.path().join("new");

    write(&src.join("a.txt"), b"original\n");
    create_archive(&archive, &src, &SyncOptions::default()).unwrap();
    let seq_after_create = head_seq(&archive);

    write(&src.join("a.txt"), b"updated\n");
    update_archive(&archive, &src, &SyncOptions::default()).unwrap();

    extract_archive(&archive, &out_old, Some(seq_after_create), true).unwrap();
    extract_archive(&archive, &out_new, None, true).unwrap();
    assert_eq!(fs::read(out_old.join("a.txt")).unwrap(), b"original\n");
    assert_eq!(fs::read(out_new.join("a.txt")).unwrap(), b"updated\n");
}

#[test]
fn no_op_update_commits_no_session() {
    let tmp = TempDir::new();
    let src = tmp.path().join("src");
    let archive = tmp.path().join("a.pfs");
    write(&src.join("a.txt"), b"same\n");
    create_archive(&archive, &src, &SyncOptions::default()).unwrap();
    let before = head_seq(&archive);
    // Re-running update with no changes must not add a session.
    update_archive(&archive, &src, &SyncOptions::default()).unwrap();
    assert_eq!(head_seq(&archive), before);
}

#[cfg(unix)]
#[test]
fn metadata_mode_is_preserved_and_skippable() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new();
    let src = tmp.path().join("src");
    let archive = tmp.path().join("a.pfs");
    let out = tmp.path().join("out");
    let out_no = tmp.path().join("out_no");

    write(&src.join("secret.txt"), b"x\n");
    fs::set_permissions(src.join("secret.txt"), fs::Permissions::from_mode(0o640)).unwrap();

    create_archive(&archive, &src, &SyncOptions::default()).unwrap();
    extract_archive(&archive, &out, None, true).unwrap();
    let mode = fs::metadata(out.join("secret.txt"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o640);

    // With metadata restore disabled the bits are not forced.
    extract_archive(&archive, &out_no, None, false).unwrap();
    assert_eq!(fs::read(out_no.join("secret.txt")).unwrap(), b"x\n");
}
