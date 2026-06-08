//! Tests for PFS-MS-aware compaction (`pfs_ms::compact`): a multi-session file
//! is rebuilt into a single fresh session that still reconstructs the same live
//! tree, while history (deleted nodes, superseded versions, deltas) is dropped.

use std::io::Cursor;

use pcf::HashAlgo;
use pfs_ms::{compact, Change, FsReader, FsWriter, ROOT_NODE_ID};

/// Build a multi-session source exercising: a delta (file written twice), an
/// empty directory, an empty file, nested directories, explicit mode/mtime,
/// and a deleted subtree. Returns the file bytes.
fn build_source() -> Vec<u8> {
    let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
    w.mkdir("docs").unwrap(); // session 2
    w.put_file("docs/f.txt", b"version one\n").unwrap(); // session 3
                                                         // Larger second version so the writer stores it as a DELTA against v1.
    let v2 = b"version two, substantially longer to invite a delta encode\n".repeat(8);
    w.put_file("docs/f.txt", &v2).unwrap(); // session 4

    // One session carrying explicit metadata, an empty dir, an empty file, and
    // a nested directory.
    w.commit_changes(&[
        Change::Mkdir {
            path: "empty".into(),
            mode: 0o755,
            mtime_unix_ms: 1111,
        },
        Change::Mkdir {
            path: "a".into(),
            mode: 0o700,
            mtime_unix_ms: 2000,
        },
        Change::Mkdir {
            path: "a/b".into(),
            mode: 0o700,
            mtime_unix_ms: 2100,
        },
        Change::Mkdir {
            path: "a/b/c".into(),
            mode: 0o700,
            mtime_unix_ms: 2222,
        },
        Change::PutFile {
            path: "a/b/note.txt".into(),
            content: b"deep".to_vec(),
            mode: 0o640,
            mtime_unix_ms: 3333,
        },
        Change::PutFile {
            path: "blank.txt".into(),
            content: Vec::new(),
            mode: 0o600,
            mtime_unix_ms: 4444,
        },
    ])
    .unwrap(); // session 5

    // A subtree that is later deleted; it must not survive compaction.
    w.mkdir("trash").unwrap(); // session 6
    w.put_file("trash/junk.txt", b"goodbye").unwrap(); // session 7
    w.rm("trash").unwrap(); // session 8

    w.into_storage().into_inner()
}

/// All live paths in a file, sorted (directories and files, root excluded).
fn live_paths(bytes: &[u8]) -> Vec<String> {
    let mut r = FsReader::open(Cursor::new(bytes.to_vec())).unwrap();
    let tree = r.tree().unwrap();
    let mut out = Vec::new();
    fn walk(tree: &pfs_ms::Tree, node: [u8; 16], prefix: &str, out: &mut Vec<String>) {
        if let Some(kids) = tree.children.get(&node) {
            for &cid in kids {
                let rec = &tree.nodes[&cid];
                let name = rec.name_str();
                let rel = if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                };
                let tag = if rec.is_dir() { "d" } else { "f" };
                out.push(format!("{tag} {rel}"));
                if rec.is_dir() {
                    walk(tree, cid, &rel, out);
                }
            }
        }
    }
    walk(&tree, ROOT_NODE_ID, "", &mut out);
    out.sort();
    out
}

#[test]
fn compact_multi_session_roundtrip() {
    let src = build_source();
    let out = compact(Cursor::new(src.clone()), Cursor::new(Vec::new()))
        .unwrap()
        .into_inner();

    // The output is a valid PFS-MS file with exactly one session.
    let mut r = FsReader::open(Cursor::new(out.clone())).unwrap();
    r.verify().unwrap();
    let sessions = r.list_sessions().unwrap();
    assert_eq!(sessions.len(), 1, "compaction must yield a single session");
    let s = &sessions[0];
    assert_eq!(s.session_seq, 1);
    assert_eq!(s.prev_session_hash, [0u8; 64]);
    assert_eq!(s.prev_session_hash_algo, HashAlgo::None);

    // Same live tree as the source (deleted `trash` is gone).
    assert_eq!(live_paths(&out), live_paths(&src));
    assert!(
        live_paths(&out).iter().all(|p| !p.contains("trash")),
        "deleted subtree must not survive"
    );

    // File contents match the latest source versions; empty file stays empty.
    let v2 = b"version two, substantially longer to invite a delta encode\n".repeat(8);
    assert_eq!(r.read_path("docs/f.txt").unwrap(), v2);
    assert_eq!(r.read_path("a/b/note.txt").unwrap(), b"deep");
    assert_eq!(r.read_path("blank.txt").unwrap(), b"");
}

#[test]
fn compact_preserves_mode_and_mtime() {
    let src = build_source();
    let out = compact(Cursor::new(src), Cursor::new(Vec::new()))
        .unwrap()
        .into_inner();

    let mut r = FsReader::open(Cursor::new(out)).unwrap();
    let tree = r.tree().unwrap();
    let by_path = |path: &str| -> pfs_ms::NodeRecord {
        let id = pfs_ms::resolve_path(&tree, path).unwrap();
        tree.nodes[&id].clone()
    };
    assert_eq!(by_path("empty").mode, 0o755);
    assert_eq!(by_path("empty").mtime_unix_ms, 1111);
    assert_eq!(by_path("a/b/c").mode, 0o700);
    assert_eq!(by_path("a/b/note.txt").mode, 0o640);
    assert_eq!(by_path("a/b/note.txt").mtime_unix_ms, 3333);
    assert_eq!(by_path("blank.txt").mode, 0o600);
}

#[test]
fn compact_preserves_hash_algo() {
    // Source built with a non-default algo; the compacted file must keep it.
    let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Blake3).unwrap();
    w.mkdir("d").unwrap();
    w.put_file("d/f", b"hi").unwrap();
    let src = w.into_storage().into_inner();

    let out = compact(Cursor::new(src), Cursor::new(Vec::new()))
        .unwrap()
        .into_inner();

    // Inspect the head block's table_hash_algo via PCF.
    let mut c = pcf::Container::open(Cursor::new(out)).unwrap();
    let head = c.table_head();
    let algo = c.read_block_at(head).unwrap().header.table_hash_algo;
    assert_eq!(algo, HashAlgo::Blake3);
}

#[test]
fn compact_empty_tree() {
    // A file whose only content has been removed compacts to an empty tree.
    let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
    w.put_file("x.txt", b"data").unwrap();
    w.rm("x.txt").unwrap();
    let src = w.into_storage().into_inner();

    let out = compact(Cursor::new(src), Cursor::new(Vec::new()))
        .unwrap()
        .into_inner();

    FsReader::open(Cursor::new(out.clone()))
        .unwrap()
        .verify()
        .unwrap();
    assert!(live_paths(&out).is_empty());
}

#[test]
fn compact_is_idempotent() {
    let src = build_source();
    let once = compact(Cursor::new(src), Cursor::new(Vec::new()))
        .unwrap()
        .into_inner();
    let twice = compact(Cursor::new(once.clone()), Cursor::new(Vec::new()))
        .unwrap()
        .into_inner();

    FsReader::open(Cursor::new(twice.clone()))
        .unwrap()
        .verify()
        .unwrap();
    assert_eq!(live_paths(&twice), live_paths(&once));
}

#[test]
fn compact_reclaims_space() {
    let src = build_source();
    let out = compact(Cursor::new(src.clone()), Cursor::new(Vec::new()))
        .unwrap()
        .into_inner();
    assert!(
        out.len() < src.len(),
        "compacted ({}) should be smaller than source ({})",
        out.len(),
        src.len()
    );
}

#[test]
fn compact_rejects_corrupt_source() {
    let mut src = build_source();
    // Flip a byte in the middle (data region) to break a data_hash; the
    // trailing bytes are the PCF trailer, so corrupt those would not trip
    // hash verification.
    let mid = src.len() / 2;
    src[mid] ^= 0xFF;
    let err = compact(Cursor::new(src), Cursor::new(Vec::new()));
    assert!(err.is_err(), "a corrupt source must be rejected");
}

#[test]
fn compact_archive_in_place() {
    let dir = std::env::temp_dir().join(format!("pfs-compact-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("a.pfs");
    std::fs::write(&path, build_source()).unwrap();

    pfs_ms::compact_archive(&path, &path).unwrap();

    let bytes = std::fs::read(&path).unwrap();
    let mut r = FsReader::open(Cursor::new(bytes.clone())).unwrap();
    r.verify().unwrap();
    assert_eq!(r.list_sessions().unwrap().len(), 1);
    assert!(live_paths(&bytes).contains(&"f docs/f.txt".to_string()));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn compact_archive_to_new_file() {
    let dir = std::env::temp_dir().join(format!("pfs-compact-out-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("src.pfs");
    let dst = dir.join("dst.pfs");
    std::fs::write(&src, build_source()).unwrap();

    pfs_ms::compact_archive(&src, &dst).unwrap();

    // Source is untouched (still multi-session); destination is compacted.
    assert!(
        FsReader::open(Cursor::new(std::fs::read(&src).unwrap()))
            .unwrap()
            .list_sessions()
            .unwrap()
            .len()
            > 1
    );
    let out = std::fs::read(&dst).unwrap();
    let mut r = FsReader::open(Cursor::new(out)).unwrap();
    r.verify().unwrap();
    assert_eq!(r.list_sessions().unwrap().len(), 1);

    std::fs::remove_dir_all(&dir).ok();
}
