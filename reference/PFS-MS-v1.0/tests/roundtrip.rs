//! End-to-end tests for the `pfs-ms` reference crate.

use std::io::Cursor;

use pcf::{Container, HashAlgo};
use pfs_ms::{FsReader, FsWriter};

/// Build the Section 17 three-session scenario in memory and return the bytes.
fn build_spec_scenario() -> Vec<u8> {
    let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
    // Session 2: create docs/ and hello.txt v1.
    w.mkdir("docs").unwrap();
    w.put_file("docs/hello.txt", b"Hello\n").unwrap();
    // Session: modify hello.txt to v2 (DELTA territory).
    w.put_file("docs/hello.txt", b"Hello, world\n").unwrap();
    // Final: rename docs -> documents, delete hello.txt.
    w.mv("docs", "documents").unwrap();
    w.rm("documents/hello.txt").unwrap();
    w.into_storage().into_inner()
}

#[test]
fn spec_scenario_reconstructs_at_head() {
    let bytes = build_spec_scenario();
    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    r.verify().unwrap();

    let tree = r.tree().unwrap();
    // The root has exactly one live child: the renamed directory.
    let root_kids: Vec<String> = {
        let root = pfs_ms::ROOT_NODE_ID;
        tree.children[&root]
            .iter()
            .map(|id| tree.nodes[id].name_str())
            .collect()
    };
    assert_eq!(root_kids, vec!["documents".to_string()]);

    // hello.txt is not live at the head.
    assert!(r.read_path("documents/hello.txt").is_err());
}

#[test]
fn history_query_as_of_earlier_session() {
    let bytes = build_spec_scenario();
    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();

    // Find the session_seq at which hello.txt held "Hello, world\n".
    // Sessions: 1 mkfs root, 2 mkdir docs, 3 put v1, 4 put v2, 5 mv, 6 rm.
    let v2 = r.read_path_as_of("docs/hello.txt", Some(4)).unwrap();
    assert_eq!(v2, b"Hello, world\n");

    let v1 = r.read_path_as_of("docs/hello.txt", Some(3)).unwrap();
    assert_eq!(v1, b"Hello\n");
}

#[test]
fn delta_and_direct_reconstruct_correctly() {
    let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
    let v1 = b"the quick brown fox jumps over the lazy dog\n".repeat(20);
    let v2 = {
        let mut s = v1.clone();
        s.extend_from_slice(b"...with a small appended change\n");
        s
    };
    w.put_file("f.txt", &v1).unwrap();
    w.put_file("f.txt", &v2).unwrap(); // should pick DELTA (small patch)
    let bytes = w.into_storage().into_inner();

    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    r.verify().unwrap();
    assert_eq!(r.read_path("f.txt").unwrap(), v2);
}

#[test]
fn large_compressible_file_roundtrips() {
    // A large, highly compressible payload exercises the DEFLATE content path
    // end to end (write -> store compressed -> read -> decompress).
    let payload = b"0123456789abcdef".repeat(4096); // 64 KiB, very compressible
    let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
    w.put_file("data.bin", &payload).unwrap();
    // Modify it; the new version is also compressed (DIRECT or DELTA).
    let mut payload2 = payload.clone();
    payload2.extend_from_slice(b"tail");
    w.put_file("data.bin", &payload2).unwrap();
    let bytes = w.into_storage().into_inner();

    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    r.verify().unwrap();
    assert_eq!(r.read_path("data.bin").unwrap(), payload2);
}

#[test]
fn move_file_preserves_bytes_via_inherit() {
    let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
    w.mkdir("a").unwrap();
    w.mkdir("b").unwrap();
    w.put_file("a/note.txt", b"keep me\n").unwrap();
    w.mv("a/note.txt", "b/renamed.txt").unwrap();
    let bytes = w.into_storage().into_inner();

    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    r.verify().unwrap();
    assert_eq!(r.read_path("b/renamed.txt").unwrap(), b"keep me\n");
    assert!(r.read_path("a/note.txt").is_err());
}

#[test]
fn directory_delete_is_recursive_by_ancestry() {
    let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
    w.mkdir("d").unwrap();
    w.put_file("d/x.txt", b"x\n").unwrap();
    w.put_file("d/y.txt", b"y\n").unwrap();
    w.rm("d").unwrap(); // single tombstone removes the whole subtree
    let bytes = w.into_storage().into_inner();

    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    r.verify().unwrap();
    let tree = r.tree().unwrap();
    assert!(tree.children[&pfs_ms::ROOT_NODE_ID].is_empty());
    assert!(r.read_path("d/x.txt").is_err());
}

#[test]
fn resurrection_reuses_node_id_path() {
    let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
    w.put_file("z.txt", b"first\n").unwrap();
    w.rm("z.txt").unwrap();
    w.put_file("z.txt", b"second\n").unwrap(); // fresh node at same path
    let bytes = w.into_storage().into_inner();

    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    r.verify().unwrap();
    assert_eq!(r.read_path("z.txt").unwrap(), b"second\n");
}

#[test]
fn reopen_and_append_more_sessions() {
    let bytes = {
        let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
        w.put_file("a.txt", b"alpha\n").unwrap();
        w.into_storage().into_inner()
    };
    // Reopen and append.
    let bytes = {
        let mut w = FsWriter::open(Cursor::new(bytes)).unwrap();
        w.put_file("b.txt", b"beta\n").unwrap();
        w.into_storage().into_inner()
    };
    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    r.verify().unwrap();
    assert_eq!(r.read_path("a.txt").unwrap(), b"alpha\n");
    assert_eq!(r.read_path("b.txt").unwrap(), b"beta\n");
}

#[test]
fn multi_block_session_spans_overflow_blocks() {
    // A single session that introduces > 255 partitions must use several
    // Table Blocks (Section 6.1). Build it via the low-level commit API.
    let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();

    let root = pfs_ms::ROOT_NODE_ID;
    let mut parts = Vec::new();
    for i in 0..600u32 {
        let rec = pfs_ms::NodeRecord {
            kind: pfs_ms::KIND_FILE,
            flags: 0,
            node_id: pfs_ms::new_id(),
            parent_id: root,
            mtime_unix_ms: 0,
            mode: 0,
            name: format!("file{i:04}.txt").into_bytes(),
            content: Some(pfs_ms::ContentSection::Empty),
        };
        parts.push(pfs_ms::Partition::node(pfs_ms::new_id(), &rec));
    }
    w.commit(parts, pfs_ms::new_id(), 600, 0, b"bulk").unwrap();
    let bytes = w.into_storage().into_inner();

    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    r.verify().unwrap();
    let tree = r.tree().unwrap();
    assert_eq!(tree.children[&root].len(), 600);

    // The bulk session must report block_count >= 3 (1 HEAD + >= 2 members).
    let sessions = r.list_sessions().unwrap();
    let bulk = sessions.iter().find(|s| s.writer == b"bulk").unwrap();
    assert!(bulk.block_count >= 3, "block_count = {}", bulk.block_count);
}

#[test]
fn a_pfs_file_is_a_valid_pcf_file() {
    // A generic PCF reader must enumerate every partition across all sessions
    // as a flat, valid set, and verify every table_hash / data_hash.
    let bytes = build_spec_scenario();
    let mut c = Container::open(Cursor::new(bytes)).unwrap();
    c.verify().unwrap();
    let entries = c.entries().unwrap();
    // At least: 6 sessions worth of PFS_SESSION + the node/content partitions.
    let sessions = entries
        .iter()
        .filter(|e| e.partition_type == pfs_ms::PFS_SESSION_TYPE)
        .count();
    assert_eq!(sessions, 6);
    assert!(entries
        .iter()
        .any(|e| e.partition_type == pfs_ms::PFS_NODE_TYPE));
}

#[test]
fn crash_recovery_truncated_tail_is_invisible() {
    // Bytes written by an interrupted session (after the committed head) are
    // invisible to readers because the header still points at the old head.
    let committed = {
        let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
        w.put_file("a.txt", b"committed\n").unwrap();
        w.into_storage().into_inner()
    };
    let mut with_garbage = committed.clone();
    with_garbage.extend_from_slice(&[0xABu8; 500]); // simulate an aborted append

    let mut r = FsReader::open(Cursor::new(with_garbage)).unwrap();
    r.verify().unwrap();
    assert_eq!(r.read_path("a.txt").unwrap(), b"committed\n");
}
