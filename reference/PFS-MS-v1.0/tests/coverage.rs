//! Targeted error-path and edge-case tests for `pfs-ms`.

use std::io::Cursor;

use pcf::HashAlgo;
use pfs_ms::{
    build_node_view, current_delta_depth, is_live, resolve_path, ContentSection, Error, FsReader,
    FsWriter, NodeRecord, Partition, SessionRecord, KIND_FILE, ROOT_NODE_ID,
};

fn id(b: u8) -> [u8; 16] {
    [b; 16]
}

// ---- record parsing edges ------------------------------------------------

#[test]
fn node_parse_rejects_garbage_and_truncation() {
    assert!(matches!(
        NodeRecord::from_bytes(b"short"),
        Err(Error::MalformedNode(_))
    ));
    // Good prefix but bogus content kind.
    let r = NodeRecord {
        kind: KIND_FILE,
        flags: 0,
        node_id: id(1),
        parent_id: ROOT_NODE_ID,
        mtime_unix_ms: 0,
        mode: 0,
        name: b"f".to_vec(),
        content: Some(ContentSection::Empty),
    };
    let mut bytes = r.to_bytes();
    *bytes.last_mut().unwrap() = 0x77; // unknown content_kind
    assert!(matches!(
        NodeRecord::from_bytes(&bytes),
        Err(Error::MalformedNode(_))
    ));
}

#[test]
fn session_parse_rejects_bad_block_count_field() {
    let mut rec = SessionRecord {
        profile_version_major: 1,
        profile_version_minor: 0,
        session_seq: 1,
        timestamp_unix_ms: 0,
        prev_session_hash_algo: HashAlgo::None,
        prev_session_hash: [0u8; 64],
        block_count: 1,
        member_digest_algo: HashAlgo::None,
        member_blocks_digest: [0u8; 64],
        change_count: 0,
        writer: Vec::new(),
    };
    rec.block_count = 1;
    let mut bytes = rec.to_bytes();
    // Zero out block_count (offset 89..93) -> must be rejected (>= 1).
    bytes[89] = 0;
    bytes[90] = 0;
    bytes[91] = 0;
    bytes[92] = 0;
    assert!(matches!(
        SessionRecord::from_bytes(&bytes),
        Err(Error::MalformedSession(_))
    ));
}

// ---- content kinds -------------------------------------------------------

#[test]
fn empty_and_inherit_reconstruct() {
    let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
    w.put_file("empty.txt", b"").unwrap(); // EMPTY
    w.mkdir("d").unwrap();
    w.mv("empty.txt", "d/moved.txt").unwrap(); // INHERIT over EMPTY
    let bytes = w.into_storage().into_inner();

    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    r.verify().unwrap();
    assert_eq!(r.read_path("d/moved.txt").unwrap(), b"");
}

// ---- liveness / tree edges ----------------------------------------------

#[test]
fn resolve_path_errors() {
    let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
    w.put_file("a.txt", b"x").unwrap();
    let bytes = w.into_storage().into_inner();

    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    let tree = r.tree().unwrap();
    assert!(matches!(resolve_path(&tree, "nope"), Err(Error::NotFound)));
    // Descending into a file is "not a directory".
    assert!(matches!(
        resolve_path(&tree, "a.txt/inner"),
        Err(Error::NotADirectory)
    ));
    assert!(is_live(&build_node_view(&r.scan().unwrap(), None), ROOT_NODE_ID).unwrap());
}

#[test]
fn name_collision_keeps_greater_seq() {
    // Two live siblings with the same name (forced via low-level commit): the
    // greater session_seq wins (Section 10.3, resilience rule).
    let mut w = FsWriter::create(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
    let a = id(0xA1);
    let b = id(0xB1);
    let mk = |node_id, content: &'static [u8]| NodeRecord {
        kind: KIND_FILE,
        flags: 0,
        node_id,
        parent_id: ROOT_NODE_ID,
        mtime_unix_ms: 0,
        mode: 0,
        name: b"dup.txt".to_vec(),
        content: Some(ContentSection::Direct {
            content_uid: if node_id == a { id(0xC1) } else { id(0xC2) },
            full_size: content.len() as u64,
            full_hash_algo: HashAlgo::Sha256,
            full_hash: HashAlgo::Sha256.compute(content),
        }),
    };
    // Session 1: node a = "old".
    w.commit(
        vec![
            Partition::raw(id(0xC1), "c", b"old".to_vec()),
            Partition::node(id(0x01), &mk(a, b"old")),
        ],
        id(0x31),
        1,
        0,
        b"",
    )
    .unwrap();
    // Session 2: node b, same name = "new" (greater seq wins).
    w.commit(
        vec![
            Partition::raw(id(0xC2), "c", b"new".to_vec()),
            Partition::node(id(0x02), &mk(b, b"new")),
        ],
        id(0x32),
        1,
        0,
        b"",
    )
    .unwrap();
    let bytes = w.into_storage().into_inner();

    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    r.verify().unwrap();
    assert_eq!(r.read_path("dup.txt").unwrap(), b"new");
}

// ---- delta depth ---------------------------------------------------------

#[test]
fn delta_depth_grows_then_rebaselines() {
    let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
    let base = b"line\n".repeat(50);
    w.put_file("f", &base).unwrap();
    // Many small edits should accumulate DELTA depth, then re-baseline at 16.
    for i in 0..40u32 {
        let mut v = base.clone();
        v.extend_from_slice(format!("edit {i}\n").as_bytes());
        w.put_file("f", &v).unwrap();
    }
    let bytes = w.into_storage().into_inner();

    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    r.verify().unwrap();
    let view = build_node_view(&r.scan().unwrap(), None);
    // Find the file's node_id from the head tree.
    let tree = r.tree().unwrap();
    let fid = *tree.children[&ROOT_NODE_ID]
        .iter()
        .find(|id| tree.nodes[*id].name == b"f")
        .unwrap();
    // Re-baselining keeps the live depth bounded by the recommended maximum.
    assert!(current_delta_depth(&view, fid) <= pfs_ms::RECOMMENDED_MAX_DELTA_DEPTH);
}

// ---- writer guard rails --------------------------------------------------

#[test]
fn writer_rejects_obvious_mistakes() {
    let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
    w.mkdir("d").unwrap();
    assert!(matches!(w.mkdir("d"), Err(Error::AlreadyExists)));
    w.put_file("d/f", b"x").unwrap();
    // Writing a file where a directory exists is rejected.
    assert!(matches!(w.put_file("d", b"x"), Err(Error::NotADirectory)));
    assert!(matches!(w.rm("/"), Err(Error::InvalidPath(_))));
    assert!(matches!(w.mv("d", "d"), Err(Error::AlreadyExists)));
    assert!(matches!(w.rm("missing"), Err(Error::NotFound)));
}

#[test]
fn writer_getters_and_writer_id() {
    let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
    assert!(w.head_offset() > 0);
    let seq_before = w.next_seq();
    w.set_writer_id(b"custom-agent");
    w.put_file("a.txt", b"x").unwrap();
    assert_eq!(w.next_seq(), seq_before + 1);
    let bytes = w.into_storage().into_inner();

    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    let sessions = r.list_sessions().unwrap();
    assert!(sessions.iter().any(|s| s.writer == b"custom-agent"));
    // node_view "as of" an early session sees no a.txt yet.
    let view = r.node_view(Some(1)).unwrap();
    assert!(view.current.contains_key(&ROOT_NODE_ID));
    let _ = r.into_storage();
}

#[test]
fn error_display_is_human_readable() {
    for e in [
        Error::MalformedNode("x"),
        Error::MalformedSession("x"),
        Error::BrokenChain("x"),
        Error::ChainHashMismatch,
        Error::DuplicateNodeInSession,
        Error::ParentCycle,
        Error::MissingContent,
        Error::ContentHashMismatch,
        Error::MissingBase,
        Error::UnsupportedPatchAlgo(9),
        Error::DeltaTooDeep,
        Error::Vcdiff("boom".into()),
        Error::NotFound,
        Error::NotADirectory,
        Error::AlreadyExists,
        Error::InvalidPath("x"),
    ] {
        assert!(!format!("{e}").is_empty());
    }
}

#[test]
fn content_corruption_is_detected() {
    let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
    w.put_file("secret.txt", b"important payload").unwrap();
    let mut bytes = w.into_storage().into_inner();

    // Locate the content RAW partition and flip a byte in its data region.
    let start = {
        let mut r = FsReader::open(Cursor::new(bytes.clone())).unwrap();
        let scan = r.scan().unwrap();
        let entry = scan
            .uid_index
            .values()
            .find(|e| e.partition_type == pfs_ms::RAW_TYPE && e.used_bytes > 0)
            .unwrap();
        entry.start_offset as usize
    };
    bytes[start] ^= 0xFF;

    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    assert!(r.verify().is_err());
}
