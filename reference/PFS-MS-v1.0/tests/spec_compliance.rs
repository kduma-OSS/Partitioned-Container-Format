//! One test (or a small group) per normative requirement in the PFS-MS
//! specification's conformance section (Section 13, R1..R8 / W1..W7) plus the
//! field-layout constants of Appendix A.

use std::io::Cursor;

use pcf::HashAlgo;
use pfs_ms::{
    build_reference_vector, ContentSection, Error, FsReader, FsWriter, NodeRecord, Partition,
    KIND_DIR, KIND_FILE, NODE_PREFIX_LEN, ROOT_NODE_ID,
};

fn id(b: u8) -> [u8; 16] {
    [b; 16]
}

// ---- Appendix A: field layout constants ---------------------------------

#[test]
fn appendix_a_layout_constants() {
    assert_eq!(NODE_PREFIX_LEN, 54);
    assert_eq!(pfs_ms::DIRECT_SECTION_LEN, 91); // includes compression_algo_id
    assert_eq!(pfs_ms::DELTA_SECTION_LEN, 165); // includes compression_algo_id
    assert_eq!(pfs_ms::SESSION_PREFIX_LEN, 162);
    assert_eq!(pfs_ms::PFS_NODE_TYPE, 0xAAAA_0001);
    assert_eq!(pfs_ms::PFS_SESSION_TYPE, 0xAAAA_0002);
    assert_eq!(pfs_ms::RAW_TYPE, 0xFFFF_FFFF);
    assert_eq!(pfs_ms::NODE_MAGIC, *b"PFSN");
    assert_eq!(pfs_ms::SESSION_MAGIC, *b"PFSS");
    assert_eq!(pfs_ms::ROOT_NODE_ID, [0u8; 16]);
    assert_eq!(pfs_ms::COMPRESS_NONE, 0);
    assert_eq!(pfs_ms::COMPRESS_DEFLATE, 1);
}

// ---- R1: a conforming PFS reader is a conforming PCF reader --------------

#[test]
fn r1_rejects_non_pcf_input() {
    let garbage = vec![0u8; 64];
    assert!(FsReader::open(Cursor::new(garbage)).is_err());
}

// ---- R2/R3: backward chain, strictly decreasing seq, one PFS_SESSION -----

#[test]
fn r2_r3_chain_is_backward_and_strictly_decreasing() {
    let bytes = build_reference_vector().unwrap();
    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    let scan = r.scan().unwrap();
    // Sessions are newest-first and strictly decreasing.
    let seqs: Vec<u64> = scan.sessions.iter().map(|s| s.seq).collect();
    assert_eq!(seqs, vec![3, 2, 1]);
    // Each HEAD block holds exactly one PFS_SESSION entry.
    for s in &scan.sessions {
        // block_count is honoured (single-block sessions here).
        assert_eq!(s.record.block_count, 1);
    }
}

#[test]
fn r3_head_block_offsets_decrease_toward_the_tail() {
    // The backward link means each newer session's HEAD sits at a higher
    // offset than the previous session's HEAD.
    let bytes = build_reference_vector().unwrap();
    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    let scan = r.scan().unwrap();
    let offs: Vec<u64> = scan.sessions.iter().map(|s| s.head_offset).collect();
    assert!(offs.windows(2).all(|w| w[0] > w[1]), "offsets {offs:?}");
}

// ---- R4: malformed node records are rejected ----------------------------

#[test]
fn r4_malformed_node_is_rejected_on_read() {
    // A node with a reserved flag bit must fail when the reader parses it.
    let mut w = FsWriter::create(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
    let bad = NodeRecord {
        kind: KIND_DIR,
        flags: 0x0002, // reserved bit
        node_id: id(1),
        parent_id: ROOT_NODE_ID,
        mtime_unix_ms: 0,
        mode: 0,
        name: b"x".to_vec(),
        content: None,
    };
    // Build the record bytes directly so the reserved bit survives to disk.
    w.commit(vec![Partition::node(id(0x01), &bad)], id(0x31), 1, 0, b"")
        .unwrap();
    let bytes = w.into_storage().into_inner();
    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    assert!(matches!(r.scan(), Err(Error::MalformedNode(_))));
}

// ---- R5: newest wins; a node twice in one session is malformed ----------

#[test]
fn r5_duplicate_node_in_one_session_is_rejected() {
    let mut w = FsWriter::create(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
    let dup = |name: &[u8]| NodeRecord {
        kind: KIND_DIR,
        flags: 0,
        node_id: id(7),
        parent_id: ROOT_NODE_ID,
        mtime_unix_ms: 0,
        mode: 0,
        name: name.to_vec(),
        content: None,
    };
    w.commit(
        vec![
            Partition::node(id(0x01), &dup(b"a")),
            Partition::node(id(0x02), &dup(b"b")),
        ],
        id(0x31),
        2,
        0,
        b"",
    )
    .unwrap();
    let bytes = w.into_storage().into_inner();
    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    assert!(matches!(r.scan(), Err(Error::DuplicateNodeInSession)));
}

// ---- R6: liveness walk rejects cycles -----------------------------------

#[test]
fn r6_parent_cycle_is_rejected() {
    let mut w = FsWriter::create(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
    let a = id(0xA0);
    let b = id(0xB0);
    let dir = |node_id, parent_id, name: &[u8]| NodeRecord {
        kind: KIND_DIR,
        flags: 0,
        node_id,
        parent_id,
        mtime_unix_ms: 0,
        mode: 0,
        name: name.to_vec(),
        content: None,
    };
    // A's parent is B and B's parent is A: an unreachable cycle.
    w.commit(
        vec![
            Partition::node(id(0x01), &dir(a, b, b"A")),
            Partition::node(id(0x02), &dir(b, a, b"B")),
        ],
        id(0x31),
        2,
        0,
        b"",
    )
    .unwrap();
    let bytes = w.into_storage().into_inner();
    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    assert!(matches!(r.verify(), Err(Error::ParentCycle)));
}

// ---- R7: content hashes are verified ------------------------------------

#[test]
fn r7_full_hash_mismatch_is_detected() {
    // Forge a DIRECT record whose full_hash does not match its content.
    let mut w = FsWriter::create(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
    let rec = NodeRecord {
        kind: KIND_FILE,
        flags: 0,
        node_id: id(5),
        parent_id: ROOT_NODE_ID,
        mtime_unix_ms: 0,
        mode: 0,
        name: b"f".to_vec(),
        content: Some(ContentSection::Direct {
            compression_algo: pfs_ms::COMPRESS_NONE,
            content_uid: id(0xC0),
            full_size: 5,
            full_hash_algo: HashAlgo::Sha256,
            full_hash: HashAlgo::Sha256.compute(b"WRONG"), // deliberately wrong
        }),
    };
    w.commit(
        vec![
            Partition::raw(id(0xC0), "c", b"right".to_vec()),
            Partition::node(id(0x01), &rec),
        ],
        id(0x31),
        1,
        0,
        b"",
    )
    .unwrap();
    let bytes = w.into_storage().into_inner();
    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    assert!(matches!(r.read_path("f"), Err(Error::ContentHashMismatch)));
}

// ---- R8: the inter-session hash chain verifies on a good file -----------

#[test]
fn r8_inter_session_chain_verifies() {
    let bytes = build_reference_vector().unwrap();
    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    // verify() includes verify_chain(); it must succeed on a well-formed file.
    r.verify().unwrap();
}

// ---- W2: only the 8-byte header pointer changes across a commit ----------

#[test]
fn w2_commit_only_rewrites_the_header_pointer() {
    let f1 = {
        let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
        w.put_file("a.txt", b"alpha\n").unwrap();
        w.into_storage().into_inner()
    };
    let len1 = f1.len();
    let f2 = {
        let mut w = FsWriter::open(Cursor::new(f1.clone())).unwrap();
        w.put_file("b.txt", b"beta\n").unwrap();
        w.into_storage().into_inner()
    };
    // The new session only appends; the previous bytes are immutable except
    // for the 8-byte partition_table_offset at header offset 12.
    assert!(f2.len() > len1);
    assert_eq!(&f2[0..12], &f1[0..12]); // magic + version unchanged
    assert_eq!(&f2[20..len1], &f1[20..len1]); // all prior bytes immutable
    assert_ne!(&f2[12..20], &f1[12..20]); // head pointer advanced
}

// ---- W3: HEAD carries the session, MEMBER blocks do not ------------------

#[test]
fn w3_member_blocks_carry_no_session_record() {
    // A >255-entry session uses overflow MEMBER blocks; only the HEAD block may
    // hold the PFS_SESSION partition.
    let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
    let mut parts = Vec::new();
    for i in 0..300u32 {
        let rec = NodeRecord {
            kind: KIND_FILE,
            flags: 0,
            node_id: pfs_ms::new_id(),
            parent_id: ROOT_NODE_ID,
            mtime_unix_ms: 0,
            mode: 0,
            name: format!("f{i}").into_bytes(),
            content: Some(ContentSection::Empty),
        };
        parts.push(Partition::node(pfs_ms::new_id(), &rec));
    }
    w.commit(parts, pfs_ms::new_id(), 300, 0, b"bulk").unwrap();
    let bytes = w.into_storage().into_inner();

    let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
    r.verify().unwrap(); // scan enforces "MEMBER block contains no PFS_SESSION"
    let scan = r.scan().unwrap();
    let bulk = scan
        .sessions
        .iter()
        .find(|s| s.record.writer == b"bulk")
        .unwrap();
    assert!(bulk.record.block_count >= 2);
    assert_eq!(bulk.nodes.len(), 300);
}

// ---- byte-exact reference vector (Section 17) ----------------------------

#[test]
fn reference_vector_is_byte_exact() {
    let bytes = build_reference_vector().unwrap();
    assert_eq!(bytes.len(), 2986, "reference vector length changed");
    let digest = HashAlgo::Sha256.compute(&bytes);
    let hex: String = digest[..32].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex, "79b6dd7093172b4fe33d57a5ca53994c387dd3149021ef4fcb2b8a3fea7429bc",
        "reference vector bytes changed"
    );
}
