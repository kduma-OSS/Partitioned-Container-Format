//! The canonical Section 17 reference vector.
//!
//! [`build_reference_vector`] deterministically constructs the three-session
//! scenario from the specification (Section 17) using fixed uids, fixed
//! node_ids, and a zero timestamp, so independent implementations can pin the
//! exact bytes. It uses the low-level [`FsWriter::commit`] API directly (rather
//! than the uuid/clock-driven high-level operations) precisely so the output is
//! reproducible.
//!
//! For illustration the first session stores a DEFLATE-compressed DIRECT
//! content (compression_algo_id = 1), and the second session is emitted as a
//! DELTA regardless of patch size, so the vector exercises both the compression
//! field and the DELTA content-section layout.

use std::io::Cursor;

use pcf::HashAlgo;

use crate::compress::compress_deflate;
use crate::consts::*;
use crate::delta::diff_vcdiff;
use crate::node::{ContentSection, NodeRecord};
use crate::writer::{FsWriter, Partition};
use crate::Result;

const ALGO: HashAlgo = HashAlgo::Sha256;

fn id(b: u8) -> [u8; 16] {
    [b; 16]
}

/// hello.txt v1: a compressible payload so the DIRECT content is stored DEFLATE.
pub(crate) fn demo_v1() -> Vec<u8> {
    b"Hello, PFS-MS! ".repeat(32)
}

/// hello.txt v2: v1 with an appended line, reachable from v1 by a small patch.
pub(crate) fn demo_v2() -> Vec<u8> {
    let mut v = demo_v1();
    v.extend_from_slice(b"...and now, hello world!\n");
    v
}

/// Build the canonical PFS-MS reference file for the Section 17 scenario.
pub fn build_reference_vector() -> Result<Vec<u8>> {
    let node_docs = id(0xD0);
    let node_hello = id(0xF0);

    let mut w = FsWriter::create(Cursor::new(Vec::new()), ALGO)?;

    // ---- Session 1: root, docs/, hello.txt v1 (DIRECT, DEFLATE) ----------
    let v1 = demo_v1();
    let v1_stored = compress_deflate(&v1)?; // smaller than v1; stored compressed
    let root = NodeRecord {
        kind: KIND_DIR,
        flags: 0,
        node_id: ROOT_NODE_ID,
        parent_id: ROOT_NODE_ID,
        mtime_unix_ms: 0,
        mode: 0,
        name: Vec::new(),
        content: None,
    };
    let docs = NodeRecord {
        kind: KIND_DIR,
        flags: 0,
        node_id: node_docs,
        parent_id: ROOT_NODE_ID,
        mtime_unix_ms: 0,
        mode: 0,
        name: b"docs".to_vec(),
        content: None,
    };
    let hello1 = NodeRecord {
        kind: KIND_FILE,
        flags: 0,
        node_id: node_hello,
        parent_id: node_docs,
        mtime_unix_ms: 0,
        mode: 0,
        name: b"hello.txt".to_vec(),
        content: Some(ContentSection::Direct {
            compression_algo: COMPRESS_DEFLATE,
            content_uid: id(0x11),
            full_size: v1.len() as u64,
            full_hash_algo: ALGO,
            full_hash: ALGO.compute(&v1),
        }),
    };
    w.commit(
        vec![
            Partition::raw(id(0x11), "content", v1_stored),
            Partition::node(id(0x21), &root),
            Partition::node(id(0x22), &docs),
            Partition::node(id(0x23), &hello1),
        ],
        id(0x31),
        3,
        0,
        b"",
    )?;

    // ---- Session 2: modify hello.txt to v2 (DELTA, patch stored verbatim) -
    let v2 = demo_v2();
    let patch = diff_vcdiff(&v1, &v2)?;
    let hello2 = NodeRecord {
        kind: KIND_FILE,
        flags: 0,
        node_id: node_hello,
        parent_id: node_docs,
        mtime_unix_ms: 0,
        mode: 0,
        name: b"hello.txt".to_vec(),
        content: Some(ContentSection::Delta {
            patch_algo: PATCH_VCDIFF,
            compression_algo: COMPRESS_NONE,
            patch_uid: id(0x12),
            full_size: v2.len() as u64,
            full_hash_algo: ALGO,
            full_hash: ALGO.compute(&v2),
            base_full_size: v1.len() as u64,
            base_full_hash_algo: ALGO,
            base_full_hash: ALGO.compute(&v1),
        }),
    };
    w.commit(
        vec![
            Partition::raw(id(0x12), "patch", patch),
            Partition::node(id(0x24), &hello2),
        ],
        id(0x32),
        1,
        0,
        b"",
    )?;

    // ---- Session 3: rename docs -> documents, tombstone hello.txt --------
    let documents = NodeRecord {
        kind: KIND_DIR,
        flags: 0,
        node_id: node_docs,
        parent_id: ROOT_NODE_ID,
        mtime_unix_ms: 0,
        mode: 0,
        name: b"documents".to_vec(),
        content: None,
    };
    let hello_tomb = NodeRecord {
        kind: KIND_FILE,
        flags: FLAG_TOMBSTONE,
        node_id: node_hello,
        parent_id: node_docs,
        mtime_unix_ms: 0,
        mode: 0,
        name: b"hello.txt".to_vec(),
        content: None,
    };
    w.commit(
        vec![
            Partition::node(id(0x25), &documents),
            Partition::node(id(0x26), &hello_tomb),
        ],
        id(0x33),
        2,
        0,
        b"",
    )?;

    Ok(w.into_storage().into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FsReader, ROOT_NODE_ID};

    #[test]
    fn reference_vector_is_deterministic() {
        let a = build_reference_vector().unwrap();
        let b = build_reference_vector().unwrap();
        assert_eq!(a, b, "the reference vector must be byte-reproducible");
    }

    #[test]
    fn reference_vector_reconstructs() {
        let bytes = build_reference_vector().unwrap();
        let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
        r.verify().unwrap();
        // At the head: /documents (renamed), hello.txt gone.
        let tree = r.tree().unwrap();
        let kids: Vec<String> = tree.children[&ROOT_NODE_ID]
            .iter()
            .map(|id| tree.nodes[id].name_str())
            .collect();
        assert_eq!(kids, vec!["documents".to_string()]);
        // History query: hello.txt at session 2 reads the v2 payload, decoded
        // from the DELTA patch applied to the DEFLATE-compressed v1 base.
        assert_eq!(
            r.read_path_as_of("docs/hello.txt", Some(2)).unwrap(),
            demo_v2()
        );
    }
}
