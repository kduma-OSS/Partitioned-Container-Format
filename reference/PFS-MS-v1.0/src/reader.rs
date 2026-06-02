//! Reading a PFS-MS file: walk the backward-linked session chain, group blocks
//! into sessions, verify the inter-session hash chain, and build the node view
//! (Sections 8, 10, 11).
//!
//! The core is a set of generic functions over a [`pcf::Container`], so both the
//! owning [`FsReader`] and the writer's mid-commit state snapshot can share
//! them. Block walking reuses [`pcf::Container::read_block_at`].

use std::collections::HashMap;
use std::io::{Read, Seek, Write};

use pcf::{Container, HashAlgo, PartitionEntry};

use crate::consts::*;
use crate::error::{Error, Result};
use crate::node::NodeRecord;
use crate::session::{member_blocks_digest, SessionRecord};

/// One session as recovered from the chain (newest sessions appear first).
#[derive(Debug, Clone)]
pub struct SessionView {
    /// `session_seq` of this session.
    pub seq: u64,
    /// Absolute offset of this session's HEAD block.
    pub head_offset: u64,
    /// The parsed Session Record.
    pub record: SessionRecord,
    /// `(offset, table_hash, algo)` for each block, HEAD first then members.
    pub block_hashes: Vec<(u64, [u8; HASH_FIELD_SIZE], HashAlgo)>,
    /// MEMBER block table_hashes in chain order (HEAD excluded).
    pub member_hashes: Vec<[u8; HASH_FIELD_SIZE]>,
    /// Every PFS_NODE record introduced by this session.
    pub nodes: Vec<NodeRecord>,
}

/// The result of scanning the whole chain.
#[derive(Debug, Clone, Default)]
pub struct Scan {
    /// Sessions, newest first (strictly decreasing `seq`).
    pub sessions: Vec<SessionView>,
    /// PCF uid -> entry, for content lookup during reconstruction.
    pub uid_index: HashMap<[u8; 16], PartitionEntry>,
}

/// True iff the significant prefix of two hash fields matches for `algo`.
pub fn hash_eq(algo: HashAlgo, a: &[u8; HASH_FIELD_SIZE], b: &[u8; HASH_FIELD_SIZE]) -> bool {
    let n = algo.digest_len();
    a[..n] == b[..n]
}

/// Walk the backward-linked chain from the head, grouping blocks into sessions
/// (Section 11.2, spec R2/R3).
pub fn scan<S: Read + Write + Seek>(c: &mut Container<S>) -> Result<Scan> {
    let mut sessions = Vec::new();
    let mut uid_index: HashMap<[u8; 16], PartitionEntry> = HashMap::new();
    let mut last_seq: Option<u64> = None;

    let mut tbl = c.header().partition_table_offset;
    while tbl != 0 {
        let head = c.read_block_at(tbl)?;
        let session_entries: Vec<PartitionEntry> = head
            .entries
            .iter()
            .filter(|e| e.partition_type == PFS_SESSION_TYPE)
            .cloned()
            .collect();
        if session_entries.len() != 1 {
            return Err(Error::BrokenChain(
                "HEAD block must hold exactly one PFS_SESSION",
            ));
        }
        let sess_data = c.read_partition_data(&session_entries[0])?;
        let record = SessionRecord::from_bytes(&sess_data)?;

        if let Some(prev) = last_seq {
            if record.session_seq >= prev {
                return Err(Error::BrokenChain("session_seq not strictly decreasing"));
            }
        }
        last_seq = Some(record.session_seq);

        let mut all_entries = head.entries.clone();
        let mut block_hashes = vec![(
            head.offset,
            head.header.table_hash,
            head.header.table_hash_algo,
        )];
        let mut member_hashes: Vec<[u8; HASH_FIELD_SIZE]> = Vec::new();

        let mut t = head.header.next_table_offset;
        for _ in 1..record.block_count {
            if t == 0 {
                return Err(Error::BrokenChain(
                    "chain ended before block_count blocks were read",
                ));
            }
            let mv = c.read_block_at(t)?;
            if mv
                .entries
                .iter()
                .any(|e| e.partition_type == PFS_SESSION_TYPE)
            {
                return Err(Error::BrokenChain("MEMBER block contains a PFS_SESSION"));
            }
            member_hashes.push(mv.header.table_hash);
            block_hashes.push((mv.offset, mv.header.table_hash, mv.header.table_hash_algo));
            all_entries.extend(mv.entries.iter().cloned());
            t = mv.header.next_table_offset;
        }

        // Index uids and parse node records; reject a node_id seen twice here.
        let mut seen: HashMap<[u8; 16], ()> = HashMap::new();
        let mut nodes = Vec::new();
        for e in &all_entries {
            uid_index.insert(e.uid, e.clone());
            if e.partition_type == PFS_NODE_TYPE {
                let data = c.read_partition_data(e)?;
                let rec = NodeRecord::from_bytes(&data)?;
                if seen.insert(rec.node_id, ()).is_some() {
                    return Err(Error::DuplicateNodeInSession);
                }
                nodes.push(rec);
            }
        }

        sessions.push(SessionView {
            seq: record.session_seq,
            head_offset: head.offset,
            record,
            block_hashes,
            member_hashes,
            nodes,
        });
        tbl = t;
    }

    Ok(Scan {
        sessions,
        uid_index,
    })
}

/// Verify the inter-session hash chain (Section 8.2, spec R8). Assumes the
/// container's own table/data hashes have already been verified via
/// [`pcf::Container::verify`].
pub fn verify_chain(scan: &Scan) -> Result<()> {
    for (i, s) in scan.sessions.iter().enumerate() {
        // Member-block commitment.
        let digest = member_blocks_digest(s.record.member_digest_algo, &s.member_hashes);
        if !hash_eq(
            s.record.member_digest_algo,
            &digest,
            &s.record.member_blocks_digest,
        ) {
            return Err(Error::ChainHashMismatch);
        }
        // Inter-session commitment: this session's prev_session_hash must equal
        // the previous (older) session's HEAD block table_hash.
        match scan.sessions.get(i + 1) {
            Some(prev) => {
                let (_, prev_head_hash, prev_head_algo) = prev.block_hashes[0];
                if s.record.prev_session_hash_algo != prev_head_algo
                    || !hash_eq(prev_head_algo, &s.record.prev_session_hash, &prev_head_hash)
                {
                    return Err(Error::ChainHashMismatch);
                }
            }
            None => {
                // Oldest session: prev hash must be zero under algo None.
                if s.record.prev_session_hash_algo != HashAlgo::None
                    || s.record.prev_session_hash != [0u8; HASH_FIELD_SIZE]
                {
                    return Err(Error::ChainHashMismatch);
                }
            }
        }
    }
    Ok(())
}

/// The resolved per-node state (Section 10.2).
#[derive(Debug, Clone, Default)]
pub struct NodeView {
    /// node_id -> (winning session_seq, current record). Newest wins.
    pub current: HashMap<[u8; 16], (u64, NodeRecord)>,
    /// node_id -> records, descending by session_seq (for reconstruction).
    pub history: HashMap<[u8; 16], Vec<(u64, NodeRecord)>>,
}

/// Build the node view from a scan, optionally "as of" `max_seq` (inclusive),
/// implementing the history-query facility of Section 15.
pub fn build_node_view(scan: &Scan, max_seq: Option<u64>) -> NodeView {
    let mut view = NodeView::default();
    // Ascending session_seq so "newest wins" falls out naturally.
    let mut ordered: Vec<&SessionView> = scan
        .sessions
        .iter()
        .filter(|s| max_seq.map(|m| s.seq <= m).unwrap_or(true))
        .collect();
    ordered.sort_by_key(|s| s.seq);

    for s in ordered {
        for rec in &s.nodes {
            view.history
                .entry(rec.node_id)
                .or_default()
                .push((s.seq, rec.clone()));
            view.current.insert(rec.node_id, (s.seq, rec.clone()));
        }
    }
    for v in view.history.values_mut() {
        v.sort_by_key(|b| std::cmp::Reverse(b.0)); // descending seq
    }
    view
}
