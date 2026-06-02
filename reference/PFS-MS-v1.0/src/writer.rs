//! The append-only, multi-session writer (Sections 4, 6, 12).
//!
//! [`FsWriter`] operates directly on a `Read + Write + Seek` store using PCF's
//! pure serialization primitives ([`pcf::PartitionEntry`],
//! [`pcf::TableBlockHeader`], [`pcf::compute_table_hash`], [`pcf::FileHeader`]).
//! It never uses PCF's in-place `Container` writer, because PFS-MS requires
//! backward-linked Table Blocks and a single in-place header-pointer rewrite at
//! commit — neither of which the PCF writer performs.

use std::io::{Read, Seek, SeekFrom, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use pcf::{
    compute_table_hash, encode_label, Container, FileHeader, HashAlgo, PartitionEntry,
    TableBlockHeader, ENTRY_SIZE, HEADER_SIZE, MAX_ENTRIES_PER_BLOCK, TABLE_HEADER_SIZE,
    VERSION_MAJOR, VERSION_MINOR,
};

use crate::consts::*;
use crate::error::{Error, Result};
use crate::node::{ContentSection, NodeRecord};
use crate::reader::{build_node_view, scan, NodeView, Scan};
use crate::session::{member_blocks_digest, SessionRecord};
use crate::tree::{build_tree, current_delta_depth, read_file, resolve_path, Tree};

/// One partition to publish in a session (RAW content, or a serialized record).
#[derive(Debug, Clone)]
pub struct Partition {
    /// PCF partition type.
    pub partition_type: u32,
    /// PCF uid (must be unique and non-NIL).
    pub uid: [u8; 16],
    /// 32-byte PCF label field.
    pub label: [u8; 32],
    /// Partition data bytes.
    pub data: Vec<u8>,
}

impl Partition {
    /// A RAW content partition (full bytes or a delta patch).
    pub fn raw(uid: [u8; 16], label: &str, data: Vec<u8>) -> Self {
        Partition {
            partition_type: RAW_TYPE,
            uid,
            label: lbl(label),
            data,
        }
    }
    /// A PFS_NODE partition carrying one serialized Node Record.
    pub fn node(uid: [u8; 16], record: &NodeRecord) -> Self {
        Partition {
            partition_type: PFS_NODE_TYPE,
            uid,
            label: lbl("node"),
            data: record.to_bytes(),
        }
    }
}

fn lbl(s: &str) -> [u8; 32] {
    encode_label(s).expect("static label is valid")
}

/// A fresh 16-byte identifier (UUIDv7, recommended by both specs).
pub fn new_id() -> [u8; 16] {
    *uuid::Uuid::now_v7().as_bytes()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// An append-only PFS-MS writer.
pub struct FsWriter<S: Read + Write + Seek> {
    storage: S,
    hash_algo: HashAlgo,
    /// Offset of the current committed HEAD block (0 if none yet).
    head_offset: u64,
    prev_head_hash: [u8; HASH_FIELD_SIZE],
    prev_head_algo: HashAlgo,
    next_seq: u64,
    eof: u64,
    writer_id: Vec<u8>,
    compress: bool,
}

impl<S: Read + Write + Seek> FsWriter<S> {
    /// Create an empty container (no sessions yet). The header points nowhere
    /// (`partition_table_offset = 0`) until the first session is committed; a
    /// reader of this transient state sees an empty filesystem.
    pub fn create(mut storage: S, hash_algo: HashAlgo) -> Result<Self> {
        let header = FileHeader {
            version_major: VERSION_MAJOR,
            version_minor: VERSION_MINOR,
            partition_table_offset: 0,
        };
        storage.seek(SeekFrom::Start(0))?;
        storage.write_all(&header.to_bytes())?;
        storage.flush()?;
        Ok(Self {
            storage,
            hash_algo,
            head_offset: 0,
            prev_head_hash: [0u8; HASH_FIELD_SIZE],
            prev_head_algo: HashAlgo::None,
            next_seq: 1,
            eof: HEADER_SIZE,
            writer_id: b"pfs-ms-ref/1.0".to_vec(),
            compress: true,
        })
    }

    /// Create a new filesystem and commit session 1 with an explicit root
    /// directory record (Section 10.1).
    pub fn mkfs(storage: S, hash_algo: HashAlgo) -> Result<Self> {
        let mut w = Self::create(storage, hash_algo)?;
        let root = NodeRecord {
            kind: KIND_DIR,
            flags: 0,
            node_id: ROOT_NODE_ID,
            parent_id: ROOT_NODE_ID,
            mtime_unix_ms: now_ms(),
            mode: 0,
            name: Vec::new(),
            content: None,
        };
        let part = Partition::node(new_id(), &root);
        let wid = w.writer_id.clone();
        w.commit(vec![part], new_id(), 1, now_ms(), &wid)?;
        Ok(w)
    }

    /// Reopen an existing PFS-MS file for appending further sessions.
    pub fn open(mut storage: S) -> Result<Self> {
        let (head_offset, prev_head_hash, prev_head_algo, next_seq, hash_algo) = {
            let mut c = Container::open(&mut storage)?;
            let head = c.header().partition_table_offset;
            if head == 0 {
                (
                    0,
                    [0u8; HASH_FIELD_SIZE],
                    HashAlgo::None,
                    1,
                    HashAlgo::Sha256,
                )
            } else {
                let hv = c.read_block_at(head)?;
                let sess_entry = hv
                    .entries
                    .iter()
                    .find(|e| e.partition_type == PFS_SESSION_TYPE)
                    .ok_or(Error::BrokenChain("HEAD block has no PFS_SESSION"))?
                    .clone();
                let data = c.read_partition_data(&sess_entry)?;
                let rec = SessionRecord::from_bytes(&data)?;
                (
                    head,
                    hv.header.table_hash,
                    hv.header.table_hash_algo,
                    rec.session_seq + 1,
                    hv.header.table_hash_algo,
                )
            }
        };
        let eof = storage.seek(SeekFrom::End(0))?;
        Ok(Self {
            storage,
            hash_algo,
            head_offset,
            prev_head_hash,
            prev_head_algo,
            next_seq,
            eof,
            writer_id: b"pfs-ms-ref/1.0".to_vec(),
            compress: true,
        })
    }

    /// Set the free-form writer identifier recorded in each session.
    pub fn set_writer_id(&mut self, id: &[u8]) {
        self.writer_id = id.to_vec();
    }

    /// Enable or disable content compression for subsequent writes. When
    /// disabled, content and patches are always stored verbatim
    /// (compression_algo_id = 0). Compression is enabled by default.
    pub fn set_compression(&mut self, enabled: bool) {
        self.compress = enabled;
    }

    /// Consume the writer and return the backing store.
    pub fn into_storage(self) -> S {
        self.storage
    }

    /// The current committed head offset (0 before the first commit).
    pub fn head_offset(&self) -> u64 {
        self.head_offset
    }

    /// The session_seq that the next commit will use.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    // ---- low-level I/O ----------------------------------------------------

    fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<()> {
        self.storage.seek(SeekFrom::Start(off))?;
        self.storage.write_all(buf)?;
        Ok(())
    }

    fn write_block(
        &mut self,
        off: u64,
        next: u64,
        algo: HashAlgo,
        entries: &[PartitionEntry],
    ) -> Result<[u8; HASH_FIELD_SIZE]> {
        let hash = compute_table_hash(algo, next, entries);
        let header = TableBlockHeader {
            partition_count: entries.len() as u8,
            next_table_offset: next,
            table_hash_algo: algo,
            table_hash: hash,
        };
        self.write_at(off, &header.to_bytes())?;
        let mut buf = Vec::with_capacity(entries.len() * ENTRY_SIZE as usize);
        for e in entries {
            buf.extend_from_slice(&e.to_bytes());
        }
        self.write_at(off + TABLE_HEADER_SIZE, &buf)?;
        Ok(hash)
    }

    // ---- the commit protocol (Section 6.2) --------------------------------

    /// Publish one session containing `parts` (RAW content and PFS_NODE
    /// partitions) plus an internally built PFS_SESSION partition. Follows the
    /// commit protocol S1..S7: append all data and blocks beyond the live
    /// chain, then atomically repoint the header.
    pub fn commit(
        &mut self,
        parts: Vec<Partition>,
        session_uid: [u8; 16],
        change_count: u16,
        timestamp: u64,
        writer: &[u8],
    ) -> Result<()> {
        let algo = self.hash_algo;
        let first_session = self.head_offset == 0;
        let prev_head = self.head_offset; // 0 if first session

        // S1/S2: write content + node partition data; build their entries.
        let mut non_session: Vec<PartitionEntry> = Vec::with_capacity(parts.len());
        for p in &parts {
            let start = self.eof;
            if !p.data.is_empty() {
                self.write_at(start, &p.data)?;
            }
            self.eof += p.data.len() as u64;
            non_session.push(PartitionEntry {
                partition_type: p.partition_type,
                uid: p.uid,
                label: p.label,
                start_offset: start,
                max_length: p.data.len() as u64,
                used_bytes: p.data.len() as u64,
                data_hash_algo: algo,
                data_hash: algo.compute(&p.data),
            });
        }

        // Reserve the PFS_SESSION data region (length is known up front).
        let session_len = SESSION_PREFIX_LEN + writer.len();
        let session_start = self.eof;
        self.eof += session_len as u64;

        // Split entries into blocks: the PFS_SESSION entry plus up to 254
        // others in the HEAD block; the rest in MEMBER blocks of <=255.
        let head_other_cap = (MAX_ENTRIES_PER_BLOCK as usize) - 1;
        let head_take = non_session.len().min(head_other_cap);
        let (head_others, rest) = non_session.split_at(head_take);
        let member_chunks: Vec<&[PartitionEntry]> =
            rest.chunks(MAX_ENTRIES_PER_BLOCK as usize).collect();
        let block_count = 1 + member_chunks.len();

        // S4 (offsets): MEMBER blocks first (chain order), then the HEAD block.
        let mut member_offsets = Vec::with_capacity(member_chunks.len());
        for chunk in &member_chunks {
            member_offsets.push(self.eof);
            self.eof += TABLE_HEADER_SIZE + chunk.len() as u64 * ENTRY_SIZE;
        }
        let head_offset = self.eof;
        let head_count = 1 + head_others.len();
        self.eof += TABLE_HEADER_SIZE + head_count as u64 * ENTRY_SIZE;

        // Chain: HEAD -> m0 -> m1 -> ... -> m_{k-1} -> prev_head (or 0).
        let mut member_nexts = Vec::with_capacity(member_chunks.len());
        let mut member_hashes = Vec::with_capacity(member_chunks.len());
        for i in 0..member_chunks.len() {
            let next = if i + 1 < member_chunks.len() {
                member_offsets[i + 1]
            } else {
                prev_head
            };
            member_nexts.push(next);
            member_hashes.push(compute_table_hash(algo, next, member_chunks[i]));
        }
        let head_next = member_offsets.first().copied().unwrap_or(prev_head);

        // S2/S3: build and write the PFS_SESSION record + entry.
        let (prev_algo, prev_hash) = if first_session {
            (HashAlgo::None, [0u8; HASH_FIELD_SIZE])
        } else {
            (self.prev_head_algo, self.prev_head_hash)
        };
        let (mdigest_algo, mdigest) = if member_chunks.is_empty() {
            (HashAlgo::None, [0u8; HASH_FIELD_SIZE])
        } else {
            (algo, member_blocks_digest(algo, &member_hashes))
        };
        let session_rec = SessionRecord {
            profile_version_major: PROFILE_VERSION_MAJOR,
            profile_version_minor: PROFILE_VERSION_MINOR,
            session_seq: self.next_seq,
            timestamp_unix_ms: timestamp,
            prev_session_hash_algo: prev_algo,
            prev_session_hash: prev_hash,
            block_count: block_count as u32,
            member_digest_algo: mdigest_algo,
            member_blocks_digest: mdigest,
            change_count,
            writer: writer.to_vec(),
        };
        let session_bytes = session_rec.to_bytes();
        debug_assert_eq!(session_bytes.len(), session_len);
        self.write_at(session_start, &session_bytes)?;
        let session_entry = PartitionEntry {
            partition_type: PFS_SESSION_TYPE,
            uid: session_uid,
            label: lbl("session"),
            start_offset: session_start,
            max_length: session_len as u64,
            used_bytes: session_len as u64,
            data_hash_algo: algo,
            data_hash: algo.compute(&session_bytes),
        };

        // S4: write MEMBER blocks first, then the HEAD block last (its
        // table_hash commits to the member digest via the session record).
        for i in 0..member_chunks.len() {
            self.write_block(member_offsets[i], member_nexts[i], algo, member_chunks[i])?;
        }
        let mut head_entries = Vec::with_capacity(head_count);
        head_entries.push(session_entry);
        head_entries.extend_from_slice(head_others);
        let head_hash = self.write_block(head_offset, head_next, algo, &head_entries)?;

        // S5: flush data + blocks before publishing.
        self.storage.flush()?;
        // S6: the single permitted in-place write — the 8-byte header pointer.
        self.write_at(12, &head_offset.to_le_bytes())?;
        // S7: flush the header.
        self.storage.flush()?;

        // Advance writer state.
        self.head_offset = head_offset;
        self.prev_head_hash = head_hash;
        self.prev_head_algo = algo;
        self.next_seq += 1;
        Ok(())
    }

    // ---- high-level filesystem operations (Section 10.4) ------------------

    fn snapshot(&mut self) -> Result<(Scan, NodeView, Tree)> {
        let scan = {
            let mut c = Container::open(&mut self.storage)?;
            scan(&mut c)?
        };
        let view = build_node_view(&scan, None);
        let tree = build_tree(&view)?;
        Ok((scan, view, tree))
    }

    fn current_content(&mut self, node_id: [u8; 16]) -> Result<Option<Vec<u8>>> {
        let scan = {
            let mut c = Container::open(&mut self.storage)?;
            scan(&mut c)?
        };
        let view = build_node_view(&scan, None);
        if !view.history.contains_key(&node_id) {
            return Ok(None);
        }
        let mut c = Container::open(&mut self.storage)?;
        match read_file(&mut c, &scan, &view, node_id) {
            Ok(b) => Ok(Some(b)),
            Err(Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Split a path into (live parent directory id, final name bytes).
    fn resolve_parent(&self, tree: &Tree, path: &str) -> Result<([u8; 16], Vec<u8>)> {
        let trimmed = path.trim_end_matches('/');
        let (parent_path, name) = match trimmed.rsplit_once('/') {
            Some((p, n)) => (p, n),
            None => ("", trimmed),
        };
        if name.is_empty() || name == "." || name == ".." {
            return Err(Error::InvalidPath("illegal final component"));
        }
        if name.as_bytes().contains(&0) || name.len() > PFS_MAX_NAME {
            return Err(Error::InvalidPath("illegal name"));
        }
        let parent_id = resolve_path(tree, parent_path)?;
        let parent = tree.nodes.get(&parent_id).ok_or(Error::NotFound)?;
        if !parent.is_dir() {
            return Err(Error::NotADirectory);
        }
        Ok((parent_id, name.as_bytes().to_vec()))
    }

    fn live_child(tree: &Tree, parent_id: [u8; 16], name: &[u8]) -> Option<[u8; 16]> {
        tree.children.get(&parent_id).and_then(|kids| {
            kids.iter()
                .find(|id| tree.nodes.get(*id).map(|r| r.name == name).unwrap_or(false))
                .copied()
        })
    }

    /// Create a directory at `path` (Section 10.4).
    pub fn mkdir(&mut self, path: &str) -> Result<()> {
        let (_, _, tree) = self.snapshot()?;
        let (parent_id, name) = self.resolve_parent(&tree, path)?;
        if Self::live_child(&tree, parent_id, &name).is_some() {
            return Err(Error::AlreadyExists);
        }
        let rec = NodeRecord {
            kind: KIND_DIR,
            flags: 0,
            node_id: new_id(),
            parent_id,
            mtime_unix_ms: now_ms(),
            mode: 0,
            name,
            content: None,
        };
        let part = Partition::node(new_id(), &rec);
        let wid = self.writer_id.clone();
        self.commit(vec![part], new_id(), 1, now_ms(), &wid)
    }

    /// Create or modify the file at `path` with `content` (Section 10.4),
    /// choosing DIRECT vs DELTA automatically (Sections 9.2, 9.4).
    pub fn put_file(&mut self, path: &str, content: &[u8]) -> Result<()> {
        let (_, view, tree) = self.snapshot()?;
        let (parent_id, name) = self.resolve_parent(&tree, path)?;

        let mut parts: Vec<Partition> = Vec::new();
        let existing = Self::live_child(&tree, parent_id, &name);
        let node_id;
        let content_section;

        match existing {
            Some(id) => {
                let rec = tree.nodes.get(&id).ok_or(Error::NotFound)?;
                if rec.is_dir() {
                    return Err(Error::NotADirectory);
                }
                node_id = id;
                let prev = self.current_content(id)?.unwrap_or_default();
                content_section =
                    self.build_modified_content(&mut parts, &prev, content, &view, id);
            }
            None => {
                node_id = new_id();
                content_section = self.build_new_content(&mut parts, content);
            }
        }

        let rec = NodeRecord {
            kind: KIND_FILE,
            flags: 0,
            node_id,
            parent_id,
            mtime_unix_ms: now_ms(),
            mode: 0,
            name,
            content: Some(content_section),
        };
        parts.push(Partition::node(new_id(), &rec));
        let wid = self.writer_id.clone();
        self.commit(parts, new_id(), 1, now_ms(), &wid)
    }

    /// DEFLATE `bytes` and return the smaller of (compressed, verbatim) along
    /// with the `compression_algo_id` describing the chosen form (Section 9.5).
    /// Returns the verbatim bytes when compression is disabled or not smaller.
    fn maybe_compress(&self, bytes: &[u8]) -> (u8, Vec<u8>) {
        if self.compress {
            if let Ok(packed) = crate::compress::compress_deflate(bytes) {
                if packed.len() < bytes.len() {
                    return (COMPRESS_DEFLATE, packed);
                }
            }
        }
        (COMPRESS_NONE, bytes.to_vec())
    }

    fn build_new_content(&self, parts: &mut Vec<Partition>, content: &[u8]) -> ContentSection {
        let algo = self.hash_algo;
        if content.is_empty() {
            return ContentSection::Empty;
        }
        let content_uid = new_id();
        let (compression_algo, stored) = self.maybe_compress(content);
        parts.push(Partition::raw(content_uid, "content", stored));
        ContentSection::Direct {
            compression_algo,
            content_uid,
            full_size: content.len() as u64,
            full_hash_algo: algo,
            full_hash: algo.compute(content),
        }
    }

    fn build_modified_content(
        &self,
        parts: &mut Vec<Partition>,
        prev: &[u8],
        content: &[u8],
        view: &NodeView,
        node_id: [u8; 16],
    ) -> ContentSection {
        let algo = self.hash_algo;
        if content.is_empty() {
            return ContentSection::Empty;
        }
        // Prefer DELTA only when a smaller patch exists and re-baselining is not
        // yet required (Section 9.4).
        if !prev.is_empty() {
            if let Ok(patch) = crate::delta::diff_vcdiff(prev, content) {
                let depth = current_delta_depth(view, node_id);
                if patch.len() < content.len() && depth < RECOMMENDED_MAX_DELTA_DEPTH {
                    let patch_uid = new_id();
                    let (compression_algo, stored) = self.maybe_compress(&patch);
                    parts.push(Partition::raw(patch_uid, "patch", stored));
                    return ContentSection::Delta {
                        patch_algo: PATCH_VCDIFF,
                        compression_algo,
                        patch_uid,
                        full_size: content.len() as u64,
                        full_hash_algo: algo,
                        full_hash: algo.compute(content),
                        base_full_size: prev.len() as u64,
                        base_full_hash_algo: algo,
                        base_full_hash: algo.compute(prev),
                    };
                }
            }
        }
        self.build_new_content(parts, content)
    }

    /// Move and/or rename `src` to `dst` (Section 10.4). A file carries INHERIT
    /// content so its bytes are preserved without a copy.
    pub fn mv(&mut self, src: &str, dst: &str) -> Result<()> {
        let (_, _, tree) = self.snapshot()?;
        let src_id = resolve_path(&tree, src)?;
        if src_id == ROOT_NODE_ID {
            return Err(Error::InvalidPath("cannot move the root"));
        }
        let src_rec = tree.nodes.get(&src_id).ok_or(Error::NotFound)?.clone();
        let (parent_id, name) = self.resolve_parent(&tree, dst)?;
        if Self::live_child(&tree, parent_id, &name).is_some() {
            return Err(Error::AlreadyExists);
        }
        let content = if src_rec.is_file() {
            Some(ContentSection::Inherit)
        } else {
            None
        };
        let rec = NodeRecord {
            kind: src_rec.kind,
            flags: 0,
            node_id: src_id,
            parent_id,
            mtime_unix_ms: now_ms(),
            mode: src_rec.mode,
            name,
            content,
        };
        let part = Partition::node(new_id(), &rec);
        let wid = self.writer_id.clone();
        self.commit(vec![part], new_id(), 1, now_ms(), &wid)
    }

    /// Delete the node at `path` by tombstone (Section 10.4). Directory
    /// deletion is recursive by ancestry (Section 10.2).
    pub fn rm(&mut self, path: &str) -> Result<()> {
        let (_, _, tree) = self.snapshot()?;
        let id = resolve_path(&tree, path)?;
        if id == ROOT_NODE_ID {
            return Err(Error::InvalidPath("cannot delete the root"));
        }
        let rec = tree.nodes.get(&id).ok_or(Error::NotFound)?.clone();
        let tomb = NodeRecord {
            kind: rec.kind,
            flags: FLAG_TOMBSTONE,
            node_id: id,
            parent_id: rec.parent_id,
            mtime_unix_ms: now_ms(),
            mode: 0,
            name: rec.name,
            content: None,
        };
        let part = Partition::node(new_id(), &tomb);
        let wid = self.writer_id.clone();
        self.commit(vec![part], new_id(), 1, now_ms(), &wid)
    }
}
