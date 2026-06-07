//! The DCP arena: the in-memory model of one DCP container and its canonical
//! byte serialisation.
//!
//! An [`Arena`] holds a byte pool (`blob`) plus a list of inner partitions,
//! each of which owns a list of [`Frag`]s. A `Frag` addresses a byte range in
//! the pool; two `Frag`s addressing the *same* range share that extent
//! (deduplication, spec Section 10.2). Editing operations (append, overwrite,
//! insert, delete, truncate) work purely on the fragment list and append new
//! bytes to the pool, never overwriting bytes a `SHARED` extent still names
//! (copy-on-write, spec Section 10.1).
//!
//! [`Arena::to_bytes`] always emits the *canonical* layout used by the spec's
//! test vector (Section 17): `DCP Header || data extents || Fragment Tables ||
//! Inner Table Block(s)`, with each distinct extent emitted exactly once.

use std::collections::HashMap;

use pcf::{
    compute_table_hash, decode_label, encode_label, HashAlgo, PartitionEntry, TableBlockHeader,
    ENTRY_SIZE, NIL_UID, TABLE_HEADER_SIZE, UID_SIZE,
};

use crate::consts::*;
use crate::error::{Error, Result};
use crate::fragment::{walk_fragment_table, FragTableHeader, FragmentEntry};
use crate::header::{read_header, DcpHeader};

/// How a Writer splits an inner partition's content into extents
/// (spec Section 10.2; chunking is writer-side policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chunker {
    /// One extent for the whole content.
    Whole,
    /// Fixed-size chunks of `n` bytes (the final chunk may be shorter). `n == 0`
    /// is treated as [`Chunker::Whole`].
    Fixed(usize),
}

impl Chunker {
    fn split<'a>(&self, content: &'a [u8]) -> Vec<&'a [u8]> {
        match *self {
            Chunker::Whole => {
                if content.is_empty() {
                    Vec::new()
                } else {
                    vec![content]
                }
            }
            Chunker::Fixed(0) => Chunker::Whole.split(content),
            Chunker::Fixed(n) => content.chunks(n).collect(),
        }
    }
}

/// One extent reference inside an inner partition. `offset`/`length` address
/// [`Arena::blob`]; `shared` is the on-disk SHARED flag (bit 0 of `flags`).
#[derive(Debug, Clone, Copy)]
struct Frag {
    offset: u64,
    length: u64,
    kind: u8,
    shared: bool,
}

/// One inner partition.
#[derive(Debug, Clone)]
struct Inner {
    partition_type: u32,
    uid: [u8; UID_SIZE],
    label: [u8; 32],
    data_hash_algo: HashAlgo,
    frags: Vec<Frag>,
}

impl Inner {
    fn logical_len(&self) -> u64 {
        self.frags
            .iter()
            .filter(|f| f.kind == KIND_DATA)
            .map(|f| f.length)
            .sum()
    }

    fn content(&self, blob: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.logical_len() as usize);
        for f in &self.frags {
            if f.kind == KIND_DATA {
                let (a, b) = (f.offset as usize, (f.offset + f.length) as usize);
                out.extend_from_slice(&blob[a..b]);
            }
        }
        out
    }

    fn data_hash(&self, blob: &[u8]) -> [u8; 64] {
        self.data_hash_algo.compute(&self.content(blob))
    }
}

/// A read-only view of one extent, for tooling (`dcp info`, tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtentInfo {
    /// Arena/pool-relative offset of the extent.
    pub extent_offset: u64,
    /// Length of the extent in bytes.
    pub extent_length: u64,
    /// Extent kind (`1` = DATA).
    pub kind: u8,
    /// Whether the SHARED flag is set.
    pub shared: bool,
}

/// A read-only view of one inner partition, for tooling and verification.
#[derive(Debug, Clone)]
pub struct InnerInfo {
    /// Application partition type.
    pub partition_type: u32,
    /// 16-byte uid (unique file-wide).
    pub uid: [u8; UID_SIZE],
    /// Decoded label.
    pub label: String,
    /// Logical content length (= `used_bytes`).
    pub used_bytes: u64,
    /// Hash algorithm protecting the logical content.
    pub data_hash_algo: HashAlgo,
    /// The 64-byte data-hash field over the logical content.
    pub data_hash: [u8; 64],
    /// The partition's extents in logical order.
    pub extents: Vec<ExtentInfo>,
}

/// The in-memory model of one DCP container.
#[derive(Debug, Clone)]
pub struct Arena {
    profile_version_major: u8,
    profile_version_minor: u8,
    flags: u16,
    inner_table_algo: HashAlgo,
    blob: Vec<u8>,
    inners: Vec<Inner>,
}

impl Default for Arena {
    fn default() -> Self {
        Self::new()
    }
}

impl Arena {
    // ---- construction -----------------------------------------------------

    /// A fresh, empty arena (profile v1.0, SHA-256 inner table hashing).
    pub fn new() -> Self {
        Arena {
            profile_version_major: PROFILE_VERSION_MAJOR,
            profile_version_minor: PROFILE_VERSION_MINOR,
            flags: 0,
            inner_table_algo: HashAlgo::Sha256,
            blob: Vec::new(),
            inners: Vec::new(),
        }
    }

    /// Choose the hash algorithm used for inner Table Blocks (default
    /// SHA-256). A Writer SHOULD keep this cryptographic (spec Section 9.2).
    pub fn with_inner_table_algo(mut self, algo: HashAlgo) -> Self {
        self.inner_table_algo = algo;
        self
    }

    /// Parse an arena from its on-disk bytes (spec Sections 6–8). The byte
    /// pool is the arena itself, so every parsed extent offset is
    /// arena-relative and indexes directly into it.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let header = read_header(bytes)?;
        if header.profile_version_major != PROFILE_VERSION_MAJOR {
            return Err(Error::UnsupportedProfileMajor(header.profile_version_major));
        }
        let arena_used = header.arena_used;

        let mut inners = Vec::new();
        let mut inner_table_algo = HashAlgo::Sha256;
        let mut first_block = true;
        let mut off = header.inner_table_offset;
        let mut budget = bytes.len() / TABLE_HEADER_SIZE as usize + 1;
        while off != ARENA_NONE {
            if budget == 0 {
                return Err(Error::OffsetOutOfRange);
            }
            budget -= 1;
            let base = off as usize;
            let hb: [u8; 74] = bytes
                .get(base..base + TABLE_HEADER_SIZE as usize)
                .ok_or(Error::OffsetOutOfRange)?
                .try_into()
                .unwrap();
            let h = TableBlockHeader::from_bytes(&hb)?;
            if first_block {
                inner_table_algo = h.table_hash_algo;
                first_block = false;
            }
            for i in 0..h.partition_count as u64 {
                let eo = base + TABLE_HEADER_SIZE as usize + (i * ENTRY_SIZE) as usize;
                let eb: [u8; 141] = bytes
                    .get(eo..eo + ENTRY_SIZE as usize)
                    .ok_or(Error::OffsetOutOfRange)?
                    .try_into()
                    .unwrap();
                let entry = PartitionEntry::from_bytes(&eb)?;
                let on_disk = walk_fragment_table(bytes, entry.start_offset)?;
                let frags = on_disk
                    .iter()
                    .map(|fe| Frag {
                        offset: fe.extent_offset,
                        length: fe.extent_length,
                        kind: fe.kind,
                        shared: fe.is_shared(),
                    })
                    .collect();
                inners.push(Inner {
                    partition_type: entry.partition_type,
                    uid: entry.uid,
                    label: entry.label,
                    data_hash_algo: entry.data_hash_algo,
                    frags,
                });
            }
            off = h.next_table_offset;
        }

        let blob = bytes.to_vec();
        let arena = Arena {
            profile_version_major: header.profile_version_major,
            profile_version_minor: header.profile_version_minor,
            flags: header.flags,
            inner_table_algo,
            blob,
            inners,
        };
        // Bound every extent by the declared arena_used.
        for inner in &arena.inners {
            for f in &inner.frags {
                let end = f
                    .offset
                    .checked_add(f.length)
                    .ok_or(Error::OffsetOutOfRange)?;
                if end > arena_used {
                    return Err(Error::OffsetOutOfRange);
                }
            }
        }
        Ok(arena)
    }

    // ---- read-only views --------------------------------------------------

    /// Number of inner partitions.
    pub fn len(&self) -> usize {
        self.inners.len()
    }

    /// Whether the arena has no inner partitions.
    pub fn is_empty(&self) -> bool {
        self.inners.is_empty()
    }

    /// The uids of all inner partitions, in stored order.
    pub fn uids(&self) -> Vec<[u8; UID_SIZE]> {
        self.inners.iter().map(|i| i.uid).collect()
    }

    fn index_of(&self, uid: &[u8; UID_SIZE]) -> Result<usize> {
        self.inners
            .iter()
            .position(|i| &i.uid == uid)
            .ok_or(Error::NotFound)
    }

    /// A read-only view of one inner partition.
    pub fn inner_info(&self, uid: &[u8; UID_SIZE]) -> Result<InnerInfo> {
        let inner = &self.inners[self.index_of(uid)?];
        Ok(self.view(inner))
    }

    /// Read-only views of every inner partition, in stored order.
    pub fn inners(&self) -> Vec<InnerInfo> {
        self.inners.iter().map(|i| self.view(i)).collect()
    }

    fn view(&self, inner: &Inner) -> InnerInfo {
        InnerInfo {
            partition_type: inner.partition_type,
            uid: inner.uid,
            label: decode_label(&inner.label).unwrap_or_default(),
            used_bytes: inner.logical_len(),
            data_hash_algo: inner.data_hash_algo,
            data_hash: inner.data_hash(&self.blob),
            extents: inner
                .frags
                .iter()
                .map(|f| ExtentInfo {
                    extent_offset: f.offset,
                    extent_length: f.length,
                    kind: f.kind,
                    shared: f.shared,
                })
                .collect(),
        }
    }

    /// Reconstruct an inner partition's logical content (spec Section 8.3),
    /// checking its length and (when algorithmic) its stored data hash.
    pub fn content(&self, uid: &[u8; UID_SIZE]) -> Result<Vec<u8>> {
        let inner = &self.inners[self.index_of(uid)?];
        let bytes = inner.content(&self.blob);
        let declared = inner.logical_len();
        if bytes.len() as u64 != declared {
            return Err(Error::LengthMismatch {
                expected: declared,
                got: bytes.len() as u64,
            });
        }
        Ok(bytes)
    }

    // ---- builder ----------------------------------------------------------

    /// Add an inner partition whose `content` is split by `chunker` into
    /// extents, deduplicating against extents already present (spec Section
    /// 10.2). Sharing sets the SHARED flag on the new and aliased entries
    /// (rule F1, spec Section 8.4).
    #[allow(clippy::too_many_arguments)]
    pub fn add_inner(
        &mut self,
        partition_type: u32,
        uid: [u8; UID_SIZE],
        label: &str,
        content: &[u8],
        data_hash_algo: HashAlgo,
        chunker: Chunker,
    ) -> Result<()> {
        if partition_type == 0 {
            return Err(Error::ReservedType);
        }
        if partition_type == DCP_CONTAINER_TYPE {
            return Err(Error::NestedContainer);
        }
        if uid == NIL_UID {
            return Err(Error::NilUid);
        }
        if self.inners.iter().any(|i| i.uid == uid) {
            return Err(Error::DuplicateUid);
        }
        let label = encode_label(label).map_err(Error::Pcf)?;

        let mut frags: Vec<Frag> = Vec::new();
        for chunk in chunker.split(content) {
            // Deduplicate against extents already present in other inner
            // partitions AND against earlier chunks of this same partition.
            let hit = self
                .find_extent(chunk)
                .or_else(|| find_local(&self.blob, &frags, chunk));
            match hit {
                Some((offset, length)) => {
                    self.mark_shared(offset, length);
                    for f in &mut frags {
                        if f.offset == offset && f.length == length {
                            f.shared = true;
                        }
                    }
                    frags.push(Frag {
                        offset,
                        length,
                        kind: KIND_DATA,
                        shared: true,
                    });
                }
                None => {
                    let offset = self.blob.len() as u64;
                    self.blob.extend_from_slice(chunk);
                    frags.push(Frag {
                        offset,
                        length: chunk.len() as u64,
                        kind: KIND_DATA,
                        shared: false,
                    });
                }
            }
        }
        self.inners.push(Inner {
            partition_type,
            uid,
            label,
            data_hash_algo,
            frags,
        });
        Ok(())
    }

    /// Find an existing DATA extent whose bytes equal `chunk`, returning its
    /// `(offset, length)`. Realises content-defined sharing for `add_inner`
    /// and `dedup`.
    fn find_extent(&self, chunk: &[u8]) -> Option<(u64, u64)> {
        if chunk.is_empty() {
            return None;
        }
        for inner in &self.inners {
            for f in &inner.frags {
                if f.kind == KIND_DATA && f.length == chunk.len() as u64 {
                    let (a, b) = (f.offset as usize, (f.offset + f.length) as usize);
                    if &self.blob[a..b] == chunk {
                        return Some((f.offset, f.length));
                    }
                }
            }
        }
        None
    }

    /// Set the SHARED flag on every live fragment that references exactly the
    /// `(offset, length)` extent (rule F1).
    fn mark_shared(&mut self, offset: u64, length: u64) {
        for inner in &mut self.inners {
            for f in &mut inner.frags {
                if f.offset == offset && f.length == length {
                    f.shared = true;
                }
            }
        }
    }

    // ---- logical edits (copy-on-write) ------------------------------------

    /// Append `bytes` to the end of an inner partition's logical content.
    pub fn append(&mut self, uid: &[u8; UID_SIZE], bytes: &[u8]) -> Result<()> {
        let idx = self.index_of(uid)?;
        if bytes.is_empty() {
            return Ok(());
        }
        let offset = self.blob.len() as u64;
        self.blob.extend_from_slice(bytes);
        self.inners[idx].frags.push(Frag {
            offset,
            length: bytes.len() as u64,
            kind: KIND_DATA,
            shared: false,
        });
        Ok(())
    }

    /// Overwrite the logical range `[pos, pos+len)` with `bytes` (which need not
    /// be the same length: this is delete-then-insert). The replaced bytes go
    /// into a fresh private extent, leaving any SHARED bytes untouched.
    pub fn overwrite(
        &mut self,
        uid: &[u8; UID_SIZE],
        pos: u64,
        len: u64,
        bytes: &[u8],
    ) -> Result<()> {
        self.delete(uid, pos, len)?;
        self.insert(uid, pos, bytes)
    }

    /// Insert `bytes` at logical position `pos` (`pos == content length`
    /// appends). The new bytes form a fresh private extent.
    pub fn insert(&mut self, uid: &[u8; UID_SIZE], pos: u64, bytes: &[u8]) -> Result<()> {
        let idx = self.index_of(uid)?;
        let total = self.inners[idx].logical_len();
        if pos > total {
            return Err(Error::PositionOutOfRange);
        }
        if bytes.is_empty() {
            return Ok(());
        }
        let split = self.split_at(idx, pos);
        let offset = self.blob.len() as u64;
        self.blob.extend_from_slice(bytes);
        self.inners[idx].frags.insert(
            split,
            Frag {
                offset,
                length: bytes.len() as u64,
                kind: KIND_DATA,
                shared: false,
            },
        );
        Ok(())
    }

    /// Delete the logical range `[pos, pos+len)`, dropping the covered
    /// fragments without moving any bytes (spec Section 10.1).
    pub fn delete(&mut self, uid: &[u8; UID_SIZE], pos: u64, len: u64) -> Result<()> {
        let idx = self.index_of(uid)?;
        let total = self.inners[idx].logical_len();
        let end = pos.checked_add(len).ok_or(Error::PositionOutOfRange)?;
        if end > total {
            return Err(Error::PositionOutOfRange);
        }
        if len == 0 {
            return Ok(());
        }
        let lo = self.split_at(idx, pos);
        let hi = self.split_at(idx, end);
        self.inners[idx].frags.drain(lo..hi);
        Ok(())
    }

    /// Truncate the partition's logical content to `new_len` bytes.
    pub fn truncate(&mut self, uid: &[u8; UID_SIZE], new_len: u64) -> Result<()> {
        let idx = self.index_of(uid)?;
        let total = self.inners[idx].logical_len();
        if new_len > total {
            return Err(Error::PositionOutOfRange);
        }
        let cut = self.split_at(idx, new_len);
        self.inners[idx].frags.truncate(cut);
        Ok(())
    }

    /// Ensure a fragment boundary exists at logical position `pos` in inner
    /// `idx`, splitting the straddling fragment if needed. Returns the index of
    /// the first fragment at-or-after `pos`. Splitting never copies bytes: both
    /// halves keep the parent's `shared` flag and address the same pool bytes.
    fn split_at(&mut self, idx: usize, pos: u64) -> usize {
        let frags = &mut self.inners[idx].frags;
        let mut logical = 0u64;
        let mut i = 0;
        while i < frags.len() {
            let flen = frags[i].length;
            if logical == pos {
                return i;
            }
            if pos < logical + flen {
                // Split fragment i at (pos - logical).
                let head = pos - logical;
                let f = frags[i];
                let left = Frag {
                    offset: f.offset,
                    length: head,
                    kind: f.kind,
                    shared: f.shared,
                };
                let right = Frag {
                    offset: f.offset + head,
                    length: flen - head,
                    kind: f.kind,
                    shared: f.shared,
                };
                frags[i] = left;
                frags.insert(i + 1, right);
                return i + 1;
            }
            logical += flen;
            i += 1;
        }
        frags.len()
    }

    // ---- promotion support ------------------------------------------------

    /// Remove an inner partition, returning the pieces a promotion needs: its
    /// type, label, hash algorithm, and reconstructed logical content. The uid
    /// is the caller's; the data hash is recomputed from the content (and is,
    /// by construction, identical to the inner entry's — the promotion
    /// invariant, spec Section 10.4).
    pub fn remove_inner(
        &mut self,
        uid: &[u8; UID_SIZE],
    ) -> Result<(u32, String, HashAlgo, Vec<u8>)> {
        let idx = self.index_of(uid)?;
        let content = self.content(uid)?;
        let inner = self.inners.remove(idx);
        let label = decode_label(&inner.label).unwrap_or_default();
        Ok((inner.partition_type, label, inner.data_hash_algo, content))
    }

    // ---- deduplication and compaction -------------------------------------

    /// Re-chunk every inner partition with `chunker` and deduplicate identical
    /// extents across the whole arena (spec Section 10.2). Logical content and
    /// every `data_hash` are preserved. Returns the number of bytes the pool
    /// shrank by once re-serialised (an estimate of dedup savings).
    pub fn dedup(&mut self, chunker: Chunker) -> u64 {
        let before = self.canonical_extent_bytes();
        // Rebuild the pool from each partition's logical content, re-chunking
        // and sharing identical chunks. A fresh arena guarantees a clean pool.
        let mut rebuilt = Arena {
            profile_version_major: self.profile_version_major,
            profile_version_minor: self.profile_version_minor,
            flags: self.flags,
            inner_table_algo: self.inner_table_algo,
            blob: Vec::new(),
            inners: Vec::new(),
        };
        for inner in &self.inners {
            let content = inner.content(&self.blob);
            // add_inner cannot fail here: inputs already passed validation.
            let _ = rebuilt.add_inner(
                inner.partition_type,
                inner.uid,
                &decode_label(&inner.label).unwrap_or_default(),
                &content,
                inner.data_hash_algo,
                chunker,
            );
        }
        *self = rebuilt;
        let after = self.canonical_extent_bytes();
        before.saturating_sub(after)
    }

    /// Compact the arena (spec Section 10.3): drop unreferenced pool bytes and
    /// normalise the SHARED flag, clearing it on any extent now referenced
    /// exactly once (rule F2). Returns the number of dead pool bytes reclaimed.
    pub fn compact(&mut self) -> u64 {
        // Reference count by distinct (offset, length) extent.
        let mut refcount: HashMap<(u64, u64), u32> = HashMap::new();
        for inner in &self.inners {
            for f in &inner.frags {
                *refcount.entry((f.offset, f.length)).or_insert(0) += 1;
            }
        }
        // Normalise SHARED: an extent referenced once is private again.
        for inner in &mut self.inners {
            for f in &mut inner.frags {
                let rc = refcount[&(f.offset, f.length)];
                if rc <= 1 {
                    f.shared = false;
                }
            }
        }
        // Sweep: copy each distinct live extent once into a fresh pool, in
        // first-reference order, and rewrite offsets.
        let dead_before = self.blob.len() as u64 - self.live_extent_bytes(&refcount);
        let mut newpool: Vec<u8> = Vec::new();
        let mut remap: HashMap<(u64, u64), u64> = HashMap::new();
        for inner in &self.inners {
            for f in &inner.frags {
                remap.entry((f.offset, f.length)).or_insert_with(|| {
                    let at = newpool.len() as u64;
                    let (a, b) = (f.offset as usize, (f.offset + f.length) as usize);
                    newpool.extend_from_slice(&self.blob[a..b]);
                    at
                });
            }
        }
        for inner in &mut self.inners {
            for f in &mut inner.frags {
                f.offset = remap[&(f.offset, f.length)];
            }
        }
        self.blob = newpool;
        dead_before
    }

    fn live_extent_bytes(&self, refcount: &HashMap<(u64, u64), u32>) -> u64 {
        refcount
            .keys()
            .map(|&(_, len)| len)
            .sum::<u64>()
            .min(self.blob.len() as u64)
    }

    /// Total bytes of the distinct extents that [`Self::to_bytes`] would emit.
    fn canonical_extent_bytes(&self) -> u64 {
        let mut seen: HashMap<(u64, u64), ()> = HashMap::new();
        let mut total = 0u64;
        for inner in &self.inners {
            for f in &inner.frags {
                if seen.insert((f.offset, f.length), ()).is_none() {
                    total += f.length;
                }
            }
        }
        total
    }

    // ---- canonical serialisation ------------------------------------------

    /// Serialise the arena into its canonical on-disk layout (spec Section 17):
    /// `DCP Header || data extents || Fragment Tables || Inner Table Block(s)`,
    /// each distinct extent emitted once. The returned bytes are a complete DCP
    /// arena ready to become a PCF partition's data.
    pub fn to_bytes(&self) -> Vec<u8> {
        // --- 1. distinct extents, first-reference order --------------------
        let mut ext_order: Vec<(u64, u64)> = Vec::new();
        let mut ext_index: HashMap<(u64, u64), usize> = HashMap::new();
        for inner in &self.inners {
            for f in &inner.frags {
                let key = (f.offset, f.length);
                ext_index.entry(key).or_insert_with(|| {
                    ext_order.push(key);
                    ext_order.len() - 1
                });
            }
        }

        // --- 2. lay out extents right after the header ---------------------
        let mut cur = DCP_HEADER_SIZE;
        let mut ext_arena_off: Vec<u64> = Vec::with_capacity(ext_order.len());
        for &(_, len) in &ext_order {
            ext_arena_off.push(cur);
            cur += len;
        }

        // --- 3. Fragment Tables (one chain per inner) ----------------------
        let mut frag_off: Vec<u64> = Vec::with_capacity(self.inners.len());
        for inner in &self.inners {
            frag_off.push(cur);
            cur += fragtable_span(inner.frags.len());
        }

        // --- 4. Inner Table Block(s) ---------------------------------------
        let inner_table_offset = cur;
        let counts = block_counts(self.inners.len());
        let mut block_off: Vec<u64> = Vec::with_capacity(counts.len());
        for &c in &counts {
            block_off.push(cur);
            cur += TABLE_HEADER_SIZE + c as u64 * ENTRY_SIZE;
        }
        let arena_used = cur;

        // --- serialise into a zeroed buffer --------------------------------
        let mut buf = vec![0u8; arena_used as usize];

        let header = DcpHeader {
            profile_version_major: self.profile_version_major,
            profile_version_minor: self.profile_version_minor,
            flags: self.flags,
            inner_table_offset,
            arena_used,
        };
        buf[0..24].copy_from_slice(&header.to_bytes());

        for (i, &(boff, len)) in ext_order.iter().enumerate() {
            let dst = ext_arena_off[i] as usize;
            let (a, b) = (boff as usize, (boff + len) as usize);
            buf[dst..dst + len as usize].copy_from_slice(&self.blob[a..b]);
        }

        for (ii, inner) in self.inners.iter().enumerate() {
            write_fragment_table(
                &mut buf,
                frag_off[ii],
                &inner.frags,
                &ext_index,
                &ext_arena_off,
            );
        }

        let entries: Vec<PartitionEntry> = self
            .inners
            .iter()
            .enumerate()
            .map(|(ii, inner)| {
                let used = inner.logical_len();
                PartitionEntry {
                    partition_type: inner.partition_type,
                    uid: inner.uid,
                    label: inner.label,
                    start_offset: frag_off[ii],
                    max_length: used,
                    used_bytes: used,
                    data_hash_algo: inner.data_hash_algo,
                    data_hash: inner.data_hash(&self.blob),
                }
            })
            .collect();

        let mut idx = 0usize;
        for (b, &c) in counts.iter().enumerate() {
            let next = if b + 1 < counts.len() {
                block_off[b + 1]
            } else {
                0
            };
            let slice = &entries[idx..idx + c];
            let th = compute_table_hash(self.inner_table_algo, next, slice);
            let bh = TableBlockHeader {
                partition_count: c as u8,
                next_table_offset: next,
                table_hash_algo: self.inner_table_algo,
                table_hash: th,
            };
            let bo = block_off[b] as usize;
            buf[bo..bo + 74].copy_from_slice(&bh.to_bytes());
            for (j, e) in slice.iter().enumerate() {
                let eo = bo + 74 + j * ENTRY_SIZE as usize;
                buf[eo..eo + ENTRY_SIZE as usize].copy_from_slice(&e.to_bytes());
            }
            idx += c;
        }

        buf
    }
}

/// Find an extent among `frags` whose pool bytes equal `chunk`, for
/// intra-partition deduplication while a partition is being built.
fn find_local(blob: &[u8], frags: &[Frag], chunk: &[u8]) -> Option<(u64, u64)> {
    if chunk.is_empty() {
        return None;
    }
    for f in frags {
        if f.kind == KIND_DATA && f.length == chunk.len() as u64 {
            let (a, b) = (f.offset as usize, (f.offset + f.length) as usize);
            if &blob[a..b] == chunk {
                return Some((f.offset, f.length));
            }
        }
    }
    None
}

/// On-disk span of an inner partition's Fragment Table chain holding `n`
/// extents, split into blocks of at most 255 entries.
fn fragtable_span(n: usize) -> u64 {
    let mut span = 0u64;
    for c in block_counts(n) {
        span += FRAGTABLE_HEADER_SIZE + c as u64 * FRAGMENT_ENTRY_SIZE;
    }
    span
}

/// Split `n` items into blocks of at most 255; always at least one block (an
/// empty block when `n == 0`).
fn block_counts(n: usize) -> Vec<usize> {
    if n == 0 {
        return vec![0];
    }
    let mut out = Vec::new();
    let mut rem = n;
    while rem > 0 {
        let c = rem.min(MAX_ENTRIES_PER_BLOCK);
        out.push(c);
        rem -= c;
    }
    out
}

/// Write one inner partition's Fragment Table chain at `start`.
fn write_fragment_table(
    buf: &mut [u8],
    start: u64,
    frags: &[Frag],
    ext_index: &HashMap<(u64, u64), usize>,
    ext_arena_off: &[u64],
) {
    let counts = block_counts(frags.len());
    let mut block_start = start;
    let mut idx = 0usize;
    for (b, &c) in counts.iter().enumerate() {
        let span = FRAGTABLE_HEADER_SIZE + c as u64 * FRAGMENT_ENTRY_SIZE;
        let next = if b + 1 < counts.len() {
            block_start + span
        } else {
            0
        };
        let bs = block_start as usize;
        let fh = FragTableHeader {
            next_fragtable_offset: next,
            fragment_count: c as u8,
        };
        buf[bs..bs + 9].copy_from_slice(&fh.to_bytes());
        for j in 0..c {
            let f = &frags[idx + j];
            let arena_off = ext_arena_off[ext_index[&(f.offset, f.length)]];
            let fe = FragmentEntry {
                extent_offset: arena_off,
                extent_length: f.length,
                kind: f.kind,
                flags: if f.shared { FLAG_SHARED } else { 0 },
            };
            let eo = bs + 9 + j * FRAGMENT_ENTRY_SIZE as usize;
            buf[eo..eo + FRAGMENT_ENTRY_SIZE as usize].copy_from_slice(&fe.to_bytes());
        }
        block_start += span;
        idx += c;
    }
}
