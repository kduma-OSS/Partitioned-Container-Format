//! The high-level [`Container`] type: reading and writing whole PCF files.
//!
//! [`Container`] is generic over any backing store that is
//! [`Read`] + [`Write`] + [`Seek`], so it works equally with [`std::fs::File`]
//! and with an in-memory [`std::io::Cursor`].
//!
//! # Reader vs. writer scope
//!
//! The *reader* side (`open`, `entries`, `read_partition_data`, `verify`) is
//! fully general: it accepts any conforming file, including arbitrary region
//! placement and overflow-block chains.
//!
//! The *writer* side implements one documented placement strategy (the format
//! deliberately leaves layout to the writer, spec section 12 / A7, A9):
//!
//! * The first table block sits immediately after the header and is created
//!   with reserved capacity for `first_block_capacity` entries, so entries can
//!   be appended in place without moving data.
//! * Partition data is appended at a growing end-of-data cursor; each
//!   partition may reserve `extra_reserve` spare bytes for later in-place
//!   growth.
//! * When every known block is full, a new overflow block is appended and
//!   linked into the chain.
//! * Block capacity is *not* stored in the file (spec A9); it is tracked only
//!   in memory for the lifetime of this handle. After [`Container::open`],
//!   blocks are treated as having no spare capacity, so subsequent additions
//!   go into fresh overflow blocks. [`Container::compacted_image`] rebuilds a
//!   tightly packed file.

use std::io::{Read, Seek, SeekFrom, Write};

use crate::consts::*;
use crate::entry::{encode_label, PartitionEntry};
use crate::error::{Error, Result};
use crate::hash::HashAlgo;
use crate::header::FileHeader;
use crate::table::{compute_table_hash, TableBlockHeader};
use crate::trailer::Trailer;

/// In-memory bookkeeping for one table block (not stored on disk).
#[derive(Debug, Clone, Copy)]
struct BlockInfo {
    offset: u64,
    capacity: u32,
    count: u8,
    algo: HashAlgo,
    next: u64,
}

/// One table block as read from disk: its absolute `offset`, its parsed
/// [`TableBlockHeader`] (including `table_hash` and `next_table_offset`), and
/// its [`PartitionEntry`] list.
///
/// This is a read-only view returned by [`Container::read_block_at`]. It exists
/// so that profiles layered on PCF (which must group blocks, inspect each
/// block's `table_hash`, and follow non-default `next_table_offset` chains) can
/// reuse PCF's block parsing and verification rather than re-decoding raw
/// bytes. It plays no part in the writer's in-memory bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockView {
    /// Absolute file offset of the table block.
    pub offset: u64,
    /// Parsed 74-byte block header.
    pub header: TableBlockHeader,
    /// The block's entries, in stored order.
    pub entries: Vec<PartitionEntry>,
}

/// A PCF container backed by `S`.
pub struct Container<S: Read + Write + Seek> {
    storage: S,
    header: FileHeader,
    /// Resolved absolute offset of the partition-table head. Equal to
    /// `header.partition_table_offset` for a classic file, or the offset taken
    /// from the file [`Trailer`] when the header holds [`PT_OFFSET_TRAILER`].
    /// 0 denotes an empty table.
    table_head: u64,
    /// Chain-direction flags resolved at open time (see [`Trailer::chain_flags`]).
    chain_flags: u8,
    blocks: Vec<BlockInfo>,
    data_eof: u64,
    default_capacity: u32,
    table_hash_algo: HashAlgo,
}

impl<S: Read + Write + Seek> Container<S> {
    // ---- construction ----------------------------------------------------

    /// Create an empty container with sensible defaults (first block capacity
    /// 16, table hashing with SHA-256).
    pub fn create(storage: S) -> Result<Self> {
        Self::create_with(storage, 16, HashAlgo::Sha256)
    }

    /// Create an empty container, choosing the first block's reserved capacity
    /// and the table-hash algorithm.
    pub fn create_with(
        mut storage: S,
        first_block_capacity: u32,
        table_hash_algo: HashAlgo,
    ) -> Result<Self> {
        let cap = first_block_capacity.clamp(1, MAX_ENTRIES_PER_BLOCK);
        let header = FileHeader {
            version_major: VERSION_MAJOR,
            version_minor: VERSION_MINOR,
            partition_table_offset: HEADER_SIZE,
        };
        storage.seek(SeekFrom::Start(0))?;
        storage.write_all(&header.to_bytes())?;

        let th = compute_table_hash(table_hash_algo, 0, &[]);
        let bh = TableBlockHeader {
            partition_count: 0,
            next_table_offset: 0,
            table_hash_algo,
            table_hash: th,
        };
        storage.seek(SeekFrom::Start(HEADER_SIZE))?;
        storage.write_all(&bh.to_bytes())?;

        let data_eof = HEADER_SIZE + TABLE_HEADER_SIZE + cap as u64 * ENTRY_SIZE;
        let blocks = vec![BlockInfo {
            offset: HEADER_SIZE,
            capacity: cap,
            count: 0,
            algo: table_hash_algo,
            next: 0,
        }];
        Ok(Self {
            storage,
            header,
            table_head: HEADER_SIZE,
            chain_flags: CHAIN_FORWARD,
            blocks,
            data_eof,
            default_capacity: cap,
            table_hash_algo,
        })
    }

    /// Open an existing container, validating the header (spec C1, C2).
    ///
    /// When the header's `partition_table_offset` is the [`PT_OFFSET_TRAILER`]
    /// sentinel, the partition-table head and chain direction are read from the
    /// fixed [`Trailer`] in the final [`TRAILER_SIZE`] bytes of the file. Chain
    /// traversal is mechanically identical in both directions (follow
    /// `next_table_offset` until 0); the direction only conveys which end is
    /// newest, exposed via [`Self::chain_is_backward`].
    pub fn open(mut storage: S) -> Result<Self> {
        let mut hb = [0u8; 20];
        storage.seek(SeekFrom::Start(0))?;
        storage.read_exact(&mut hb)?;
        let header = FileHeader::from_bytes(&hb)?;

        let (table_head, chain_flags) = if header.partition_table_offset == PT_OFFSET_TRAILER {
            Self::locate_trailer(&mut storage)?
        } else {
            (header.partition_table_offset, CHAIN_FORWARD)
        };

        let mut me = Self {
            storage,
            header,
            table_head,
            chain_flags,
            blocks: Vec::new(),
            data_eof: 0,
            default_capacity: 16,
            table_hash_algo: HashAlgo::Sha256,
        };

        let mut blocks = Vec::new();
        let mut off = table_head;
        while off != 0 {
            let (h, _entries) = me.read_block(off)?;
            blocks.push(BlockInfo {
                offset: off,
                capacity: h.partition_count as u32, // no known spare after open
                count: h.partition_count,
                algo: h.table_hash_algo,
                next: h.next_table_offset,
            });
            off = h.next_table_offset;
        }
        if let Some(b0) = blocks.first() {
            me.table_hash_algo = b0.algo;
        }
        me.blocks = blocks;
        me.data_eof = me.storage.seek(SeekFrom::End(0))?;
        Ok(me)
    }

    /// Consume the container and return the backing store.
    pub fn into_storage(self) -> S {
        self.storage
    }

    /// The parsed file header. In trailer mode its `partition_table_offset`
    /// holds the [`PT_OFFSET_TRAILER`] sentinel rather than a real offset; use
    /// [`Self::table_head`] for the resolved head.
    pub fn header(&self) -> FileHeader {
        self.header
    }

    /// The resolved absolute offset of the partition-table head (0 if the table
    /// is empty). This is the value to follow regardless of whether the file
    /// uses a header pointer or a trailer.
    pub fn table_head(&self) -> u64 {
        self.table_head
    }

    /// Whether the chain is backward-linked (head = newest block,
    /// `next_table_offset` points at the previous/older block). A classic
    /// header-pointer file is always forward.
    pub fn chain_is_backward(&self) -> bool {
        self.chain_flags & 1 != 0
    }

    /// Locate the most recent valid file trailer by scanning backward from the
    /// end of the file for the last 20-byte window ending in [`TRAILER_MAGIC`]
    /// whose recorded head is either empty (0) or references a parseable table
    /// block. Bytes after that trailer — an incomplete or aborted append — are
    /// ignored, which gives append-only writers crash recovery for free. In the
    /// common (clean) case the trailer is exactly the final [`TRAILER_SIZE`]
    /// bytes, found on the first iteration.
    fn locate_trailer(storage: &mut S) -> Result<(u64, u8)> {
        let file_len = storage.seek(SeekFrom::End(0))?;
        let mut end = file_len;
        while end >= TRAILER_SIZE {
            let start = end - TRAILER_SIZE;
            let mut tb = [0u8; 20];
            storage.seek(SeekFrom::Start(start))?;
            storage.read_exact(&mut tb)?;
            if tb[12..20] == TRAILER_MAGIC {
                let t = Trailer::from_bytes(&tb)?;
                if t.partition_table_offset == 0 {
                    return Ok((0, t.chain_flags));
                }
                // Guard against the magic appearing inside an aborted tail: the
                // recorded head must precede this trailer and parse as a block.
                let head_ok = t
                    .partition_table_offset
                    .checked_add(TABLE_HEADER_SIZE)
                    .is_some_and(|past| past <= start)
                    && {
                        let mut hb = [0u8; 74];
                        storage.seek(SeekFrom::Start(t.partition_table_offset))?;
                        storage.read_exact(&mut hb).is_ok()
                            && TableBlockHeader::from_bytes(&hb).is_ok()
                    };
                if head_ok {
                    return Ok((t.partition_table_offset, t.chain_flags));
                }
            }
            end -= 1;
        }
        Err(Error::BadTrailer)
    }

    // ---- low-level I/O ----------------------------------------------------

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<()> {
        self.storage.seek(SeekFrom::Start(off))?;
        self.storage.read_exact(buf)?;
        Ok(())
    }

    fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<()> {
        self.storage.seek(SeekFrom::Start(off))?;
        self.storage.write_all(buf)?;
        Ok(())
    }

    fn read_block(&mut self, off: u64) -> Result<(TableBlockHeader, Vec<PartitionEntry>)> {
        let mut hb = [0u8; 74];
        self.read_at(off, &mut hb)?;
        let h = TableBlockHeader::from_bytes(&hb)?;
        let mut entries = Vec::with_capacity(h.partition_count as usize);
        let mut eb = [0u8; 141];
        for i in 0..h.partition_count as u64 {
            self.read_at(off + TABLE_HEADER_SIZE + i * ENTRY_SIZE, &mut eb)?;
            entries.push(PartitionEntry::from_bytes(&eb)?);
        }
        Ok((h, entries))
    }

    fn write_block(
        &mut self,
        off: u64,
        next: u64,
        algo: HashAlgo,
        entries: &[PartitionEntry],
    ) -> Result<()> {
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
        Ok(())
    }

    // ---- reading ----------------------------------------------------------

    /// All live partition entries, in chain order.
    pub fn entries(&mut self) -> Result<Vec<PartitionEntry>> {
        let mut out = Vec::new();
        let mut off = self.table_head;
        while off != 0 {
            let (h, entries) = self.read_block(off)?;
            out.extend(entries);
            off = h.next_table_offset;
        }
        Ok(out)
    }

    /// Read a single table block at an absolute `offset`, returning its parsed
    /// header (including `table_hash`) and entries as a [`BlockView`].
    ///
    /// Unlike [`Self::entries`], which flattens the whole chain, this exposes
    /// one block at a time so a caller can follow an arbitrary
    /// `next_table_offset` chain and inspect each block's `table_hash`. It is a
    /// read-only operation and does not alter the container.
    pub fn read_block_at(&mut self, offset: u64) -> Result<BlockView> {
        let (header, entries) = self.read_block(offset)?;
        Ok(BlockView {
            offset,
            header,
            entries,
        })
    }

    /// Read a partition's used data.
    pub fn read_partition_data(&mut self, entry: &PartitionEntry) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; entry.used_bytes as usize];
        if !buf.is_empty() {
            self.read_at(entry.start_offset, &mut buf)?;
        }
        Ok(buf)
    }

    fn locate(&mut self, uid: &[u8; UID_SIZE]) -> Result<(u64, usize, PartitionEntry)> {
        let mut off = self.table_head;
        while off != 0 {
            let (h, entries) = self.read_block(off)?;
            for (i, e) in entries.iter().enumerate() {
                if &e.uid == uid {
                    return Ok((off, i, e.clone()));
                }
            }
            off = h.next_table_offset;
        }
        Err(Error::NotFound)
    }

    fn block_index(&self, offset: u64) -> usize {
        self.blocks
            .iter()
            .position(|b| b.offset == offset)
            .expect("block offset must be tracked")
    }

    // ---- writing ----------------------------------------------------------

    /// Add a new partition. The data is appended at the end-of-data cursor and
    /// reserves `extra_reserve` spare bytes for later in-place growth.
    pub fn add_partition(
        &mut self,
        partition_type: u32,
        uid: [u8; UID_SIZE],
        label: &str,
        data: &[u8],
        extra_reserve: u64,
        data_hash_algo: HashAlgo,
    ) -> Result<()> {
        if partition_type == TYPE_RESERVED {
            return Err(Error::ReservedType);
        }
        if uid == NIL_UID {
            return Err(Error::NilUid);
        }
        if self.entries()?.iter().any(|e| e.uid == uid) {
            return Err(Error::DuplicateUid);
        }

        let label = encode_label(label)?;
        let used = data.len() as u64;
        let max = used + extra_reserve;
        let start = self.data_eof;
        if used > 0 {
            self.write_at(start, data)?;
        }
        self.data_eof += max;
        let data_hash = data_hash_algo.compute(data);

        let entry = PartitionEntry {
            partition_type,
            uid,
            label,
            start_offset: start,
            max_length: max,
            used_bytes: used,
            data_hash_algo,
            data_hash,
        };

        // Find an existing block with reserved room.
        let target = self.blocks.iter().position(|b| {
            (b.count as u32) < b.capacity && (b.count as u32) < MAX_ENTRIES_PER_BLOCK
        });

        match target {
            Some(i) => {
                let boff = self.blocks[i].offset;
                let (_h, mut entries) = self.read_block(boff)?;
                entries.push(entry);
                let algo = self.blocks[i].algo;
                let next = self.blocks[i].next;
                self.write_block(boff, next, algo, &entries)?;
                self.blocks[i].count += 1;
            }
            None => {
                // Allocate a new overflow block at the end-of-data cursor.
                let new_off = self.data_eof;
                let cap = self.default_capacity.clamp(1, MAX_ENTRIES_PER_BLOCK);
                self.data_eof = new_off + TABLE_HEADER_SIZE + cap as u64 * ENTRY_SIZE;
                let algo = self.table_hash_algo;
                self.write_block(new_off, 0, algo, &[entry])?;

                // Re-link the previous tail block to point at the new block.
                let tail = *self.blocks.last().expect("at least one block");
                let (_h, tentries) = self.read_block(tail.offset)?;
                self.write_block(tail.offset, new_off, tail.algo, &tentries)?;
                if let Some(last) = self.blocks.last_mut() {
                    last.next = new_off;
                }
                self.blocks.push(BlockInfo {
                    offset: new_off,
                    capacity: cap,
                    count: 1,
                    algo,
                    next: 0,
                });
            }
        }
        Ok(())
    }

    /// Replace a partition's data in place (spec section 8.5, hash cascade).
    /// Fails if `new_data` exceeds the partition's reservation.
    pub fn update_partition_data(&mut self, uid: &[u8; UID_SIZE], new_data: &[u8]) -> Result<()> {
        let (boff, slot, mut entry) = self.locate(uid)?;
        if new_data.len() as u64 > entry.max_length {
            return Err(Error::DataTooLarge);
        }
        if !new_data.is_empty() {
            self.write_at(entry.start_offset, new_data)?;
        }
        entry.used_bytes = new_data.len() as u64;
        entry.data_hash = entry.data_hash_algo.compute(new_data);

        let (_h, mut entries) = self.read_block(boff)?;
        entries[slot] = entry;
        let bi = self.block_index(boff);
        let next = self.blocks[bi].next;
        let algo = self.blocks[bi].algo;
        self.write_block(boff, next, algo, &entries)?;
        Ok(())
    }

    /// Remove a partition. Entries after it in the same block shift down; the
    /// freed data region becomes dead space until [`Self::compacted_image`]
    /// reclaims it (spec section 11.4).
    pub fn remove_partition(&mut self, uid: &[u8; UID_SIZE]) -> Result<()> {
        let (boff, slot, _e) = self.locate(uid)?;
        let (_h, mut entries) = self.read_block(boff)?;
        entries.remove(slot);
        let bi = self.block_index(boff);
        let next = self.blocks[bi].next;
        let algo = self.blocks[bi].algo;
        self.write_block(boff, next, algo, &entries)?;
        self.blocks[bi].count -= 1;
        Ok(())
    }

    // ---- integrity --------------------------------------------------------

    /// Verify every table block and every partition's data against its stored
    /// hash, and run the per-entry conformance checks (spec section 12).
    pub fn verify(&mut self) -> Result<()> {
        let mut off = self.table_head;
        while off != 0 {
            let (h, entries) = self.read_block(off)?;
            if h.table_hash_algo.verifies() {
                let computed = compute_table_hash(h.table_hash_algo, h.next_table_offset, &entries);
                let n = h.table_hash_algo.digest_len();
                if computed[..n] != h.table_hash[..n] {
                    return Err(Error::TableHashMismatch);
                }
            }
            for e in &entries {
                e.validate()?;
                let data = self.read_partition_data(e)?;
                if !e.data_hash_algo.verify(&data, &e.data_hash) {
                    return Err(Error::DataHashMismatch);
                }
            }
            off = h.next_table_offset;
        }
        Ok(())
    }

    // ---- compaction -------------------------------------------------------

    /// Build a freshly compacted image: all dead space removed, every
    /// `max_length` trimmed to `used_bytes`, partitions placed contiguously
    /// after a tightly packed table (spec section 11.5). The current handle is
    /// left unchanged; write the bytes to a new file and re-open it.
    pub fn compacted_image(&mut self) -> Result<Vec<u8>> {
        // Gather live entries and their data, in chain order.
        let mut live: Vec<(PartitionEntry, Vec<u8>)> = Vec::new();
        let mut off = self.table_head;
        while off != 0 {
            let (h, entries) = self.read_block(off)?;
            for e in entries {
                let data = self.read_partition_data(&e)?;
                live.push((e, data));
            }
            off = h.next_table_offset;
        }

        let algo = self.table_hash_algo;
        let n = live.len();
        let num_blocks = if n == 0 { 1 } else { n.div_ceil(255) };

        let mut counts = Vec::with_capacity(num_blocks);
        let mut rem = n;
        for _ in 0..num_blocks {
            let c = rem.min(255);
            counts.push(c);
            rem -= c;
        }

        let mut block_offsets = Vec::with_capacity(num_blocks);
        let mut o = HEADER_SIZE;
        for &c in &counts {
            block_offsets.push(o);
            o += TABLE_HEADER_SIZE + c as u64 * ENTRY_SIZE;
        }
        let data_start = o;

        // Assign contiguous data offsets; trim reservations to used size.
        let mut d = data_start;
        for (e, data) in live.iter_mut() {
            e.start_offset = d;
            e.used_bytes = data.len() as u64;
            e.max_length = data.len() as u64;
            // data_hash is unchanged because the content is unchanged.
            d += data.len() as u64;
        }

        // Serialise.
        let mut image: Vec<u8> = Vec::with_capacity(d as usize);
        let header = FileHeader {
            version_major: VERSION_MAJOR,
            version_minor: VERSION_MINOR,
            partition_table_offset: HEADER_SIZE,
        };
        image.extend_from_slice(&header.to_bytes());

        let mut idx = 0usize;
        for (bi, &c) in counts.iter().enumerate() {
            let next = if bi + 1 < num_blocks {
                block_offsets[bi + 1]
            } else {
                0
            };
            let slice: Vec<PartitionEntry> =
                live[idx..idx + c].iter().map(|(e, _)| e.clone()).collect();
            let th = compute_table_hash(algo, next, &slice);
            let bh = TableBlockHeader {
                partition_count: c as u8,
                next_table_offset: next,
                table_hash_algo: algo,
                table_hash: th,
            };
            image.extend_from_slice(&bh.to_bytes());
            for e in &slice {
                image.extend_from_slice(&e.to_bytes());
            }
            idx += c;
        }
        debug_assert_eq!(image.len() as u64, data_start);

        for (_e, data) in &live {
            image.extend_from_slice(data);
        }
        Ok(image)
    }

    /// Write a compacted copy of the container to `out`.
    pub fn compact_into<W: Write>(&mut self, mut out: W) -> Result<()> {
        let img = self.compacted_image()?;
        out.write_all(&img)?;
        Ok(())
    }

    // ---- trailer mode -----------------------------------------------------

    /// Convert the file to trailer mode: append a fixed [`Trailer`] at the end
    /// of the file recording the current partition-table head, then overwrite
    /// the header's `partition_table_offset` with the [`PT_OFFSET_TRAILER`]
    /// sentinel so the head is located via that trailer.
    ///
    /// This is the generic-container counterpart of an append-only writer's
    /// commit step. The chain built by this writer is forward-linked, so the
    /// trailer records [`CHAIN_FORWARD`]. After calling this the container
    /// reads back identically; it is intended as a finalisation step rather
    /// than a prelude to further in-place edits.
    pub fn finalize_with_trailer(&mut self) -> Result<()> {
        let trailer = Trailer {
            partition_table_offset: self.table_head,
            chain_flags: CHAIN_FORWARD,
        };
        let pos = self.storage.seek(SeekFrom::End(0))?;
        self.write_at(pos, &trailer.to_bytes())?;
        self.header.partition_table_offset = PT_OFFSET_TRAILER;
        let hb = self.header.to_bytes();
        self.write_at(0, &hb)?;
        self.chain_flags = CHAIN_FORWARD;
        self.data_eof = pos + TRAILER_SIZE;
        Ok(())
    }
}
