//! [`DcpReader`]: reading DCP containers from a PCF file.
//!
//! The reader works entirely through the high-level [`pcf::Container`] API
//! (`open`, `entries`, `read_partition_data`, `verify`). Because
//! `Container::open` resolves a file [`pcf::Trailer`] and exposes the table
//! head itself, a DCP file written in trailer mode (append-only host) reads
//! back transparently here — this code never assumes the header's
//! `partition_table_offset` is a real offset (spec Section 2, "Compatibility
//! with the PCF File Trailer").

use std::collections::HashSet;
use std::io::{Read, Seek, Write};

use pcf::{Container, PartitionEntry, UID_SIZE};

use crate::arena::{Arena, InnerInfo};
use crate::consts::DCP_CONTAINER_TYPE;
use crate::error::{Error, Result};

/// An inner partition together with the container that holds it.
#[derive(Debug, Clone)]
pub struct InnerLocation {
    /// uid of the enclosing DCP container partition.
    pub container_uid: [u8; UID_SIZE],
    /// The inner partition's metadata and extents.
    pub info: InnerInfo,
}

/// The result of resolving a uid against the flattened partition set
/// (top-level ∪ inner), per the Opt-B scope of spec Section 2.1.
#[derive(Debug, Clone)]
pub enum Resolved {
    /// A top-level PCF partition.
    TopLevel(PartitionEntry),
    /// An inner partition inside a DCP container.
    Inner(InnerLocation),
}

/// A reader for DCP containers layered over a PCF file.
pub struct DcpReader<S: Read + Write + Seek> {
    container: Container<S>,
}

impl<S: Read + Write + Seek> DcpReader<S> {
    /// Open a PCF file for DCP-aware reading.
    pub fn open(storage: S) -> Result<Self> {
        Ok(Self {
            container: Container::open(storage)?,
        })
    }

    /// Borrow the underlying PCF container (e.g. to inspect non-DCP
    /// partitions).
    pub fn container(&mut self) -> &mut Container<S> {
        &mut self.container
    }

    /// All top-level entries, in chain order.
    pub fn entries(&mut self) -> Result<Vec<PartitionEntry>> {
        Ok(self.container.entries()?)
    }

    /// The top-level DCP container entries (`partition_type ==
    /// DCP_CONTAINER_TYPE`).
    pub fn containers(&mut self) -> Result<Vec<PartitionEntry>> {
        Ok(self
            .container
            .entries()?
            .into_iter()
            .filter(|e| e.partition_type == DCP_CONTAINER_TYPE)
            .collect())
    }

    /// Parse the arena of a DCP container entry.
    pub fn open_arena(&mut self, entry: &PartitionEntry) -> Result<Arena> {
        if entry.partition_type != DCP_CONTAINER_TYPE {
            return Err(Error::NotADcpContainer);
        }
        let data = self.container.read_partition_data(entry)?;
        Arena::parse(&data)
    }

    /// Every inner partition across every DCP container, in file order.
    pub fn inner_partitions(&mut self) -> Result<Vec<InnerLocation>> {
        let mut out = Vec::new();
        for c in self.containers()? {
            let arena = self.open_arena(&c)?;
            for info in arena.inners() {
                out.push(InnerLocation {
                    container_uid: c.uid,
                    info,
                });
            }
        }
        Ok(out)
    }

    /// Resolve a uid against the flattened set top-level ∪ inner (spec Section
    /// 2.1). Top-level entries are checked first.
    pub fn resolve_uid(&mut self, uid: &[u8; UID_SIZE]) -> Result<Resolved> {
        if let Some(e) = self
            .container
            .entries()?
            .into_iter()
            .find(|e| &e.uid == uid)
        {
            return Ok(Resolved::TopLevel(e));
        }
        for loc in self.inner_partitions()? {
            if &loc.info.uid == uid {
                return Ok(Resolved::Inner(loc));
            }
        }
        Err(Error::NotFound)
    }

    /// Reconstruct an inner partition's logical content by uid, searching every
    /// DCP container.
    pub fn read_inner(&mut self, uid: &[u8; UID_SIZE]) -> Result<Vec<u8>> {
        for c in self.containers()? {
            let arena = self.open_arena(&c)?;
            if arena.uids().iter().any(|u| u == uid) {
                return arena.content(uid);
            }
        }
        Err(Error::NotFound)
    }

    /// Full DCP-aware verification:
    ///
    /// 1. PCF integrity (`Container::verify`): every table block and partition
    ///    data hash, and per-entry conformance.
    /// 2. Per container: valid `"PDCP"` magic and supported profile major (via
    ///    `Arena::parse`), each inner Table Block's `table_hash` (checked while
    ///    parsing through PCF), reconstruction length and (when algorithmic)
    ///    `data_hash`, no nested container, and file-wide uid uniqueness.
    pub fn verify(&mut self) -> Result<()> {
        self.container.verify()?;

        let mut seen: HashSet<[u8; UID_SIZE]> = HashSet::new();
        // Top-level uids participate in the file-wide namespace too.
        for e in self.container.entries()? {
            if !seen.insert(e.uid) {
                return Err(Error::DuplicateUid);
            }
        }

        for c in self.containers()? {
            // Verify the inner Table Block hashes the same way PCF does.
            let data = self.container.read_partition_data(&c)?;
            verify_inner_table_hashes(&data)?;

            let arena = Arena::parse(&data)?;
            for info in arena.inners() {
                if info.partition_type == DCP_CONTAINER_TYPE {
                    return Err(Error::NestedContainer);
                }
                if !seen.insert(info.uid) {
                    return Err(Error::DuplicateUid);
                }
                // Reconstruct and check length + data hash.
                let content = arena.content(&info.uid)?;
                if content.len() as u64 != info.used_bytes {
                    return Err(Error::LengthMismatch {
                        expected: info.used_bytes,
                        got: content.len() as u64,
                    });
                }
                if !info.data_hash_algo.verify(&content, &info.data_hash) {
                    return Err(Error::HashMismatch);
                }
            }
        }
        Ok(())
    }
}

/// Walk the inner Table Block chain in an arena and recompute each block's
/// `table_hash`, exactly as PCF does for the top-level table (spec Section
/// 9.2). The inner table is the primary integrity anchor for the inner entries
/// because the container's own PCF `data_hash_algo` is normally 0.
fn verify_inner_table_hashes(arena: &[u8]) -> Result<()> {
    use pcf::{
        compute_table_hash, PartitionEntry, TableBlockHeader, ENTRY_SIZE, TABLE_HEADER_SIZE,
    };

    let header = crate::header::read_header(arena)?;
    let mut off = header.inner_table_offset;
    let mut budget = arena.len() / TABLE_HEADER_SIZE as usize + 1;
    while off != 0 {
        if budget == 0 {
            return Err(Error::OffsetOutOfRange);
        }
        budget -= 1;
        let base = off as usize;
        let hb: [u8; 74] = arena
            .get(base..base + TABLE_HEADER_SIZE as usize)
            .ok_or(Error::OffsetOutOfRange)?
            .try_into()
            .unwrap();
        let h = TableBlockHeader::from_bytes(&hb)?;
        let mut entries = Vec::with_capacity(h.partition_count as usize);
        for i in 0..h.partition_count as u64 {
            let eo = base + TABLE_HEADER_SIZE as usize + (i * ENTRY_SIZE) as usize;
            let eb: [u8; 141] = arena
                .get(eo..eo + ENTRY_SIZE as usize)
                .ok_or(Error::OffsetOutOfRange)?
                .try_into()
                .unwrap();
            entries.push(PartitionEntry::from_bytes(&eb)?);
        }
        if h.table_hash_algo.verifies() {
            let computed = compute_table_hash(h.table_hash_algo, h.next_table_offset, &entries);
            let n = h.table_hash_algo.digest_len();
            if computed[..n] != h.table_hash[..n] {
                return Err(Error::HashMismatch);
            }
        }
        off = h.next_table_offset;
    }
    Ok(())
}
