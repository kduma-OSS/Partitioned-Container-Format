//! [`DcpWriter`]: building and rewriting PCF files that carry DCP containers.
//!
//! The writer keeps the whole file as an in-memory list of top-level partitions
//! (plain partitions and DCP containers) and emits a fresh, canonical PCF image
//! on demand. Every mutating operation — adding a container, promotion,
//! demotion, dedup, defrag — is a logical edit of that list followed by a
//! rebuild. This is deliberately simple and always correct for a reference
//! implementation; the resulting file is a fully conforming PCF v1.0 file.

use std::io::{Cursor, Read, Seek, Write};

use pcf::{decode_label, Container, HashAlgo, UID_SIZE};

use crate::arena::{Arena, Chunker};
use crate::consts::DCP_CONTAINER_TYPE;
use crate::error::{Error, Result};

/// The body of a top-level partition.
enum Body {
    /// An ordinary partition's raw bytes.
    Plain(Vec<u8>),
    /// A DCP container's arena.
    Container(Arena),
}

/// One top-level partition.
struct TopPart {
    partition_type: u32,
    uid: [u8; UID_SIZE],
    label: String,
    data_hash_algo: HashAlgo,
    body: Body,
}

/// A writer that assembles a PCF file containing DCP containers.
pub struct DcpWriter {
    parts: Vec<TopPart>,
    table_hash_algo: HashAlgo,
    trailer: bool,
}

impl Default for DcpWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl DcpWriter {
    /// A new, empty writer (top-level table hashed with SHA-256).
    pub fn new() -> Self {
        DcpWriter {
            parts: Vec::new(),
            table_hash_algo: HashAlgo::Sha256,
            trailer: false,
        }
    }

    /// Load an existing PCF file into the writer's model, classifying each
    /// top-level partition as a plain partition or a DCP container.
    pub fn open<S: Read + Write + Seek>(storage: S) -> Result<Self> {
        let mut c = Container::open(storage)?;
        let mut parts = Vec::new();
        for e in c.entries()? {
            let data = c.read_partition_data(&e)?;
            let label = decode_label(&e.label).unwrap_or_default();
            let body = if e.partition_type == DCP_CONTAINER_TYPE {
                Body::Container(Arena::parse(&data)?)
            } else {
                Body::Plain(data)
            };
            parts.push(TopPart {
                partition_type: e.partition_type,
                uid: e.uid,
                label,
                data_hash_algo: e.data_hash_algo,
                body,
            });
        }
        Ok(DcpWriter {
            parts,
            table_hash_algo: HashAlgo::Sha256,
            trailer: false,
        })
    }

    /// Finalise emitted images in trailer mode (append-only host). Off by
    /// default; passes through to [`pcf::Container::finalize_with_trailer`].
    pub fn set_trailer(&mut self, on: bool) {
        self.trailer = on;
    }

    // ---- top-level construction -------------------------------------------

    /// Add a DCP container partition holding `arena` (data hash algo 0,
    /// unsealed; spec Section 9).
    pub fn add_container(&mut self, uid: [u8; UID_SIZE], label: &str, arena: Arena) -> Result<()> {
        self.ensure_unique(&uid)?;
        self.parts.push(TopPart {
            partition_type: DCP_CONTAINER_TYPE,
            uid,
            label: label.to_string(),
            data_hash_algo: HashAlgo::None,
            body: Body::Container(arena),
        });
        Ok(())
    }

    /// Add an ordinary top-level partition.
    pub fn add_plain(
        &mut self,
        partition_type: u32,
        uid: [u8; UID_SIZE],
        label: &str,
        data: Vec<u8>,
        data_hash_algo: HashAlgo,
    ) -> Result<()> {
        self.ensure_unique(&uid)?;
        self.parts.push(TopPart {
            partition_type,
            uid,
            label: label.to_string(),
            data_hash_algo,
            body: Body::Plain(data),
        });
        Ok(())
    }

    fn ensure_unique(&self, uid: &[u8; UID_SIZE]) -> Result<()> {
        if self.parts.iter().any(|p| &p.uid == uid) {
            return Err(Error::DuplicateUid);
        }
        Ok(())
    }

    fn container_mut(&mut self, uid: &[u8; UID_SIZE]) -> Result<&mut Arena> {
        for p in &mut self.parts {
            if &p.uid == uid {
                return match &mut p.body {
                    Body::Container(a) => Ok(a),
                    Body::Plain(_) => Err(Error::NotADcpContainer),
                };
            }
        }
        Err(Error::NotFound)
    }

    /// Borrow a container's arena for inspection or in-place editing.
    pub fn arena_mut(&mut self, container_uid: &[u8; UID_SIZE]) -> Result<&mut Arena> {
        self.container_mut(container_uid)
    }

    // ---- migration: promotion / demotion ----------------------------------

    /// Promote an inner partition out of its DCP container to a top-level PCF
    /// partition (dynamic → fixed), preserving uid, type, label, hash algorithm
    /// and `data_hash` (the promotion invariant, spec Section 10.4). The inner
    /// partition is removed from the arena (a MOVE, keeping uids unique).
    pub fn promote(
        &mut self,
        container_uid: &[u8; UID_SIZE],
        inner_uid: &[u8; UID_SIZE],
    ) -> Result<()> {
        let (ptype, label, algo, content) = {
            let arena = self.container_mut(container_uid)?;
            arena.remove_inner(inner_uid)?
        };
        // The inner uid is now free file-wide; add it as a top-level partition.
        self.parts.push(TopPart {
            partition_type: ptype,
            uid: *inner_uid,
            label,
            data_hash_algo: algo,
            body: Body::Plain(content),
        });
        Ok(())
    }

    /// Demote a top-level partition into a DCP container as an inner partition
    /// (fixed → dynamic), preserving uid, type, label, hash algorithm and
    /// `data_hash`. The content becomes a single DATA extent.
    pub fn demote(
        &mut self,
        part_uid: &[u8; UID_SIZE],
        container_uid: &[u8; UID_SIZE],
    ) -> Result<()> {
        let pos = self
            .parts
            .iter()
            .position(|p| &p.uid == part_uid)
            .ok_or(Error::NotFound)?;
        if self.parts[pos].partition_type == DCP_CONTAINER_TYPE {
            return Err(Error::NestedContainer);
        }
        let (ptype, label, algo, content) = {
            let p = &self.parts[pos];
            let content = match &p.body {
                Body::Plain(b) => b.clone(),
                Body::Container(_) => return Err(Error::NestedContainer),
            };
            (p.partition_type, p.label.clone(), p.data_hash_algo, content)
        };
        let arena = self.container_mut(container_uid)?;
        arena.add_inner(ptype, *part_uid, &label, &content, algo, Chunker::Whole)?;
        self.parts.remove(pos);
        Ok(())
    }

    // ---- container-level maintenance --------------------------------------

    /// Re-chunk and deduplicate a container's inner partitions (spec Section
    /// 10.2). Returns estimated bytes saved.
    pub fn dedup(&mut self, container_uid: &[u8; UID_SIZE], chunker: Chunker) -> Result<u64> {
        Ok(self.container_mut(container_uid)?.dedup(chunker))
    }

    /// Compact / defragment a container's arena, reclaiming dead bytes and
    /// normalising the SHARED flag (spec Section 10.3). Returns bytes reclaimed.
    pub fn defrag(&mut self, container_uid: &[u8; UID_SIZE]) -> Result<u64> {
        Ok(self.container_mut(container_uid)?.compact())
    }

    // ---- serialisation ----------------------------------------------------

    /// Build a fresh, canonical PCF image of the whole file. The first table
    /// block is sized to hold every partition (a single block, no overflow),
    /// matching the spec's canonical test-vector layout.
    pub fn to_image(&self) -> Result<Vec<u8>> {
        let cap = self.parts.len().max(1) as u32;
        let mut c = Container::create_with(Cursor::new(Vec::new()), cap, self.table_hash_algo)?;
        for p in &self.parts {
            let data = match &p.body {
                Body::Plain(b) => b.clone(),
                Body::Container(a) => a.to_bytes(),
            };
            c.add_partition(
                p.partition_type,
                p.uid,
                &p.label,
                &data,
                0,
                p.data_hash_algo,
            )?;
        }
        if self.trailer {
            c.finalize_with_trailer()?;
        }
        Ok(c.into_storage().into_inner())
    }

    /// Write the image to any [`Write`] sink.
    pub fn write_to<W: Write>(&self, mut out: W) -> Result<()> {
        out.write_all(&self.to_image()?)?;
        Ok(())
    }
}
