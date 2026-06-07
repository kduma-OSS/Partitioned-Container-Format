//! # `pcf-dcp` — PCF Dynamic Container Partition (reference implementation)
//!
//! This crate is the reference reader/writer for **PCF-DCP v1.0**, an
//! application-level profile that adds *dynamic*, fragmentable, dedup-friendly
//! sub-partitions to [PCF v1.0](../pcf/index.html) without changing the PCF
//! byte container. It mirrors the written specification
//! (`specs/PCF-DCP-spec-v1.0.txt`) field-for-field and favours auditability
//! over performance.
//!
//! ## Layout at a glance
//!
//! One new PCF partition type is defined:
//!
//! * **`DCP_CONTAINER`** (type `0xAAAC0001`) — a partition whose bytes are an
//!   *arena*: a [`DcpHeader`], a chain of reused PCF Table Blocks listing
//!   *inner* partitions, a [`FragmentEntry`] table per inner partition, and the
//!   data extents those fragments name.
//!
//! Each inner partition's logical content is the concatenation of its DATA
//! extents (spec Section 8.3); its `data_hash` covers that logical content, so
//! fragmentation, deduplication, compaction, and promotion all leave the hash
//! (and any PCF-SIG signature over it) unchanged.
//!
//! A generic PCF reader sees a DCP file as one opaque, typed partition; only a
//! DCP-aware reader looks inside. A DCP file is always a conforming PCF v1.0
//! file.
//!
//! ## Example
//!
//! ```
//! use std::io::Cursor;
//! use pcf_dcp::{Arena, Chunker, DcpReader, DcpWriter, HashAlgo};
//!
//! // Build a container with two inner partitions that share an extent.
//! let mut arena = Arena::new();
//! arena.add_inner(0x10, [0xA1; 16], "A", b"Hello, World!", HashAlgo::Sha256, Chunker::Fixed(7))?;
//! arena.add_inner(0x10, [0xB2; 16], "B", b"World!", HashAlgo::Sha256, Chunker::Whole)?;
//!
//! let mut w = DcpWriter::new();
//! w.add_container([0xDC; 16], "dcp", arena)?;
//! let image = w.to_image()?;
//!
//! // Read it back: a valid PCF file whose inner content reconstructs exactly.
//! let mut r = DcpReader::open(Cursor::new(image))?;
//! r.verify()?;
//! assert_eq!(r.read_inner(&[0xB2; 16])?, b"World!");
//! # Ok::<(), pcf_dcp::Error>(())
//! ```

mod arena;
pub mod consts;
mod error;
mod fragment;
mod header;
mod reader;
mod vector;
mod writer;

pub use arena::{Arena, Chunker, ExtentInfo, InnerInfo};
pub use consts::*;
pub use error::{Error, Result};
pub use fragment::{reconstruct, walk_fragment_table, FragTableHeader, FragmentEntry};
pub use header::DcpHeader;
pub use reader::{DcpReader, InnerLocation, Resolved};
pub use vector::build_reference_vector;
pub use writer::DcpWriter;

// Re-export underlying PCF primitives used across the DCP API surface.
pub use pcf::{HashAlgo, PartitionEntry, UID_SIZE};
