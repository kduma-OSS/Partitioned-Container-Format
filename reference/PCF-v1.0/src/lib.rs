//! # `pcf` — Partitioned Container Format reference implementation
//!
//! This crate is the reference reader/writer for **PCF v1.0**, a
//! language-agnostic binary container that stores multiple independent regions
//! of bytes ("partitions") in a single file. It mirrors the written
//! specification field-for-field and favours auditability over performance.
//!
//! ## Layout at a glance
//!
//! ```text
//! [ 20-byte header ] [ table block(s) ] [ partition data regions ]
//! ```
//!
//! * **Header** (20 B): magic, major/minor version, offset of the first table
//!   block.
//! * **Table block** (74 B header + N x 141 B entries): a linked chain; each
//!   block is self-verified by its own hash.
//! * **Entry** (141 B): type, 16-byte UID, 32-byte label, start offset, max
//!   length, used bytes, and a 64-byte data hash with an algorithm id.
//!
//! All integers are little-endian. Free space is derived as
//! `max_length - used_bytes`.
//!
//! ## Example
//!
//! ```
//! use std::io::Cursor;
//! use pcf::{Container, HashAlgo};
//!
//! let mut c = Container::create(Cursor::new(Vec::new())).unwrap();
//! let uid = [1u8; 16];
//! c.add_partition(0x10, uid, "notes", b"hello world", 64, HashAlgo::Sha256)
//!     .unwrap();
//!
//! c.verify().unwrap();
//! let entries = c.entries().unwrap();
//! assert_eq!(entries.len(), 1);
//! assert_eq!(c.read_partition_data(&entries[0]).unwrap(), b"hello world");
//! ```

pub mod consts;
mod container;
mod entry;
mod error;
mod hash;
mod header;
mod table;
mod trailer;

pub use consts::*;
pub use container::{BlockView, Container};
pub use entry::{decode_label, encode_label, PartitionEntry};
pub use error::{Error, Result};
pub use hash::HashAlgo;
pub use header::FileHeader;
pub use table::{compute_table_hash, TableBlockHeader};
pub use trailer::Trailer;
