//! # `pfs-ms` — PFS-MS v1.0 reference implementation
//!
//! PFS-MS (PCF File System, Multi-Session Profile) stores an append-only,
//! multi-session tree of files and directories inside a single **PCF v1.0**
//! file. It is layered *strictly above* PCF: a PFS-MS file is a fully
//! conforming PCF file (a generic PCF reader sees a valid flat set of
//! partitions), and this crate builds entirely on the [`pcf`] reference crate.
//!
//! Three kinds of PCF partition carry the profile:
//!
//! * **RAW** (`0xFFFFFFFF`) — file content: full bytes or a VCDIFF patch.
//! * **PFS_NODE** (`0xAAAA0001`) — one [`NodeRecord`] per changed node.
//! * **PFS_SESSION** (`0xAAAA0002`) — one [`SessionRecord`] per session.
//!
//! Sessions are committed by appending **backward-linked** Table Blocks
//! (newest → oldest via `next_table_offset`) followed by a fresh PCF
//! [`pcf::Trailer`] at the end of the file. The header permanently holds the
//! [`pcf::PT_OFFSET_TRAILER`] sentinel, so a commit rewrites **no** committed
//! byte — PFS-MS is purely append-only (Section 4.3).
//!
//! ## Example
//!
//! ```
//! use std::io::Cursor;
//! use pcf::HashAlgo;
//! use pfs_ms::{FsReader, FsWriter};
//!
//! // Create a filesystem and commit three sessions.
//! let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Sha256).unwrap();
//! w.mkdir("docs").unwrap();
//! w.put_file("docs/hello.txt", b"Hello\n").unwrap();
//! w.put_file("docs/hello.txt", b"Hello, world\n").unwrap();
//! let bytes = w.into_storage().into_inner();
//!
//! // Read it back.
//! let mut r = FsReader::open(Cursor::new(bytes)).unwrap();
//! r.verify().unwrap();
//! assert_eq!(r.read_path("docs/hello.txt").unwrap(), b"Hello, world\n");
//! ```

mod compact;
mod compress;
pub mod consts;
mod delta;
mod dirsync;
mod error;
mod fs;
mod node;
mod reader;
mod session;
mod tree;
mod vector;
mod writer;

pub use compact::{compact, compact_archive};
pub use compress::{compress_deflate, decompress};
pub use consts::*;
pub use dirsync::{create_archive, extract_archive, session_at_time, update_archive, SyncOptions};
pub use error::{Error, Result};
pub use fs::FsReader;
pub use node::{ContentSection, NodeRecord};
pub use reader::{build_node_view, scan, verify_chain, NodeView, Scan, SessionView};
pub use session::{member_blocks_digest, SessionRecord};
pub use tree::{build_tree, current_delta_depth, is_live, read_file, resolve_path, Tree};
pub use vector::build_reference_vector;
pub use writer::{new_id, Change, FsWriter, Partition};

// Re-export the underlying hash registry for convenience.
pub use pcf::HashAlgo;
