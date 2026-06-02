//! The high-level [`FsReader`]: open a PFS-MS file and query the reconstructed
//! filesystem (Sections 11, 13).

use std::io::{Read, Seek, Write};

use pcf::Container;

use crate::error::{Error, Result};
use crate::reader::{build_node_view, scan, verify_chain, NodeView, Scan};
use crate::session::SessionRecord;
use crate::tree::{build_tree, read_file, resolve_path, Tree};

/// A read-only view over a PFS-MS file, backed by a PCF [`Container`].
pub struct FsReader<S: Read + Write + Seek> {
    container: Container<S>,
}

impl<S: Read + Write + Seek> FsReader<S> {
    /// Open a PFS-MS file (validates the PCF header, spec R1).
    pub fn open(storage: S) -> Result<Self> {
        Ok(Self {
            container: Container::open(storage)?,
        })
    }

    /// Consume the reader and return the backing store.
    pub fn into_storage(self) -> S {
        self.container.into_storage()
    }

    /// Scan the backward-linked session chain (spec R2, R3).
    pub fn scan(&mut self) -> Result<Scan> {
        scan(&mut self.container)
    }

    /// Full integrity check: PCF table/data hashes (R1, R7), the inter-session
    /// hash chain (R8), and node-view consistency including cycle and
    /// duplicate-node detection (R5, R6).
    pub fn verify(&mut self) -> Result<()> {
        self.container.verify()?;
        let scan = scan(&mut self.container)?;
        verify_chain(&scan)?;
        let view = build_node_view(&scan, None);
        build_tree(&view)?;
        Ok(())
    }

    /// The resolved node view at the head (or "as of" `max_seq`).
    pub fn node_view(&mut self, max_seq: Option<u64>) -> Result<NodeView> {
        let scan = scan(&mut self.container)?;
        Ok(build_node_view(&scan, max_seq))
    }

    /// The live directory tree at the head.
    pub fn tree(&mut self) -> Result<Tree> {
        self.tree_as_of(None)
    }

    /// The live directory tree as of `max_seq` (history query, Section 15).
    pub fn tree_as_of(&mut self, max_seq: Option<u64>) -> Result<Tree> {
        let scan = scan(&mut self.container)?;
        let view = build_node_view(&scan, max_seq);
        build_tree(&view)
    }

    /// Read a file's content at the head.
    pub fn read_path(&mut self, path: &str) -> Result<Vec<u8>> {
        self.read_path_as_of(path, None)
    }

    /// Read a file's content as of `max_seq` (history query, Section 15).
    pub fn read_path_as_of(&mut self, path: &str, max_seq: Option<u64>) -> Result<Vec<u8>> {
        let scan = scan(&mut self.container)?;
        let view = build_node_view(&scan, max_seq);
        let tree = build_tree(&view)?;
        let id = resolve_path(&tree, path)?;
        let rec = tree.nodes.get(&id).ok_or(Error::NotFound)?;
        if !rec.is_file() {
            return Err(Error::NotADirectory);
        }
        read_file(&mut self.container, &scan, &view, id)
    }

    /// All session records, newest first.
    pub fn list_sessions(&mut self) -> Result<Vec<SessionRecord>> {
        let scan = scan(&mut self.container)?;
        Ok(scan.sessions.into_iter().map(|s| s.record).collect())
    }
}
