//! Filesystem semantics over a node view: liveness, the directory tree, path
//! resolution, and file content reconstruction (Sections 9.3, 10).

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, Write};

use pcf::Container;

use crate::consts::*;
use crate::error::{Error, Result};
use crate::node::{ContentSection, NodeRecord};
use crate::reader::{NodeView, Scan};

/// A directory's live children keyed by name, each mapped to the winning
/// `(session_seq, node_id)` used to resolve collisions (Section 10.3).
type SiblingNames = HashMap<Vec<u8>, (u64, [u8; 16])>;

/// The reconstructed directory tree at a point in history.
#[derive(Debug, Clone, Default)]
pub struct Tree {
    /// Live nodes by node_id (the current record for each).
    pub nodes: HashMap<[u8; 16], NodeRecord>,
    /// Live children (node_ids) of each live directory, name-deduplicated.
    pub children: HashMap<[u8; 16], Vec<[u8; 16]>>,
}

/// Memoised liveness with cycle detection (Section 10.2, spec R6).
struct Liveness<'a> {
    view: &'a NodeView,
    memo: HashMap<[u8; 16], bool>,
}

impl<'a> Liveness<'a> {
    fn new(view: &'a NodeView) -> Self {
        Liveness {
            view,
            memo: HashMap::new(),
        }
    }

    fn is_live(&mut self, id: [u8; 16]) -> Result<bool> {
        let mut stack: HashSet<[u8; 16]> = HashSet::new();
        self.walk(id, &mut stack)
    }

    fn walk(&mut self, id: [u8; 16], stack: &mut HashSet<[u8; 16]>) -> Result<bool> {
        if let Some(&v) = self.memo.get(&id) {
            return Ok(v);
        }
        if !stack.insert(id) {
            return Err(Error::ParentCycle);
        }

        let result: Result<bool> = (|| {
            if id == ROOT_NODE_ID {
                // The root is live unless an explicit record tombstones it; if
                // absent it is synthesized as a live empty directory.
                return Ok(match self.view.current.get(&ROOT_NODE_ID) {
                    Some((_, r)) => !r.is_tombstone(),
                    None => true,
                });
            }
            let (_, rec) = match self.view.current.get(&id) {
                Some(x) => x,
                None => return Ok(false),
            };
            if rec.is_tombstone() {
                return Ok(false);
            }
            let parent = rec.parent_id;
            // A non-root node parenting itself can never reach the root.
            if parent == id {
                return Ok(false);
            }
            if !self.walk(parent, stack)? {
                return Ok(false);
            }
            // The parent must be a live directory.
            let parent_is_dir = if parent == ROOT_NODE_ID {
                true
            } else {
                self.view
                    .current
                    .get(&parent)
                    .map(|(_, r)| r.is_dir())
                    .unwrap_or(false)
            };
            Ok(parent_is_dir)
        })();

        stack.remove(&id);
        let live = result?;
        self.memo.insert(id, live);
        Ok(live)
    }
}

/// True iff `id` resolves to a live node in `view`.
pub fn is_live(view: &NodeView, id: [u8; 16]) -> Result<bool> {
    Liveness::new(view).is_live(id)
}

/// Build the live directory tree, enforcing unique names among live siblings
/// (Section 10.3): on a collision the greater session_seq wins.
pub fn build_tree(view: &NodeView) -> Result<Tree> {
    let mut live = Liveness::new(view);
    let mut tree = Tree::default();

    // Synthesize the root if no explicit record exists.
    let root_rec = match view.current.get(&ROOT_NODE_ID) {
        Some((_, r)) => r.clone(),
        None => NodeRecord {
            kind: KIND_DIR,
            flags: 0,
            node_id: ROOT_NODE_ID,
            parent_id: ROOT_NODE_ID,
            mtime_unix_ms: 0,
            mode: 0,
            name: Vec::new(),
            content: None,
        },
    };
    if !root_rec.is_tombstone() {
        tree.nodes.insert(ROOT_NODE_ID, root_rec);
        tree.children.entry(ROOT_NODE_ID).or_default();
    }

    // Collect every live node.
    for (&id, (_, rec)) in view.current.iter() {
        if id == ROOT_NODE_ID {
            continue;
        }
        if live.is_live(id)? {
            tree.nodes.insert(id, rec.clone());
            if rec.is_dir() {
                tree.children.entry(id).or_default();
            }
        }
    }

    // Attach children to parents, resolving name collisions by greater seq.
    // parent_id -> (name -> (winning_seq, winning_id))
    let mut by_parent: HashMap<[u8; 16], SiblingNames> = HashMap::new();
    for (&id, rec) in tree.nodes.iter() {
        if id == ROOT_NODE_ID {
            continue;
        }
        let seq = view.current.get(&id).map(|(s, _)| *s).unwrap_or(0);
        let slot = by_parent.entry(rec.parent_id).or_default();
        match slot.get(&rec.name) {
            Some(&(other_seq, _)) if other_seq >= seq => { /* keep existing winner */ }
            _ => {
                slot.insert(rec.name.clone(), (seq, id));
            }
        }
    }
    for (parent, names) in by_parent {
        let entry = tree.children.entry(parent).or_default();
        for (_, (_, id)) in names {
            entry.push(id);
        }
    }
    // Stable, name-sorted children for deterministic listings.
    for kids in tree.children.values_mut() {
        kids.sort_by(|a, b| {
            let na = tree
                .nodes
                .get(a)
                .map(|r| r.name.clone())
                .unwrap_or_default();
            let nb = tree
                .nodes
                .get(b)
                .map(|r| r.name.clone())
                .unwrap_or_default();
            na.cmp(&nb)
        });
    }

    Ok(tree)
}

/// Resolve a '/'-separated path to a live node_id. "" or "/" is the root.
pub fn resolve_path(tree: &Tree, path: &str) -> Result<[u8; 16]> {
    let mut cur = ROOT_NODE_ID;
    if !tree.nodes.contains_key(&ROOT_NODE_ID) {
        return Err(Error::NotFound);
    }
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        let kids = tree.children.get(&cur).ok_or(Error::NotADirectory)?;
        let next = kids.iter().find(|id| {
            tree.nodes
                .get(*id)
                .map(|r| r.name == comp.as_bytes())
                .unwrap_or(false)
        });
        match next {
            Some(&id) => cur = id,
            None => return Err(Error::NotFound),
        }
    }
    Ok(cur)
}

/// Reconstruct the current content of a live file node (Section 9.3).
pub fn read_file<S: Read + Write + Seek>(
    c: &mut Container<S>,
    scan: &Scan,
    view: &NodeView,
    node_id: [u8; 16],
) -> Result<Vec<u8>> {
    let history = view.history.get(&node_id).ok_or(Error::NotFound)?;
    // Content-bearing versions (excludes tombstones/dirs), descending seq.
    let chain: Vec<&NodeRecord> = history
        .iter()
        .filter_map(|(_, r)| if r.content.is_some() { Some(r) } else { None })
        .collect();
    if chain.is_empty() {
        return Err(Error::NotFound);
    }
    materialize(c, scan, &chain, 0, 0)
}

fn materialize<S: Read + Write + Seek>(
    c: &mut Container<S>,
    scan: &Scan,
    chain: &[&NodeRecord],
    k: usize,
    depth: usize,
) -> Result<Vec<u8>> {
    if depth > MIN_READER_DELTA_DEPTH.max(4096) {
        return Err(Error::DeltaTooDeep);
    }
    let rec = chain.get(k).ok_or(Error::MissingBase)?;
    let content = rec.content.as_ref().ok_or(Error::MissingBase)?;
    match content {
        ContentSection::Empty => Ok(Vec::new()),
        ContentSection::Inherit => materialize(c, scan, chain, k + 1, depth + 1),
        ContentSection::Direct {
            compression_algo,
            content_uid,
            full_size,
            full_hash_algo,
            full_hash,
        } => {
            let entry = scan
                .uid_index
                .get(content_uid)
                .ok_or(Error::MissingContent)?
                .clone();
            let stored = c.read_partition_data(&entry)?;
            if !entry.data_hash_algo.verify(&stored, &entry.data_hash) {
                return Err(Error::ContentHashMismatch);
            }
            let data = crate::compress::decompress(*compression_algo, &stored)?;
            if data.len() as u64 != *full_size || !full_hash_algo.verify(&data, full_hash) {
                return Err(Error::ContentHashMismatch);
            }
            Ok(data)
        }
        ContentSection::Delta {
            patch_algo,
            compression_algo,
            patch_uid,
            full_size,
            full_hash_algo,
            full_hash,
            base_full_size,
            base_full_hash_algo,
            base_full_hash,
        } => {
            let base = materialize(c, scan, chain, k + 1, depth + 1)?;
            if base.len() as u64 != *base_full_size
                || !base_full_hash_algo.verify(&base, base_full_hash)
            {
                return Err(Error::ContentHashMismatch);
            }
            let entry = scan
                .uid_index
                .get(patch_uid)
                .ok_or(Error::MissingContent)?
                .clone();
            let stored = c.read_partition_data(&entry)?;
            if !entry.data_hash_algo.verify(&stored, &entry.data_hash) {
                return Err(Error::ContentHashMismatch);
            }
            let patch = crate::compress::decompress(*compression_algo, &stored)?;
            let bytes = crate::delta::apply(*patch_algo, &base, &patch)?;
            if bytes.len() as u64 != *full_size || !full_hash_algo.verify(&bytes, full_hash) {
                return Err(Error::ContentHashMismatch);
            }
            Ok(bytes)
        }
    }
}

/// The current delta depth of a live file node: the number of consecutive
/// DELTA/INHERIT records before the first EMPTY/DIRECT (Section 9.4). Returns 0
/// if the node has no content-bearing history.
pub fn current_delta_depth(view: &NodeView, node_id: [u8; 16]) -> usize {
    let history = match view.history.get(&node_id) {
        Some(h) => h,
        None => return 0,
    };
    let mut depth = 0;
    for (_, r) in history.iter() {
        match &r.content {
            Some(ContentSection::Delta { .. }) | Some(ContentSection::Inherit) => depth += 1,
            Some(_) => break, // EMPTY or DIRECT terminates the chain
            None => continue, // tombstone/dir: skip
        }
    }
    depth
}
