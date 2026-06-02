//! Directory <-> archive tooling: build an archive from a host directory,
//! update it from a directory, and extract it back to a directory.
//!
//! This is the only module that touches the host filesystem. Each `create` or
//! `update` is committed as a SINGLE session via [`FsWriter::commit_changes`]
//! (one "burn"), and `extract` can reconstruct any point in history. Symlinks
//! and other non-regular files are skipped with a warning; only regular files
//! and directories are imported.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::path::Path;
use std::time::UNIX_EPOCH;

use pcf::HashAlgo;

use crate::error::{Error, Result};
use crate::fs::FsReader;
use crate::tree::Tree;
use crate::writer::{Change, FsWriter};
use crate::ROOT_NODE_ID;

/// Options for [`create_archive`] / [`update_archive`].
#[derive(Debug, Clone, Copy)]
pub struct SyncOptions {
    /// Compress file content with DEFLATE when smaller (Section 9.5).
    pub compress: bool,
    /// Capture POSIX mode + mtime from the source into the archive.
    pub metadata: bool,
    /// (update only) Tombstone archive entries absent from the source (mirror).
    pub delete: bool,
}

impl Default for SyncOptions {
    fn default() -> Self {
        SyncOptions {
            compress: true,
            metadata: true,
            delete: false,
        }
    }
}

// ---- metadata capture / restore -----------------------------------------

#[cfg(unix)]
fn mode_of(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}
#[cfg(not(unix))]
fn mode_of(_meta: &fs::Metadata) -> u32 {
    0
}

fn mtime_ms_of(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(unix)]
fn restore_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if mode != 0 {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    }
}
#[cfg(not(unix))]
fn restore_mode(_path: &Path, _mode: u32) {}

fn restore_mtime(path: &Path, mtime_ms: u64) {
    if mtime_ms != 0 {
        let secs = (mtime_ms / 1000) as i64;
        let nanos = ((mtime_ms % 1000) * 1_000_000) as u32;
        let _ = filetime::set_file_mtime(path, filetime::FileTime::from_unix_time(secs, nanos));
    }
}

// ---- walking the source tree --------------------------------------------

fn collect_changes(src: &Path, opts: &SyncOptions) -> Result<Vec<Change>> {
    let mut out = Vec::new();
    walk(src, "", opts, &mut out)?;
    Ok(out)
}

fn walk(dir: &Path, prefix: &str, opts: &SyncOptions, out: &mut Vec<Change>) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let path = e.path();
        let ft = fs::symlink_metadata(&path)?.file_type();
        let name = e.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if ft.is_symlink() {
            eprintln!("pfs: skipping symlink {}", path.display());
            continue;
        }
        if ft.is_dir() {
            let meta = fs::metadata(&path)?;
            let (mode, mtime) = if opts.metadata {
                (mode_of(&meta), mtime_ms_of(&meta))
            } else {
                (0, 0)
            };
            out.push(Change::Mkdir {
                path: rel.clone(),
                mode,
                mtime_unix_ms: mtime,
            });
            walk(&path, &rel, opts, out)?;
        } else if ft.is_file() {
            let meta = fs::metadata(&path)?;
            let (mode, mtime) = if opts.metadata {
                (mode_of(&meta), mtime_ms_of(&meta))
            } else {
                (0, 0)
            };
            let content = fs::read(&path)?;
            out.push(Change::PutFile {
                path: rel,
                content,
                mode,
                mtime_unix_ms: mtime,
            });
        } else {
            eprintln!("pfs: skipping special file {}", path.display());
        }
    }
    Ok(())
}

fn open_rw(archive: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(archive)
        .map_err(Error::Io)
}

// ---- public operations ---------------------------------------------------

/// Create a brand-new archive from the contents of `src`. Fails if `archive`
/// already exists. The root directory is session 1; the imported tree is
/// session 2 (a single session regardless of file count).
pub fn create_archive(archive: &Path, src: &Path, opts: &SyncOptions) -> Result<()> {
    if !fs::metadata(src)?.is_dir() {
        return Err(Error::NotADirectory);
    }
    let changes = collect_changes(src, opts)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(archive)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Error::AlreadyExists
            } else {
                Error::Io(e)
            }
        })?;
    let mut w = FsWriter::mkfs(file, HashAlgo::Sha256)?;
    w.set_writer_id(b"pfs-create");
    w.set_compression(opts.compress);
    w.commit_changes(&changes)?;
    Ok(())
}

/// Update an existing archive from `src`: add new files, update changed ones,
/// and (when `opts.delete`) tombstone live archive entries absent from `src`.
/// All of it is one session.
pub fn update_archive(archive: &Path, src: &Path, opts: &SyncOptions) -> Result<()> {
    if !fs::metadata(src)?.is_dir() {
        return Err(Error::NotADirectory);
    }
    let mut changes = collect_changes(src, opts)?;

    if opts.delete {
        // Paths present in the source (normalised, '/'-separated).
        let source: HashSet<String> = changes
            .iter()
            .map(|c| match c {
                Change::Mkdir { path, .. } => path.clone(),
                Change::PutFile { path, .. } => path.clone(),
                Change::Remove { path } => path.clone(),
            })
            .collect();
        // Live archive paths; tombstone any not in the source.
        let live = {
            let mut r = FsReader::open(open_rw(archive)?)?;
            let tree = r.tree()?;
            live_paths(&tree)
        };
        for p in live {
            if !source.contains(&p) {
                changes.push(Change::Remove { path: p });
            }
        }
    }

    let mut w = FsWriter::open(open_rw(archive)?)?;
    w.set_writer_id(b"pfs-update");
    w.set_compression(opts.compress);
    w.commit_changes(&changes)?;
    Ok(())
}

/// Extract the archive's tree (optionally as of session `at`) into `dst`,
/// restoring mode + mtime when `metadata` is true.
pub fn extract_archive(archive: &Path, dst: &Path, at: Option<u64>, metadata: bool) -> Result<()> {
    let mut r = FsReader::open(open_rw(archive)?)?;
    let tree = r.tree_as_of(at)?;
    fs::create_dir_all(dst)?;
    extract_dir(&mut r, &tree, ROOT_NODE_ID, dst, "", at, metadata)?;
    Ok(())
}

/// Resolve a unix-millisecond timestamp to the newest session_seq committed at
/// or before it (0 if none), for `extract --at-time`.
pub fn session_at_time(archive: &Path, unix_ms: u64) -> Result<u64> {
    let mut r = FsReader::open(open_rw(archive)?)?;
    let mut best = 0u64;
    for s in r.list_sessions()? {
        if s.timestamp_unix_ms <= unix_ms && s.session_seq > best {
            best = s.session_seq;
        }
    }
    Ok(best)
}

// ---- helpers --------------------------------------------------------------

/// All live node paths in the tree (directories and files), root excluded.
fn live_paths(tree: &Tree) -> Vec<String> {
    let mut out = Vec::new();
    collect_paths(tree, ROOT_NODE_ID, "", &mut out);
    out
}

fn collect_paths(tree: &Tree, node: [u8; 16], prefix: &str, out: &mut Vec<String>) {
    if let Some(kids) = tree.children.get(&node) {
        for &cid in kids {
            if let Some(rec) = tree.nodes.get(&cid) {
                let name = rec.name_str();
                let rel = if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                };
                out.push(rel.clone());
                if rec.is_dir() {
                    collect_paths(tree, cid, &rel, out);
                }
            }
        }
    }
}

fn extract_dir<S: std::io::Read + std::io::Write + std::io::Seek>(
    r: &mut FsReader<S>,
    tree: &Tree,
    node: [u8; 16],
    host_dir: &Path,
    prefix: &str,
    at: Option<u64>,
    metadata: bool,
) -> Result<()> {
    let kids = match tree.children.get(&node) {
        Some(k) => k.clone(),
        None => return Ok(()),
    };
    for cid in kids {
        let rec = tree.nodes.get(&cid).ok_or(Error::NotFound)?.clone();
        let name = rec.name_str();
        let host = host_dir.join(&name);
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if rec.is_dir() {
            fs::create_dir_all(&host)?;
            extract_dir(r, tree, cid, &host, &rel, at, metadata)?;
            // Restore directory metadata AFTER its children are written.
            if metadata {
                restore_mode(&host, rec.mode);
                restore_mtime(&host, rec.mtime_unix_ms);
            }
        } else {
            let content = r.read_path_as_of(&rel, at)?;
            fs::write(&host, &content)?;
            if metadata {
                restore_mode(&host, rec.mode);
                restore_mtime(&host, rec.mtime_unix_ms);
            }
        }
    }
    Ok(())
}
