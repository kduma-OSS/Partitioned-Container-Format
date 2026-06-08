//! PFS-MS-aware compaction: rebuild a multi-session file into a fresh,
//! single-session snapshot of its current state (spec Section 15).
//!
//! Generic PCF compaction (PCF Section 11.5, [`pcf::Container::compacted_image`])
//! MUST NOT be used on a PFS-MS file: it repacks entries into shared blocks and
//! rewrites every `table_hash`, which destroys the one-`PFS_SESSION`-per-HEAD
//! invariant and the inter-session hash commitments (`member_blocks_digest`,
//! `prev_session_hash`). The result no longer scans or verifies as PFS-MS.
//!
//! Compaction here is therefore profile-aware. It resolves the live tree at the
//! head and re-emits it as **one** session (`session_seq = 1`,
//! `prev_session_hash = 0`). This is a full rewrite that *discards history*:
//!
//! * deleted nodes are gone — only live nodes are re-emitted;
//! * every file is stored as fresh `Direct` (or `Empty`) content, collapsing
//!   any delta chain to the newest full version;
//! * superseded versions and abandoned tails are reclaimed.
//!
//! The output is a fully valid, verifiable PFS-MS file.

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

use pcf::HashAlgo;

use crate::error::{Error, Result};
use crate::fs::FsReader;
use crate::tree::Tree;
use crate::writer::{Change, FsWriter};
use crate::ROOT_NODE_ID;

/// Rebuild the PFS-MS file in `src` into a fresh, single-session image written
/// to `dst`, returning the destination handle.
///
/// The resolved current tree of `src` becomes session 1 (`session_seq = 1`,
/// `prev_session_hash = 0`); history is discarded (Section 15). The source is
/// verified before any output is produced, so a corrupt input is rejected
/// rather than propagated. `dst` must be a fresh, writable, empty handle.
///
/// The whole source tree (every live file's content) is materialised in memory
/// before `dst` is touched, so `src` and `dst` may be distinct handles to the
/// same logical data without interfering.
pub fn compact<R, W>(src: R, mut dst: W) -> Result<W>
where
    R: Read + Write + Seek,
    W: Read + Write + Seek,
{
    let mut r = FsReader::open(src)?;
    // Refuse to compact a corrupt source (mirrors pcf-compact's verify-before).
    r.verify()?;

    let algo = source_hash_algo(&mut r)?;
    let tree = r.tree()?;
    let changes = collect_changes(&mut r, &tree)?;

    let mut w = FsWriter::create(&mut dst, algo)?;
    w.set_writer_id(b"pfs-compact");
    w.set_compression(true);
    // An empty source tree yields no changes; `commit_changes` then commits
    // nothing and `dst` stays at the valid empty-table state from `create`.
    w.commit_changes(&changes)?;
    drop(w);

    Ok(dst)
}

/// Compact the PFS-MS file at `src` into `dst` on the host filesystem.
///
/// When `dst == src` the file is compacted in place. Output is written to a
/// sibling temp file, fsynced, and atomically renamed into place, so a crash
/// leaves either the original or the fully written replacement.
pub fn compact_archive(src: &Path, dst: &Path) -> Result<()> {
    // Build the compacted image in memory from the source.
    let image = {
        let in_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(src)
            .map_err(Error::Io)?;
        let out = compact(in_file, std::io::Cursor::new(Vec::new()))?;
        out.into_inner()
    };

    // Write to a sibling temp file, fsync, then atomically rename into place.
    let dir = dst.parent().filter(|p| !p.as_os_str().is_empty());
    let tmp: PathBuf = {
        let name = dst
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "pfs".into());
        let pid = std::process::id();
        let tmp_name = format!(".{name}.pfs-compact.tmp.{pid}");
        match dir {
            Some(d) => d.join(tmp_name),
            None => PathBuf::from(tmp_name),
        }
    };

    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)
        .map_err(Error::Io)?;
    f.write_all(&image).map_err(Error::Io)?;
    f.sync_all().map_err(Error::Io)?;
    drop(f);

    fs::rename(&tmp, dst).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        Error::Io(e)
    })?;
    Ok(())
}

/// The table-hash algorithm of the source's head session (`Sha256` if empty).
fn source_hash_algo<S: Read + Write + Seek>(r: &mut FsReader<S>) -> Result<HashAlgo> {
    let scan = r.scan()?;
    Ok(scan
        .sessions
        .first()
        .map(|s| s.block_hashes[0].2)
        .unwrap_or(HashAlgo::Sha256))
}

/// Build the change set re-creating the whole live tree in one session.
fn collect_changes<S: Read + Write + Seek>(
    r: &mut FsReader<S>,
    tree: &Tree,
) -> Result<Vec<Change>> {
    let mut out = Vec::new();
    walk(r, tree, ROOT_NODE_ID, "", &mut out)?;
    Ok(out)
}

fn walk<S: Read + Write + Seek>(
    r: &mut FsReader<S>,
    tree: &Tree,
    node: [u8; 16],
    prefix: &str,
    out: &mut Vec<Change>,
) -> Result<()> {
    let kids = match tree.children.get(&node) {
        Some(k) => k.clone(),
        None => return Ok(()),
    };
    for cid in kids {
        let rec = tree.nodes.get(&cid).ok_or(Error::NotFound)?;
        let name = rec.name_str();
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if rec.is_dir() {
            // Emit every directory (preserving empty ones), then recurse.
            out.push(Change::Mkdir {
                path: rel.clone(),
                mode: rec.mode,
                mtime_unix_ms: rec.mtime_unix_ms,
            });
            walk(r, tree, cid, &rel, out)?;
        } else {
            // Reconstruct the full current content; re-emitted as Direct/Empty.
            let (mode, mtime) = (rec.mode, rec.mtime_unix_ms);
            let content = r.read_path(&rel)?;
            out.push(Change::PutFile {
                path: rel,
                content,
                mode,
                mtime_unix_ms: mtime,
            });
        }
    }
    Ok(())
}
