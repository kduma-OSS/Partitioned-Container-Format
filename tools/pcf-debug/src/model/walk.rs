//! A defensive, read-only walk of a PCF file's physical structure.
//!
//! Unlike [`pcf::Container`], which flattens the table-block chain into a single
//! list of entries and hides per-block layout, this walk preserves the chain:
//! every block's offset, header, entry array, chain link, and stored-vs-computed
//! table hash. It reuses the crate's public byte parsers (`*::from_bytes`) so it
//! never re-implements the format, but it tolerates corruption that
//! `Container::open` would reject.

use pcf::{
    compute_table_hash, FileHeader, HashAlgo, PartitionEntry, TableBlockHeader, ENTRY_SIZE,
    HEADER_SIZE, TABLE_HEADER_SIZE,
};

use super::diag::{DiagKind, Diagnostic};

/// Maximum number of table blocks we will follow before giving up.
const MAX_BLOCKS: usize = 4096;

/// One partition entry as physically found in a block.
#[derive(Debug, Clone)]
pub struct EntryView {
    pub slot: usize,
    pub entry: PartitionEntry,
    /// `Ok` if [`PartitionEntry::validate`] passed, else the stringified reason.
    pub validate_ok: Result<(), String>,
    /// `Some(true/false)` when the data region is readable and the algorithm
    /// verifies; `None` when unreadable or the algorithm is `None`.
    pub data_hash_ok: Option<bool>,
    /// Whether `[start_offset, start_offset + used_bytes)` lies within the file.
    pub data_in_bounds: bool,
}

/// One table block as physically found in the chain.
#[derive(Debug, Clone)]
pub struct BlockView {
    pub index: usize,
    pub offset: u64,
    pub header: TableBlockHeader,
    pub entries: Vec<EntryView>,
    pub next_offset: u64,
    pub stored_table_hash: [u8; 64],
    /// `Some(true/false)` when recomputable; `None` if the algorithm is `None`
    /// or the block's entries could not all be parsed.
    pub table_hash_ok: Option<bool>,
}

/// The result of walking a file.
#[derive(Debug, Clone)]
pub struct Walk {
    pub file_len: u64,
    pub header: Option<FileHeader>,
    pub blocks: Vec<BlockView>,
    pub diagnostics: Vec<Diagnostic>,
}

fn read_array<const N: usize>(data: &[u8], off: usize) -> Option<[u8; N]> {
    data.get(off..off + N)?.try_into().ok()
}

/// Walk `data` (the whole file loaded into memory) and build a structural model.
///
/// When `verify` is false, data and table hashes are not computed (a fast path
/// for very large files); the corresponding `*_hash_ok` fields stay `None`.
pub fn walk(data: &[u8], verify: bool) -> Walk {
    let file_len = data.len() as u64;
    let mut diagnostics = Vec::new();

    // ---- header ----------------------------------------------------------
    let header = match read_array::<{ HEADER_SIZE as usize }>(data, 0) {
        Some(buf) => match FileHeader::from_bytes(&buf) {
            Ok(h) => Some(h),
            Err(e) => {
                diagnostics.push(Diagnostic::error(
                    DiagKind::BadHeader {
                        reason: format!("{e:?}"),
                    },
                    format!("file header is invalid: {e:?}"),
                ));
                None
            }
        },
        None => {
            diagnostics.push(Diagnostic::error(
                DiagKind::BadHeader {
                    reason: "file shorter than 20-byte header".into(),
                },
                format!("file is only {file_len} bytes; a PCF header needs {HEADER_SIZE}"),
            ));
            None
        }
    };

    // ---- block chain -----------------------------------------------------
    let mut blocks = Vec::new();
    let mut visited: Vec<u64> = Vec::new();
    if let Some(h) = header {
        let mut off = h.partition_table_offset;
        let mut index = 0usize;
        while off != 0 {
            if blocks.len() >= MAX_BLOCKS {
                diagnostics.push(Diagnostic::error(
                    DiagKind::ChainCycle { at_offset: off },
                    format!("chain exceeds {MAX_BLOCKS} blocks; stopping (possible cycle)"),
                ));
                break;
            }
            if visited.contains(&off) {
                diagnostics.push(Diagnostic::error(
                    DiagKind::ChainCycle { at_offset: off },
                    format!("table-block chain cycles back to offset {off:#x}"),
                ));
                break;
            }
            visited.push(off);

            let hdr_buf = match read_array::<{ TABLE_HEADER_SIZE as usize }>(data, off as usize) {
                Some(b) => b,
                None => {
                    diagnostics.push(Diagnostic::error(
                        DiagKind::Truncated {
                            start: off,
                            want: off + TABLE_HEADER_SIZE,
                            have: file_len,
                        },
                        format!("table block at {off:#x} runs past end of file"),
                    ));
                    break;
                }
            };
            let bh = match TableBlockHeader::from_bytes(&hdr_buf) {
                Ok(bh) => bh,
                Err(e) => {
                    diagnostics.push(Diagnostic::error(
                        DiagKind::BadBlock {
                            offset: off,
                            reason: format!("{e:?}"),
                        },
                        format!("table block header at {off:#x} is invalid: {e:?}"),
                    ));
                    break;
                }
            };

            // Parse the entries that follow the header.
            let mut entries = Vec::with_capacity(bh.partition_count as usize);
            let mut all_entries_parsed = true;
            for i in 0..bh.partition_count as u64 {
                let eoff = off + TABLE_HEADER_SIZE + i * ENTRY_SIZE;
                let ebuf = match read_array::<{ ENTRY_SIZE as usize }>(data, eoff as usize) {
                    Some(b) => b,
                    None => {
                        all_entries_parsed = false;
                        diagnostics.push(Diagnostic::error(
                            DiagKind::Truncated {
                                start: eoff,
                                want: eoff + ENTRY_SIZE,
                                have: file_len,
                            },
                            format!(
                                "entry {i} of block {index} at {eoff:#x} runs past end of file"
                            ),
                        ));
                        break;
                    }
                };
                let entry = match PartitionEntry::from_bytes(&ebuf) {
                    Ok(e) => e,
                    Err(e) => {
                        all_entries_parsed = false;
                        diagnostics.push(Diagnostic::warn(
                            DiagKind::BadBlock {
                                offset: eoff,
                                reason: format!("{e:?}"),
                            },
                            format!("entry {i} of block {index} could not be parsed: {e:?}"),
                        ));
                        break;
                    }
                };

                let validate_ok = entry.validate().map_err(|e| format!("{e:?}"));
                if let Err(reason) = &validate_ok {
                    diagnostics.push(Diagnostic::warn(
                        DiagKind::EntryInvalid {
                            uid: entry.uid,
                            reason: reason.clone(),
                        },
                        format!(
                            "entry '{}' fails conformance: {reason}",
                            entry.label_string().unwrap_or_default()
                        ),
                    ));
                }

                let start = entry.start_offset;
                let used = entry.used_bytes;
                let data_in_bounds = start
                    .checked_add(used)
                    .map(|e| e <= file_len)
                    .unwrap_or(false);
                if used > 0 && !data_in_bounds {
                    diagnostics.push(Diagnostic::error(
                        DiagKind::Truncated {
                            start,
                            want: start.saturating_add(used),
                            have: file_len,
                        },
                        format!(
                            "data of partition '{}' at {start:#x} runs past end of file",
                            entry.label_string().unwrap_or_default()
                        ),
                    ));
                }
                let data_hash_ok = if !verify || !entry.data_hash_algo.verifies() {
                    None
                } else if data_in_bounds {
                    let slice = &data[start as usize..(start + used) as usize];
                    let ok = entry.data_hash_algo.verify(slice, &entry.data_hash);
                    if !ok {
                        diagnostics.push(Diagnostic::error(
                            DiagKind::DataHashMismatch { uid: entry.uid },
                            format!(
                                "data hash mismatch for partition '{}'",
                                entry.label_string().unwrap_or_default()
                            ),
                        ));
                    }
                    Some(ok)
                } else {
                    None
                };

                entries.push(EntryView {
                    slot: i as usize,
                    entry,
                    validate_ok,
                    data_hash_ok,
                    data_in_bounds,
                });
            }

            // Verify the table hash over [header-with-zeroed-hash || entries].
            let table_hash_ok = if !verify || !bh.table_hash_algo.verifies() || !all_entries_parsed
            {
                None
            } else {
                let parsed: Vec<PartitionEntry> = entries.iter().map(|e| e.entry.clone()).collect();
                let computed =
                    compute_table_hash(bh.table_hash_algo, bh.next_table_offset, &parsed);
                let n = bh.table_hash_algo.digest_len();
                let ok = computed[..n] == bh.table_hash[..n];
                if !ok {
                    diagnostics.push(Diagnostic::error(
                        DiagKind::TableHashMismatch { block_index: index },
                        format!("table hash mismatch for block {index} at {off:#x}"),
                    ));
                }
                Some(ok)
            };

            let next = bh.next_table_offset;
            if next != 0 && next <= off {
                diagnostics.push(Diagnostic::info(
                    DiagKind::BackwardChainLink {
                        from: off,
                        to: next,
                    },
                    format!("block {index} links backward: {off:#x} -> {next:#x}"),
                ));
            }

            blocks.push(BlockView {
                index,
                offset: off,
                header: bh.clone(),
                entries,
                next_offset: next,
                stored_table_hash: bh.table_hash,
                table_hash_ok,
            });

            off = next;
            index += 1;
        }
    }

    Walk {
        file_len,
        header,
        blocks,
        diagnostics,
    }
}

/// Convenience: a flat copy of every parsed entry, in chain order.
pub fn flat_entries(walk: &Walk) -> Vec<&EntryView> {
    walk.blocks.iter().flat_map(|b| b.entries.iter()).collect()
}

/// Look up a hash algorithm's display name without exposing internals.
pub fn algo_name(algo: HashAlgo) -> &'static str {
    match algo.id() {
        0 => "none",
        1 => "crc32",
        2 => "crc32c",
        3 => "crc64",
        4 => "md5",
        5 => "sha1",
        16 => "sha256",
        17 => "sha512",
        18 => "blake3",
        _ => "unknown",
    }
}
