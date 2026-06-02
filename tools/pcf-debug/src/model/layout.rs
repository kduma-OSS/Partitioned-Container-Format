//! The physical byte-layout model: every region of the file, plus the gaps and
//! overlaps between them, derived from a [`Walk`](super::walk::Walk).

use pcf::{FileHeader, ENTRY_SIZE, HEADER_SIZE, TABLE_HEADER_SIZE};

use super::diag::{DiagKind, Diagnostic, Severity};
use super::walk::{BlockView, Walk};

/// What a physical byte range is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegionKind {
    FileHeader,
    TableBlockHeader {
        block_index: usize,
    },
    EntryArray {
        block_index: usize,
        entry_count: u8,
    },
    PartitionData {
        uid: [u8; 16],
        partition_type: u32,
        used: u64,
        max: u64,
    },
    /// Reserved-but-unused tail of a partition (`max_length - used_bytes`).
    Slack {
        uid: [u8; 16],
    },
    /// Dead space covered by no declared region.
    Gap,
}

impl RegionKind {
    /// A single-letter glyph used in the compact ASCII strip.
    pub fn glyph(&self) -> char {
        match self {
            RegionKind::FileHeader => 'H',
            RegionKind::TableBlockHeader { .. } => 'T',
            RegionKind::EntryArray { .. } => 'E',
            RegionKind::PartitionData { .. } => 'D',
            RegionKind::Slack { .. } => '_',
            RegionKind::Gap => '.',
        }
    }

    /// Stable short name used by the `--region` filter and HTML classes.
    pub fn short(&self) -> &'static str {
        match self {
            RegionKind::FileHeader => "header",
            RegionKind::TableBlockHeader { .. } => "tableheader",
            RegionKind::EntryArray { .. } => "entries",
            RegionKind::PartitionData { .. } => "data",
            RegionKind::Slack { .. } => "slack",
            RegionKind::Gap => "gap",
        }
    }
}

/// One contiguous physical byte range.
#[derive(Debug, Clone)]
pub struct Region {
    pub start: u64,
    pub len: u64,
    pub kind: RegionKind,
    pub label: String,
}

impl Region {
    pub fn end(&self) -> u64 {
        self.start.saturating_add(self.len)
    }
}

/// The full physical model of one file.
#[derive(Debug, Clone)]
pub struct LayoutMap {
    pub file_len: u64,
    pub header: Option<FileHeader>,
    pub blocks: Vec<BlockView>,
    /// Sorted by start; gaps materialised, overlaps recorded as diagnostics.
    pub regions: Vec<Region>,
    pub diagnostics: Vec<Diagnostic>,
}

/// Build the layout model from a walk of the file.
pub fn build(walk: &Walk) -> LayoutMap {
    let mut diagnostics = walk.diagnostics.clone();
    let mut regions: Vec<Region> = Vec::new();

    // Header.
    if walk.file_len >= HEADER_SIZE {
        regions.push(Region {
            start: 0,
            len: HEADER_SIZE,
            kind: RegionKind::FileHeader,
            label: "file header".into(),
        });
    }

    // Per-block header + entry array, and per-partition data + slack.
    for b in &walk.blocks {
        regions.push(Region {
            start: b.offset,
            len: TABLE_HEADER_SIZE,
            kind: RegionKind::TableBlockHeader {
                block_index: b.index,
            },
            label: format!("block {} header", b.index),
        });
        let count = b.header.partition_count;
        if count > 0 {
            regions.push(Region {
                start: b.offset + TABLE_HEADER_SIZE,
                len: count as u64 * ENTRY_SIZE,
                kind: RegionKind::EntryArray {
                    block_index: b.index,
                    entry_count: count,
                },
                label: format!("block {} entries (x{count})", b.index),
            });
        }

        for ev in &b.entries {
            let e = &ev.entry;
            let label = e.label_string().unwrap_or_default();
            if e.used_bytes > 0 {
                regions.push(Region {
                    start: e.start_offset,
                    len: e.used_bytes,
                    kind: RegionKind::PartitionData {
                        uid: e.uid,
                        partition_type: e.partition_type,
                        used: e.used_bytes,
                        max: e.max_length,
                    },
                    label: format!("data: {label}"),
                });
            }
            let slack = e.max_length.saturating_sub(e.used_bytes);
            if slack > 0 {
                regions.push(Region {
                    start: e.start_offset + e.used_bytes,
                    len: slack,
                    kind: RegionKind::Slack { uid: e.uid },
                    label: format!("slack: {label}"),
                });
            }
        }
    }

    // Sort by start (then by length so zero-length regions sort first).
    regions.sort_by(|a, b| a.start.cmp(&b.start).then(a.len.cmp(&b.len)));

    // Walk the sorted list to materialise gaps and record overlaps.
    let mut out: Vec<Region> = Vec::with_capacity(regions.len());
    let mut covered_end: u64 = 0;
    for r in regions.into_iter() {
        if r.start > covered_end {
            let gap_len = r.start - covered_end;
            diagnostics.push(Diagnostic {
                severity: Severity::Info,
                kind: DiagKind::Gap {
                    start: covered_end,
                    len: gap_len,
                },
                message: format!("{gap_len} dead byte(s) at {covered_end:#x}"),
            });
            out.push(Region {
                start: covered_end,
                len: gap_len,
                kind: RegionKind::Gap,
                label: "gap".into(),
            });
        } else if r.start < covered_end && r.len > 0 {
            let ov = covered_end - r.start;
            diagnostics.push(Diagnostic {
                severity: Severity::Warning,
                kind: DiagKind::Overlap {
                    start: r.start,
                    len: ov.min(r.len),
                },
                message: format!(
                    "region '{}' at {:#x} overlaps the preceding region",
                    r.label, r.start
                ),
            });
        }
        covered_end = covered_end.max(r.end());
        out.push(r);
    }
    if covered_end < walk.file_len {
        let gap_len = walk.file_len - covered_end;
        diagnostics.push(Diagnostic {
            severity: Severity::Info,
            kind: DiagKind::Gap {
                start: covered_end,
                len: gap_len,
            },
            message: format!("{gap_len} trailing dead byte(s) at {covered_end:#x}"),
        });
        out.push(Region {
            start: covered_end,
            len: gap_len,
            kind: RegionKind::Gap,
            label: "trailing gap".into(),
        });
    }

    LayoutMap {
        file_len: walk.file_len,
        header: walk.header,
        blocks: walk.blocks.clone(),
        regions: out,
        diagnostics,
    }
}
