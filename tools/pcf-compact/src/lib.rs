//! Library back-end for the `pcf-compact` binary.
//!
//! Exposes the pieces the integration tests want to drive directly without
//! spawning a subprocess: the in-memory compaction wrapper, the atomic
//! file-replacement helper, and the human-readable size formatter.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod cli;

/// Errors surfaced by the `pcf-compact` CLI and its library back-end.
#[derive(Debug)]
pub enum CompactError {
    Read {
        path: PathBuf,
        source: io::Error,
    },
    Write {
        path: PathBuf,
        source: io::Error,
    },
    Pcf(pcf::Error),
    OutputExists(PathBuf),
    SameInputOutput(PathBuf),
    /// `rename(2)` returned EXDEV — temp file and target on different filesystems.
    CrossDevice {
        tmp: PathBuf,
        target: PathBuf,
    },
}

impl std::fmt::Display for CompactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompactError::Read { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            CompactError::Write { path, source } => {
                write!(f, "cannot write {}: {source}", path.display())
            }
            CompactError::Pcf(e) => match e {
                pcf::Error::BadMagic => write!(f, "not a PCF file (bad magic)"),
                pcf::Error::UnsupportedMajor(v) => {
                    write!(f, "unsupported PCF major version {v}; this tool targets v1")
                }
                pcf::Error::TableHashMismatch => write!(
                    f,
                    "table block hash mismatch in input; run with --no-verify to compact anyway (data may be corrupt)"
                ),
                pcf::Error::DataHashMismatch => write!(
                    f,
                    "partition data hash mismatch in input; run with --no-verify to compact anyway (data may be corrupt)"
                ),
                other => write!(f, "{other}"),
            },
            CompactError::OutputExists(p) => {
                write!(f, "output {} already exists; use --force to overwrite", p.display())
            }
            CompactError::SameInputOutput(p) => write!(
                f,
                "--output {} is the same file as the input; omit --output for in-place compaction",
                p.display()
            ),
            CompactError::CrossDevice { tmp, target } => write!(
                f,
                "temp file {} and target {} are on different filesystems; atomic rename is not possible (write --output to a path on the same filesystem)",
                tmp.display(),
                target.display()
            ),
        }
    }
}

impl std::error::Error for CompactError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CompactError::Read { source, .. } | CompactError::Write { source, .. } => Some(source),
            CompactError::Pcf(e) => Some(e),
            _ => None,
        }
    }
}

impl From<pcf::Error> for CompactError {
    fn from(e: pcf::Error) -> Self {
        CompactError::Pcf(e)
    }
}

/// Produce a compacted PCF image from `input`.
///
/// `verify_before` runs `Container::verify` on the input first (catching
/// hash mismatches before any output is produced). `verify_after` re-opens
/// the freshly built image and verifies it (proves the output is well-formed).
pub fn compact_bytes(
    input: &[u8],
    verify_before: bool,
    verify_after: bool,
) -> Result<Vec<u8>, CompactError> {
    let mut c = pcf::Container::open(Cursor::new(input.to_vec()))?;
    if verify_before {
        c.verify()?;
    }
    let compacted = c.compacted_image()?;
    drop(c);

    if verify_after {
        let mut c2 = pcf::Container::open(Cursor::new(compacted.clone()))?;
        c2.verify()?;
    }
    Ok(compacted)
}

/// Atomically replace `target` with `bytes`.
///
/// Writes to a sibling temp file (`<name>.pcf-compact.tmp.<pid>.<nanos>`),
/// fsyncs the data, then `rename(2)`s into place. On crash, either the old
/// file is intact (rename did not commit) or the new file is fully durable
/// (rename committed and directory fsynced). A leftover temp file is the
/// only visible artifact of a crash mid-write; it is safe to delete.
///
/// `EXDEV` (cross-filesystem rename) is reported as `CrossDevice` rather
/// than silently falling back to a non-atomic copy.
pub fn atomic_write(target: &Path, bytes: &[u8]) -> Result<(), CompactError> {
    // Resolve symlinks so the temp file lands in the same directory as the
    // *real* target, and so the rename replaces the underlying file rather
    // than the link.
    let real = fs::canonicalize(target).unwrap_or_else(|_| target.to_path_buf());
    let dir = real
        .parent()
        .map(|p| {
            if p.as_os_str().is_empty() {
                Path::new(".")
            } else {
                p
            }
        })
        .unwrap_or(Path::new("."));
    let stem = real
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "pcf".to_string());

    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!("{stem}.pcf-compact.tmp.{pid}.{nanos}"));

    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| CompactError::Write {
            path: tmp.clone(),
            source: e,
        })?;

    // RAII cleanup: if anything below fails, remove the temp file on drop.
    let mut guard = TempGuard {
        path: Some(tmp.clone()),
    };

    f.write_all(bytes).map_err(|e| CompactError::Write {
        path: tmp.clone(),
        source: e,
    })?;
    f.sync_all().map_err(|e| CompactError::Write {
        path: tmp.clone(),
        source: e,
    })?;
    drop(f);

    match fs::rename(&tmp, &real) {
        Ok(()) => {
            // Best-effort directory fsync for crash-durability of the rename.
            if let Ok(d) = File::open(dir) {
                let _ = d.sync_all();
            }
            guard.commit();
            Ok(())
        }
        Err(e) if is_cross_device(&e) => Err(CompactError::CrossDevice {
            tmp: tmp.clone(),
            target: real,
        }),
        Err(e) => Err(CompactError::Write {
            path: real,
            source: e,
        }),
    }
}

/// On Linux EXDEV is 18. We keep it as a literal to avoid pulling in `libc`.
#[cfg(target_os = "linux")]
const EXDEV: i32 = 18;
#[cfg(not(target_os = "linux"))]
const EXDEV: i32 = 18;

fn is_cross_device(e: &io::Error) -> bool {
    e.raw_os_error() == Some(EXDEV)
}

struct TempGuard {
    path: Option<PathBuf>,
}

impl TempGuard {
    fn commit(&mut self) {
        self.path = None;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            let _ = fs::remove_file(p);
        }
    }
}

/// Format a byte count with binary units (KiB/MiB/...).
///
/// Whole-unit values print without a decimal (`"1 MiB"`); fractional values
/// print one decimal place (`"1.5 KiB"`).
pub fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < UNITS.len() {
        v /= 1024.0;
        i += 1;
    }
    if v.fract().abs() < 0.05 {
        format!("{:.0} {}", v, UNITS[i])
    } else {
        format!("{:.1} {}", v, UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_size_known_values() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(1023), "1023 B");
        assert_eq!(format_size(1024), "1 KiB");
        assert_eq!(format_size(1536), "1.5 KiB");
        assert_eq!(format_size(1024 * 1024), "1 MiB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1 GiB");
    }
}
