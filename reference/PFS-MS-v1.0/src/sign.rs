//! PFS-aware PCF-SIG signing (spec PFS-MS Section 15 / PCF-SIG Section 4).
//!
//! A PFS-MS file is append-only and its Table Blocks form a *backward-linked*
//! session chain terminated by a trailer. Adding signature partitions with the
//! generic PCF `add_partition` would splice a fresh block onto the oldest block
//! of that chain, which a PFS Reader then mis-reads as a stray session HEAD.
//!
//! Instead, signing commits the `PCFSIG_KEY` / `PCFSIG_SIG` partitions as a
//! dedicated **signature session**: they ride in a normal PFS session's HEAD
//! block, counted by `block_count` and committed by the head `table_hash`, so
//! the session chain stays valid and the file remains purely append-only. A PFS
//! Reader ignores the foreign partition types (they introduce no nodes); a
//! PCF-SIG Reader finds and verifies them by type.
//!
//! Coverage is **content + structure**: RAW file content and PFS_NODE records.
//! PFS_SESSION records are deliberately *not* covered — they are already
//! tamper-evident through PFS's own inter-session hash chain, and signing them
//! would never converge (each signature itself adds a new session). Signing is
//! incremental: partitions already covered by a valid signature from the same
//! key are skipped, so re-signing an unchanged file is a no-op.

use std::io::Cursor;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use pcf::Container;
use pcf_sig::{
    signed_entry_from_partition, verify_all, DataRecheck, EntryVerdict, KeyRecord, Manifest,
    ManifestVerdict, SignaturePartition, SigningMaterial, TYPE_PCFSIG_KEY, TYPE_PCFSIG_SIG,
};

use crate::consts::{PFS_NODE_TYPE, RAW_TYPE};
use crate::error::{Error, Result};
use crate::writer::{new_id, FsWriter, Partition};

/// Length of the Ed25519 secret seed stored in a key file.
const SEED_LEN: usize = 32;

/// Outcome of [`sign_archive`].
#[derive(Debug, Clone)]
pub struct SignOutcome {
    /// Partition uids covered by the signature committed in this call.
    pub signed_uids: Vec<[u8; 16]>,
    /// Uid of the new PCFSIG_SIG partition, or `None` when nothing was signed.
    pub sig_partition_uid: Option<[u8; 16]>,
    /// Eligible partitions skipped because they were already signed by this key.
    pub skipped_already_signed: usize,
}

/// Sign a PFS-MS file in place by committing a signature session.
///
/// `key_path` holds a 32-byte Ed25519 secret seed (as written by
/// `pcf-sig keygen`). When `resign` is false, only RAW/PFS_NODE partitions not
/// already covered by a valid signature from this key are signed; when true,
/// every RAW/PFS_NODE partition is signed afresh. Returns a [`SignOutcome`]
/// whose `sig_partition_uid` is `None` if there was nothing new to sign.
pub fn sign_archive(path: &Path, key_path: &Path, resign: bool) -> Result<SignOutcome> {
    let seed = read_seed(key_path)?;
    let signer = SigningMaterial::ed25519_from_seed(&seed);
    let fingerprint = signer.fingerprint();

    // Phase 1 (read-only): enumerate partitions, find what this key already
    // covers, and build the signature payload. Work on an in-memory copy so no
    // write lock is held while we read.
    let bytes = std::fs::read(path)?;
    let mut container = Container::open(Cursor::new(bytes))?;
    let entries = container.entries()?;

    // Candidate targets: file content and node records only (see module docs).
    let mut candidates: Vec<[u8; 16]> = entries
        .iter()
        .filter(|e| e.partition_type == RAW_TYPE || e.partition_type == PFS_NODE_TYPE)
        .map(|e| e.uid)
        .collect();

    let mut skipped_already_signed = 0usize;
    if !resign {
        let already = already_signed_by(&mut container, &fingerprint)?;
        let before = candidates.len();
        candidates.retain(|u| !already.contains(u));
        skipped_already_signed = before - candidates.len();
    }

    if candidates.is_empty() {
        return Ok(SignOutcome {
            signed_uids: Vec::new(),
            sig_partition_uid: None,
            skipped_already_signed,
        });
    }

    // Does a PCFSIG_KEY for this signer already exist? If so, do not duplicate
    // it; the manifest references the key by fingerprint, not by partition uid.
    let key_present = entries.iter().any(|e| {
        e.partition_type == TYPE_PCFSIG_KEY
            && container
                .read_partition_data(e)
                .ok()
                .and_then(|d| KeyRecord::from_bytes(&d).ok())
                .map(|rec| rec.fingerprint == fingerprint)
                .unwrap_or(false)
    });

    // Build the manifest over the chosen partitions and sign it.
    let mut signed_entries = Vec::with_capacity(candidates.len());
    for uid in &candidates {
        let e = entries
            .iter()
            .find(|e| &e.uid == uid)
            .expect("candidate uid came from entries");
        signed_entries.push(signed_entry_from_partition(e)?);
    }
    let manifest_hash = signer
        .sig_algo()
        .required_manifest_hash()
        .expect("Ed25519 binds a manifest hash");
    let manifest = Manifest::new(
        signer.sig_algo(),
        manifest_hash,
        fingerprint,
        now_unix_seconds(),
        signed_entries,
    );
    let manifest_bytes = manifest.to_bytes();
    let signature = signer.sign(&manifest_bytes);
    let sig_payload = SignaturePartition {
        manifest,
        manifest_bytes,
        signature,
        trailer: Vec::new(),
    };

    let sig_uid = new_id();
    let mut parts = Vec::with_capacity(2);
    if !key_present {
        parts.push(Partition {
            partition_type: TYPE_PCFSIG_KEY,
            uid: new_id(),
            label: label32("pcfkey"),
            data: signer.to_key_record().to_bytes(),
        });
    }
    parts.push(Partition {
        partition_type: TYPE_PCFSIG_SIG,
        uid: sig_uid,
        label: label32("pcfsig"),
        data: sig_payload.to_bytes(),
    });

    // Phase 2: commit the signature session. Drop the in-memory reader first.
    drop(container);
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;
    let mut w = FsWriter::open(f)?;
    w.set_writer_id(b"pcf-sig");
    w.commit(parts, new_id(), 0, now_unix_ms(), b"pcf-sig")?;
    w.into_storage().sync_all()?;

    Ok(SignOutcome {
        signed_uids: candidates,
        sig_partition_uid: Some(sig_uid),
        skipped_already_signed,
    })
}

/// Collect partition uids already covered by a valid signature from the key
/// with the given fingerprint.
fn already_signed_by(
    container: &mut Container<Cursor<Vec<u8>>>,
    fingerprint: &[u8; 32],
) -> Result<std::collections::HashSet<[u8; 16]>> {
    let mut out = std::collections::HashSet::new();
    for report in verify_all(container, DataRecheck::Skip)? {
        if report.verdict != ManifestVerdict::Valid || &report.signer_key_fingerprint != fingerprint
        {
            continue;
        }
        for entry in report.entries {
            if entry.verdict == EntryVerdict::Valid {
                out.insert(entry.uid);
            }
        }
    }
    Ok(out)
}

fn read_seed(path: &Path) -> Result<[u8; SEED_LEN]> {
    let bytes = std::fs::read(path)?;
    if bytes.len() != SEED_LEN {
        return Err(Error::InvalidPath("private key must be exactly 32 bytes"));
    }
    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

/// Encode a short ASCII label into the fixed 32-byte PCF label field.
fn label32(s: &str) -> [u8; 32] {
    let mut l = [0u8; 32];
    let b = s.as_bytes();
    let n = b.len().min(32);
    l[..n].copy_from_slice(&b[..n]);
    l
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
