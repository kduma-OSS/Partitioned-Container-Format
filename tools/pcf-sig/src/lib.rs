//! Shared command-line logic for signing and verifying PCF files with
//! PCF-SIG signatures.
//!
//! This library half is driven by two binaries: the standalone `pcf-sig` tool
//! (see `src/main.rs`) and the `pfs` CLI, which delegates its `keygen`,
//! `sign`, `verify-sig`, and per-operation auto-sign behaviour here so both
//! front-ends share one implementation.
//!
//! Everything operates on plain PCF containers. A PFS-MS file *is* a PCF file,
//! so [`verify_file`] and [`list_keys`] work on PFS archives unchanged; signing
//! a PFS archive, however, must be committed as a session ([`sign_file`] refuses
//! PFS files and the `pfs sign` subcommand handles them).

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read, Seek, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use pcf::{Container, PartitionEntry, UID_SIZE};
use pcf_sig::{
    compute_fingerprint, is_crypto_hash, sign_partitions, verify_all, verify_all_with_recheck,
    DataRecheck, EntryVerdict, KeyRecord, ManifestVerdict, SignatureReport, TYPE_PCFSIG_KEY,
    TYPE_PCFSIG_SIG,
};

/// The Ed25519 secret seed / raw public key length used by key files.
const ED25519_KEY_LEN: usize = 32;

/// PFS-MS PFS_SESSION partition type. A file carrying one is a PFS-MS archive,
/// whose backward-linked session chain would be corrupted by appending raw
/// partitions; such files must be signed with `pfs sign` instead.
const TYPE_PFS_SESSION: u32 = 0xAAAA_0002;

/// Errors surfaced by the CLI helpers, with messages suitable for printing
/// straight to stderr.
#[derive(Debug)]
pub enum CliError {
    Io(std::io::Error),
    Pcf(pcf::Error),
    Sig(pcf_sig::Error),
    Msg(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Io(e) => write!(f, "{e}"),
            CliError::Pcf(e) => write!(f, "{e}"),
            CliError::Sig(e) => write!(f, "{e}"),
            CliError::Msg(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Io(e)
    }
}
impl From<pcf::Error> for CliError {
    fn from(e: pcf::Error) -> Self {
        CliError::Pcf(e)
    }
}
impl From<pcf_sig::Error> for CliError {
    fn from(e: pcf_sig::Error) -> Self {
        CliError::Sig(e)
    }
}

/// Result alias for the CLI helpers.
pub type CliResult<T> = Result<T, CliError>;

// ---- key generation -------------------------------------------------------

/// Outcome of [`keygen`]: the fingerprint of the freshly created key.
#[derive(Debug, Clone)]
pub struct KeygenSummary {
    pub fingerprint: [u8; 32],
}

/// Generate a fresh Ed25519 keypair and write the 32-byte secret seed and the
/// 32-byte raw public key to `priv_path` and `pub_path` respectively.
///
/// Refuses to overwrite existing files so a key is never clobbered by mistake.
/// On Unix the private key file is created with mode `0600`.
pub fn keygen(priv_path: &str, pub_path: &str) -> CliResult<KeygenSummary> {
    if Path::new(priv_path).exists() {
        return Err(CliError::Msg(format!(
            "refusing to overwrite existing private key '{priv_path}'"
        )));
    }
    if Path::new(pub_path).exists() {
        return Err(CliError::Msg(format!(
            "refusing to overwrite existing public key '{pub_path}'"
        )));
    }

    let mut seed = [0u8; ED25519_KEY_LEN];
    getrandom::fill(&mut seed).map_err(|e| CliError::Msg(format!("rng failure: {e}")))?;

    let signer = pcf_sig::SigningMaterial::ed25519_from_seed(&seed);
    let public = signer.public_key_bytes();
    let fingerprint = signer.fingerprint();

    write_private_key(priv_path, &seed)?;
    std::fs::write(pub_path, &public)?;

    Ok(KeygenSummary { fingerprint })
}

#[cfg(unix)]
fn write_private_key(path: &str, seed: &[u8]) -> CliResult<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(seed)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_key(path: &str, seed: &[u8]) -> CliResult<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(seed)?;
    Ok(())
}

/// Load a 32-byte Ed25519 secret seed from `path`.
fn read_seed(path: &str) -> CliResult<[u8; ED25519_KEY_LEN]> {
    let bytes = std::fs::read(path)?;
    if bytes.len() != ED25519_KEY_LEN {
        return Err(CliError::Msg(format!(
            "private key '{path}' must be exactly {ED25519_KEY_LEN} bytes (got {})",
            bytes.len()
        )));
    }
    let mut seed = [0u8; ED25519_KEY_LEN];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

/// Load a 32-byte raw Ed25519 public key from `path`.
fn read_public(path: &Path) -> CliResult<Vec<u8>> {
    let bytes = std::fs::read(path)?;
    if bytes.len() != ED25519_KEY_LEN {
        return Err(CliError::Msg(format!(
            "public key '{}' must be exactly {ED25519_KEY_LEN} bytes (got {})",
            path.display(),
            bytes.len()
        )));
    }
    Ok(bytes)
}

// ---- signing --------------------------------------------------------------

/// Outcome of [`sign_file`].
#[derive(Debug, Clone)]
pub struct SignSummary {
    /// Partitions covered by the signature written in this call.
    pub signed_uids: Vec<[u8; UID_SIZE]>,
    /// Uid of the new PCFSIG_SIG partition, or `None` when nothing was signed.
    pub sig_partition_uid: Option<[u8; UID_SIZE]>,
    /// Eligible partitions skipped because they were already signed by this key.
    pub skipped_already_signed: usize,
    /// Partitions skipped (in "sign all" mode) for lacking a cryptographic hash.
    pub skipped_weak_hash: usize,
}

/// Sign partitions of the PCF file at `pcf_path` with the Ed25519 key in
/// `key_path`, writing one PCFSIG_SIG partition (and a deduplicated
/// PCFSIG_KEY) into the file.
///
/// * `select`: explicit list of partition uids to cover; `None` means "every
///   partition except existing PCFSIG_KEY / PCFSIG_SIG partitions".
/// * `resign`: when `false` (the default), partitions already covered by a
///   *valid* signature from this same key are skipped; signing is therefore
///   incremental and a no-op once everything is covered. When `true`, all
///   selected partitions are (re-)signed.
pub fn sign_file(
    pcf_path: &str,
    key_path: &str,
    select: Option<Vec<[u8; UID_SIZE]>>,
    resign: bool,
    sig_label: &str,
    key_label: &str,
) -> CliResult<SignSummary> {
    let seed = read_seed(key_path)?;
    let signer = pcf_sig::SigningMaterial::ed25519_from_seed(&seed);
    let fingerprint = signer.fingerprint();

    let file = open_rw(pcf_path)?;
    let mut container = Container::open(file)?;
    let entries = container.entries()?;

    // Refuse to sign PFS-MS files here: appending partitions would break their
    // session chain. The `pfs sign` subcommand signs them correctly (by
    // committing a signature session).
    if entries.iter().any(|e| e.partition_type == TYPE_PFS_SESSION) {
        return Err(CliError::Msg(
            "this looks like a PFS-MS file; use `pfs sign <file> --key <priv>` instead \
             (PFS signatures must be committed as a session, not appended)"
                .into(),
        ));
    }

    let mut skipped_weak_hash = 0usize;
    let mut candidates: Vec<[u8; UID_SIZE]> = match select {
        Some(uids) => {
            for u in &uids {
                if !entries.iter().any(|e| &e.uid == u) {
                    return Err(CliError::Msg(format!(
                        "no partition with uid {} in '{pcf_path}'",
                        hex(u)
                    )));
                }
            }
            uids
        }
        None => entries
            .iter()
            .filter(|e| e.partition_type != TYPE_PCFSIG_KEY && e.partition_type != TYPE_PCFSIG_SIG)
            .filter(|e| {
                let ok = is_crypto_hash(e.data_hash_algo);
                if !ok {
                    skipped_weak_hash += 1;
                }
                ok
            })
            .map(|e| e.uid)
            .collect(),
    };

    let mut skipped_already_signed = 0usize;
    if !resign {
        let already = signed_uids_for(&mut container, &fingerprint)?;
        let before = candidates.len();
        candidates.retain(|u| !already.contains(u));
        skipped_already_signed = before - candidates.len();
    }

    if candidates.is_empty() {
        return Ok(SignSummary {
            signed_uids: Vec::new(),
            sig_partition_uid: None,
            skipped_already_signed,
            skipped_weak_hash,
        });
    }

    let sig_uid = new_uid();
    let key_uid = new_uid();
    let signed_at = now_unix_seconds();
    sign_partitions(
        &mut container,
        &signer,
        &candidates,
        sig_uid,
        key_uid,
        signed_at,
        sig_label,
        key_label,
    )?;
    container.into_storage().flush()?;

    Ok(SignSummary {
        signed_uids: candidates,
        sig_partition_uid: Some(sig_uid),
        skipped_already_signed,
        skipped_weak_hash,
    })
}

/// Collect the uids already covered by a *valid* signature from the key with
/// the given fingerprint.
fn signed_uids_for<S: Read + Write + Seek>(
    container: &mut Container<S>,
    fingerprint: &[u8; 32],
) -> CliResult<std::collections::HashSet<[u8; UID_SIZE]>> {
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

// ---- verification ---------------------------------------------------------

/// Outcome of [`verify_file`].
#[derive(Debug, Clone)]
pub struct VerifySummary {
    /// One report per PCFSIG_SIG partition found in the file.
    pub reports: Vec<SignatureReport>,
    /// Fingerprint of the trusted public key, if `--key` was supplied.
    pub trusted_fingerprint: Option<[u8; 32]>,
    /// Whether at least one valid signature matched `trusted_fingerprint`.
    pub trusted_match: bool,
}

/// Verify every PCFSIG_SIG partition in the PCF file at `pcf_path`.
///
/// `trusted_pub`, if given, is a raw 32-byte Ed25519 public key: the result
/// records whether a valid signature from that exact key is present (an
/// out-of-band trust check on top of the in-file keys). `recheck` independently
/// re-hashes covered partition bytes when true (recommended).
pub fn verify_file(
    pcf_path: &str,
    trusted_pub: Option<&Path>,
    recheck: bool,
) -> CliResult<VerifySummary> {
    let trusted_fingerprint = match trusted_pub {
        Some(p) => Some(compute_fingerprint(&read_public(p)?)),
        None => None,
    };

    // Read-only: load into memory so no write permission is required.
    let bytes = std::fs::read(pcf_path)?;
    let mut container = Container::open(Cursor::new(bytes))?;
    let reports = if recheck {
        verify_all_with_recheck(&mut container)?
    } else {
        verify_all(&mut container, DataRecheck::Skip)?
    };

    let trusted_match = match trusted_fingerprint {
        Some(fp) => reports
            .iter()
            .any(|r| r.verdict == ManifestVerdict::Valid && r.signer_key_fingerprint == fp),
        None => false,
    };

    Ok(VerifySummary {
        reports,
        trusted_fingerprint,
        trusted_match,
    })
}

// ---- key listing ----------------------------------------------------------

/// One embedded PCFSIG_KEY partition.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub uid: [u8; UID_SIZE],
    pub fingerprint: [u8; 32],
    pub key_format_id: u8,
}

/// List the PCFSIG_KEY partitions embedded in the PCF file at `pcf_path`.
pub fn list_keys(pcf_path: &str) -> CliResult<Vec<KeyInfo>> {
    let bytes = std::fs::read(pcf_path)?;
    let mut container = Container::open(Cursor::new(bytes))?;
    let entries = container.entries()?;
    let mut out = Vec::new();
    for e in &entries {
        if e.partition_type != TYPE_PCFSIG_KEY {
            continue;
        }
        if let Ok(rec) = KeyRecord::from_bytes(&container.read_partition_data(e)?) {
            out.push(KeyInfo {
                uid: e.uid,
                fingerprint: rec.fingerprint,
                key_format_id: rec.key_format.id(),
            });
        }
    }
    Ok(out)
}

// ---- formatting helpers ---------------------------------------------------

/// Lowercase hex encoding of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Parse a 16-byte (32 hex chars) partition uid.
pub fn parse_hex_uid(s: &str) -> CliResult<[u8; UID_SIZE]> {
    let bytes = parse_hex(s)?;
    if bytes.len() != UID_SIZE {
        return Err(CliError::Msg(format!(
            "uid must be {UID_SIZE} bytes ({} hex chars); got {}",
            UID_SIZE * 2,
            s.len()
        )));
    }
    let mut uid = [0u8; UID_SIZE];
    uid.copy_from_slice(&bytes);
    Ok(uid)
}

fn parse_hex(s: &str) -> CliResult<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(CliError::Msg("hex string must have even length".into()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char)
            .to_digit(16)
            .ok_or_else(|| CliError::Msg(format!("invalid hex digit '{}'", b[i] as char)))?;
        let lo = (b[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| CliError::Msg(format!("invalid hex digit '{}'", b[i + 1] as char)))?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Ok(out)
}

/// Render a [`SignSummary`] for human consumption.
pub fn format_sign(s: &SignSummary) -> String {
    match s.sig_partition_uid {
        None => {
            let mut msg = "nothing to sign".to_string();
            if s.skipped_already_signed > 0 {
                msg.push_str(&format!(
                    " ({} partition(s) already signed by this key)",
                    s.skipped_already_signed
                ));
            }
            msg
        }
        Some(uid) => {
            let mut msg = format!(
                "signed {} partition(s) into PCFSIG_SIG {}",
                s.signed_uids.len(),
                hex(&uid)
            );
            if s.skipped_already_signed > 0 {
                msg.push_str(&format!(
                    "; skipped {} already signed",
                    s.skipped_already_signed
                ));
            }
            if s.skipped_weak_hash > 0 {
                msg.push_str(&format!(
                    "; skipped {} with non-cryptographic hash",
                    s.skipped_weak_hash
                ));
            }
            msg
        }
    }
}

/// Render a [`VerifySummary`] for human consumption.
pub fn format_verify(v: &VerifySummary) -> String {
    let mut out = String::new();
    if v.reports.is_empty() {
        out.push_str("no PCF-SIG signatures found\n");
        return out;
    }
    for r in &v.reports {
        let verdict = match &r.verdict {
            ManifestVerdict::Valid => "VALID".to_string(),
            ManifestVerdict::Invalid => "INVALID".to_string(),
            ManifestVerdict::Unverifiable(reason) => format!("UNVERIFIABLE ({reason:?})"),
        };
        out.push_str(&format!(
            "signature {} {} signer {} signed_at {}\n",
            hex(&r.sig_partition_uid),
            verdict,
            hex(&r.signer_key_fingerprint),
            r.signed_at_unix_seconds
        ));
        for e in &r.entries {
            out.push_str(&format!("  partition {} {:?}\n", hex(&e.uid), e.verdict));
        }
    }
    if let Some(fp) = v.trusted_fingerprint {
        out.push_str(&format!(
            "trusted key {}: {}\n",
            hex(&fp),
            if v.trusted_match {
                "MATCHED a valid signature"
            } else {
                "NOT matched by any valid signature"
            }
        ));
    }
    out
}

/// Render a list of [`KeyInfo`] for human consumption.
pub fn format_keys(keys: &[KeyInfo]) -> String {
    if keys.is_empty() {
        return "no PCFSIG_KEY partitions found\n".to_string();
    }
    let mut out = String::new();
    for k in keys {
        out.push_str(&format!(
            "key {} fingerprint {} key_format_id {}\n",
            hex(&k.uid),
            hex(&k.fingerprint),
            k.key_format_id
        ));
    }
    out
}

/// `true` when every signature in the summary is cryptographically valid and
/// every covered partition entry is valid. Used to pick an exit code.
pub fn all_valid(v: &VerifySummary) -> bool {
    !v.reports.is_empty()
        && v.reports.iter().all(|r| {
            r.verdict == ManifestVerdict::Valid
                && r.entries.iter().all(|e| e.verdict == EntryVerdict::Valid)
        })
}

// ---- internals ------------------------------------------------------------

fn open_rw(path: &str) -> CliResult<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| CliError::Msg(format!("cannot open '{path}': {e}")))
}

fn new_uid() -> [u8; UID_SIZE] {
    *uuid::Uuid::now_v7().as_bytes()
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Convenience: does this partition entry carry a PCF-SIG type? Exposed for
/// callers that want to reason about a container's contents.
pub fn is_pcfsig_partition(e: &PartitionEntry) -> bool {
    e.partition_type == TYPE_PCFSIG_KEY || e.partition_type == TYPE_PCFSIG_SIG
}
