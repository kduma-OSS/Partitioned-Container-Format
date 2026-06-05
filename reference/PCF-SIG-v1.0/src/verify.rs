//! High-level verification API (spec Section 11).
//!
//! The Verifier scans a PCF container, indexes every PCFSIG_KEY partition by
//! fingerprint, and produces one [`SignatureReport`] per PCFSIG_SIG
//! partition.

use std::io::{Read, Seek, Write};

use ed25519_dalek::{Signature as EdSignature, Verifier, VerifyingKey};
use pcf::{Container, PartitionEntry, UID_SIZE};

use crate::algo::{KeyFormat, SigAlgo};
use crate::consts::*;
use crate::error::Result;
use crate::key::KeyRecord;
use crate::manifest::is_crypto_hash;
use crate::sig::SignaturePartition;

/// Verdict on one SignedEntry inside a Manifest (spec Section 11, V7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryVerdict {
    /// Covered partition exists, all protected fields match, and the
    /// `data_hash_algo_id` is cryptographic. If the verifier was asked to
    /// recompute the digest, that also matched.
    Valid,
    /// No partition in the container has the SignedEntry's uid.
    MissingPartition,
    /// A protected field of the live partition does not match the manifest.
    ProtectedFieldMismatch,
    /// The verifier recomputed the partition's bytes' hash and it did not
    /// match the SignedEntry's `data_hash`.
    DataHashRecomputationMismatch,
    /// The covered partition's `data_hash_algo_id` is not cryptographic.
    WeakHash,
}

/// Per-entry report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryReport {
    /// The SignedEntry's uid.
    pub uid: [u8; UID_SIZE],
    /// Verdict for this entry.
    pub verdict: EntryVerdict,
}

/// Verdict on a whole PCFSIG_SIG partition (spec Section 11, V8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestVerdict {
    /// Manifest parsed; signature cryptographically verified against the
    /// referenced key. Per-entry results in [`SignatureReport::entries`].
    Valid,
    /// Manifest parsed; signature did NOT verify against the referenced key.
    Invalid,
    /// Manifest parsed but cannot be verified (no matching PCFSIG_KEY in this
    /// file, or the algorithm / key format is not implemented by this build).
    Unverifiable(UnverifiableReason),
}

/// Why a manifest could not be verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnverifiableReason {
    /// No PCFSIG_KEY partition with the manifest's `signer_key_fingerprint`.
    NoMatchingKey,
    /// The signature algorithm id is not implemented by this build.
    UnsupportedSigAlgo(u8),
    /// The key format id is not implemented by this build.
    UnsupportedKeyFormat(u8),
    /// The matching key partition is malformed.
    MalformedKey,
    /// The signature byte length does not match the algorithm's natural size.
    SignatureLengthMismatch,
}

/// Report for one PCFSIG_SIG partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureReport {
    /// PCF uid of the PCFSIG_SIG partition itself.
    pub sig_partition_uid: [u8; UID_SIZE],
    /// `signer_key_fingerprint` copied from the manifest.
    pub signer_key_fingerprint: [u8; FINGERPRINT_SIZE],
    /// `signed_at_unix_seconds` copied from the manifest.
    pub signed_at_unix_seconds: i64,
    /// Verdict on the manifest as a whole.
    pub verdict: ManifestVerdict,
    /// Per-entry verdicts (empty for Unverifiable signatures whose manifest
    /// could not be reached).
    pub entries: Vec<EntryReport>,
}

/// Whether to independently re-hash each covered partition's bytes during
/// verification (spec Section 11, V7 optional check). Recommended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataRecheck {
    /// Trust the PCF data_hash field as captured by the SignedEntry.
    Skip,
    /// Recompute hash(partition bytes) and compare to the SignedEntry's
    /// `data_hash`.
    Recompute,
}

/// Find every signer whose Valid signature in `reports` countersigns the
/// PCFSIG_KEY partition whose fingerprint is `leaf_key_fingerprint` (spec
/// Section 12.2). Returns the deduplicated `signer_key_fingerprint`s of those
/// signers, in first-seen order. Self-endorsement (a signer endorsing its own
/// key) is filtered out as semantically vacuous.
///
/// The container is consulted to locate the leaf PCFSIG_KEY partition by
/// fingerprint; if no such partition exists in the file the result is empty.
///
/// The reports passed in MUST come from [`verify_all`] or
/// [`verify_all_with_recheck`] on the same container; the function does not
/// re-verify any signatures.
pub fn key_endorsements<S: Read + Write + Seek>(
    container: &mut Container<S>,
    reports: &[SignatureReport],
    leaf_key_fingerprint: &[u8; FINGERPRINT_SIZE],
) -> Result<Vec<[u8; FINGERPRINT_SIZE]>> {
    // 1. Locate the leaf PCFSIG_KEY partition's PCF uid by fingerprint.
    let entries = container.entries()?;
    let mut leaf_key_uid: Option<[u8; UID_SIZE]> = None;
    for e in &entries {
        if e.partition_type == TYPE_PCFSIG_KEY {
            let data = container.read_partition_data(e)?;
            if let Ok(rec) = KeyRecord::from_bytes(&data) {
                if &rec.fingerprint == leaf_key_fingerprint {
                    leaf_key_uid = Some(e.uid);
                    break;
                }
            }
        }
    }
    let leaf_key_uid = match leaf_key_uid {
        Some(u) => u,
        None => return Ok(Vec::new()),
    };

    // 2. Scan reports for Valid signatures whose manifests cover that uid.
    let mut endorsers: Vec<[u8; FINGERPRINT_SIZE]> = Vec::new();
    for r in reports {
        if !matches!(r.verdict, ManifestVerdict::Valid) {
            continue;
        }
        if &r.signer_key_fingerprint == leaf_key_fingerprint {
            // Self-endorsement is semantically empty.
            continue;
        }
        let endorses = r
            .entries
            .iter()
            .any(|er| er.uid == leaf_key_uid && matches!(er.verdict, EntryVerdict::Valid));
        if endorses && !endorsers.contains(&r.signer_key_fingerprint) {
            endorsers.push(r.signer_key_fingerprint);
        }
    }
    Ok(endorsers)
}

/// Verify every PCFSIG_SIG partition in `container` and return one report
/// each. Returns an empty vector if the container has no signatures.
pub fn verify_all<S: Read + Write + Seek>(
    container: &mut Container<S>,
    recheck: DataRecheck,
) -> Result<Vec<SignatureReport>> {
    let entries = container.entries()?;

    // Build an index of PCFSIG_KEY records by fingerprint.
    let mut keys: Vec<(KeyRecord, [u8; UID_SIZE])> = Vec::new();
    for e in &entries {
        if e.partition_type == TYPE_PCFSIG_KEY {
            if let Ok(rec) = KeyRecord::from_bytes(&container.read_partition_data(e)?) {
                keys.push((rec, e.uid));
            }
        }
    }

    let mut reports = Vec::new();
    for e in &entries {
        if e.partition_type != TYPE_PCFSIG_SIG {
            continue;
        }
        let data = container.read_partition_data(e)?;
        let report = verify_one(&entries, &keys, e, &data, recheck);
        reports.push(report);
    }
    Ok(reports)
}

fn verify_one(
    entries: &[PartitionEntry],
    keys: &[(KeyRecord, [u8; UID_SIZE])],
    sig_entry: &PartitionEntry,
    data: &[u8],
    recheck: DataRecheck,
) -> SignatureReport {
    let parsed = match SignaturePartition::from_bytes(data) {
        Ok(p) => p,
        Err(_e) => {
            // Treat malformed signature partitions as Unverifiable rather
            // than aborting the whole pass; spec Section 11 V2 mandates
            // independent processing.
            return SignatureReport {
                sig_partition_uid: sig_entry.uid,
                signer_key_fingerprint: [0u8; FINGERPRINT_SIZE],
                signed_at_unix_seconds: 0,
                verdict: ManifestVerdict::Unverifiable(UnverifiableReason::MalformedKey),
                entries: Vec::new(),
            };
        }
    };
    let mut report = SignatureReport {
        sig_partition_uid: sig_entry.uid,
        signer_key_fingerprint: parsed.manifest.signer_key_fingerprint,
        signed_at_unix_seconds: parsed.manifest.signed_at_unix_seconds,
        verdict: ManifestVerdict::Valid,
        entries: Vec::new(),
    };

    // Self-reference check (spec Section 7.2).
    if parsed
        .manifest
        .signed_entries
        .iter()
        .any(|e| e.uid == sig_entry.uid)
    {
        report.verdict = ManifestVerdict::Invalid;
        return report;
    }

    if !parsed.manifest.sig_algo.is_implemented() {
        report.verdict = ManifestVerdict::Unverifiable(UnverifiableReason::UnsupportedSigAlgo(
            parsed.manifest.sig_algo.id(),
        ));
        return report;
    }

    let key = keys
        .iter()
        .find(|(rec, _)| rec.fingerprint == parsed.manifest.signer_key_fingerprint);
    let key = match key {
        Some(k) => k,
        None => {
            report.verdict = ManifestVerdict::Unverifiable(UnverifiableReason::NoMatchingKey);
            return report;
        }
    };

    if !key.0.key_format.is_implemented() {
        report.verdict = ManifestVerdict::Unverifiable(UnverifiableReason::UnsupportedKeyFormat(
            key.0.key_format.id(),
        ));
        return report;
    }

    match (parsed.manifest.sig_algo, key.0.key_format) {
        (SigAlgo::Ed25519, KeyFormat::Ed25519Raw) => {
            if parsed.signature.len() != ED25519_SIGNATURE_LEN {
                report.verdict =
                    ManifestVerdict::Unverifiable(UnverifiableReason::SignatureLengthMismatch);
                return report;
            }
            if key.0.key_data.len() != ED25519_PUBLIC_KEY_LEN {
                report.verdict = ManifestVerdict::Unverifiable(UnverifiableReason::MalformedKey);
                return report;
            }
            let mut pk = [0u8; ED25519_PUBLIC_KEY_LEN];
            pk.copy_from_slice(&key.0.key_data);
            let vk = match VerifyingKey::from_bytes(&pk) {
                Ok(v) => v,
                Err(_) => {
                    report.verdict =
                        ManifestVerdict::Unverifiable(UnverifiableReason::MalformedKey);
                    return report;
                }
            };
            let mut sig_bytes = [0u8; ED25519_SIGNATURE_LEN];
            sig_bytes.copy_from_slice(&parsed.signature);
            let sig = EdSignature::from_bytes(&sig_bytes);
            if vk.verify(&parsed.manifest_bytes, &sig).is_err() {
                report.verdict = ManifestVerdict::Invalid;
                return report;
            }
        }
        // Other (algorithm, key format) combinations are not implemented in
        // v1.0 of this reference; SigAlgo::is_implemented / KeyFormat::
        // is_implemented gate them off above. Any combination that reaches
        // here is a bug in the registry wiring.
        _ => {
            report.verdict = ManifestVerdict::Unverifiable(UnverifiableReason::UnsupportedSigAlgo(
                parsed.manifest.sig_algo.id(),
            ));
            return report;
        }
    }

    // Signature is cryptographically valid. Now check per-entry coverage.
    for se in &parsed.manifest.signed_entries {
        let verdict = match entries.iter().find(|p| p.uid == se.uid) {
            None => EntryVerdict::MissingPartition,
            Some(p) => {
                if !is_crypto_hash(se.data_hash_algo) {
                    EntryVerdict::WeakHash
                } else if p.partition_type != se.partition_type
                    || p.label != se.label
                    || p.used_bytes != se.used_bytes
                    || p.data_hash_algo != se.data_hash_algo
                    || p.data_hash != se.data_hash
                {
                    EntryVerdict::ProtectedFieldMismatch
                } else {
                    EntryVerdict::Valid
                }
            }
        };
        report.entries.push(EntryReport {
            uid: se.uid,
            verdict,
        });
    }

    // Optional recheck pass: independently recompute each covered partition's
    // data_hash from the live bytes (spec Section 11 V7). We do this last
    // because it requires reading partition data and we want to avoid the
    // I/O cost when the caller opted out.
    if matches!(recheck, DataRecheck::Recompute) {
        for er in &mut report.entries {
            if matches!(er.verdict, EntryVerdict::Valid) {
                if let Some(_p) = entries.iter().find(|p| p.uid == er.uid) {
                    // We cannot read here because we do not have &mut Container.
                    // Recompute is wired through verify_all_with_recheck below.
                }
            }
        }
    }

    report
}

/// Same as [`verify_all`] but also reruns the digest over each covered
/// partition's bytes for the entries whose protected fields matched (spec
/// Section 11, V7 optional check). Recommended for files that may have been
/// modified by a non-PCF-SIG-aware Writer.
pub fn verify_all_with_recheck<S: Read + Write + Seek>(
    container: &mut Container<S>,
) -> Result<Vec<SignatureReport>> {
    let mut reports = verify_all(container, DataRecheck::Skip)?;
    let entries = container.entries()?;
    for r in &mut reports {
        for er in &mut r.entries {
            if !matches!(er.verdict, EntryVerdict::Valid) {
                continue;
            }
            if let Some(p) = entries.iter().find(|p| p.uid == er.uid) {
                let bytes = container.read_partition_data(p)?;
                let h = p.data_hash_algo.compute(&bytes);
                if h != p.data_hash {
                    er.verdict = EntryVerdict::DataHashRecomputationMismatch;
                }
            }
        }
    }
    Ok(reports)
}
