//! High-level signing API (spec Section 10).
//!
//! The Writer collects a set of partition uids, asserts that each one has a
//! cryptographic `data_hash_algo_id` (Section 9), builds a [`Manifest`],
//! produces the algorithm's signature over the serialised Manifest bytes, and
//! wraps the result in a [`SignaturePartition`].

use std::io::{Read, Seek, Write};

use ed25519_dalek::{Signer, SigningKey};
use pcf::{Container, HashAlgo, PartitionEntry, UID_SIZE};

use crate::algo::{KeyFormat, SigAlgo};
use crate::consts::*;
use crate::error::{Error, Result};
use crate::key::{compute_fingerprint, KeyRecord};
use crate::manifest::{is_crypto_hash, Manifest, SignedEntry};
use crate::sig::SignaturePartition;

/// A signing key wired to one algorithm.
///
/// `SigningMaterial` is the trait-free entry point of the v1.0 reference: it
/// covers Ed25519, the MUST-support baseline. Additional algorithms can be
/// plugged in by adding variants when their implementations land.
pub enum SigningMaterial {
    /// Ed25519 keypair (32-byte secret seed expanded via RFC 8032).
    Ed25519(SigningKey),
}

impl SigningMaterial {
    /// Construct an Ed25519 signer from a 32-byte secret seed.
    pub fn ed25519_from_seed(seed: &[u8; 32]) -> Self {
        SigningMaterial::Ed25519(SigningKey::from_bytes(seed))
    }

    /// The signature algorithm id this signer produces.
    pub fn sig_algo(&self) -> SigAlgo {
        match self {
            SigningMaterial::Ed25519(_) => SigAlgo::Ed25519,
        }
    }

    /// The key format id of the signer's public material.
    pub fn key_format(&self) -> KeyFormat {
        match self {
            SigningMaterial::Ed25519(_) => KeyFormat::Ed25519Raw,
        }
    }

    /// The signer's public key bytes in the encoding named by `key_format`.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            SigningMaterial::Ed25519(sk) => sk.verifying_key().to_bytes().to_vec(),
        }
    }

    /// The signer's SHA-256 fingerprint over `public_key_bytes()`.
    pub fn fingerprint(&self) -> [u8; FINGERPRINT_SIZE] {
        compute_fingerprint(&self.public_key_bytes())
    }

    /// Build a [`KeyRecord`] that represents this signer.
    pub fn to_key_record(&self) -> KeyRecord {
        let pk = self.public_key_bytes();
        // Cannot fail: public_key_bytes() returns a non-empty buffer for every
        // implemented algorithm.
        KeyRecord::new(self.key_format(), pk).expect("non-empty public key")
    }

    /// Sign `message` and return the raw signature bytes.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            SigningMaterial::Ed25519(sk) => sk.sign(message).to_bytes().to_vec(),
        }
    }
}

/// Look up an existing PCFSIG_KEY partition by fingerprint, or, if none
/// exists, add a fresh one carrying `signer`'s public material. Returns the
/// PCF uid of the chosen partition.
///
/// `key_uid_seed` is consulted only when a new partition is added; it MUST
/// be non-NIL.
pub fn ensure_key_partition<S: Read + Write + Seek>(
    container: &mut Container<S>,
    signer: &SigningMaterial,
    key_uid_seed: [u8; UID_SIZE],
    label: &str,
) -> Result<[u8; UID_SIZE]> {
    let fp = signer.fingerprint();
    for e in container.entries()? {
        if e.partition_type == TYPE_PCFSIG_KEY {
            let data = container.read_partition_data(&e)?;
            if let Ok(rec) = KeyRecord::from_bytes(&data) {
                if rec.fingerprint == fp {
                    return Ok(e.uid);
                }
            }
        }
    }
    let rec = signer.to_key_record();
    let data = rec.to_bytes();
    container.add_partition(
        TYPE_PCFSIG_KEY,
        key_uid_seed,
        label,
        &data,
        0,
        HashAlgo::Sha256,
    )?;
    Ok(key_uid_seed)
}

/// Build a [`SignedEntry`] mirroring a PCF [`PartitionEntry`]. Validates the
/// cryptographic-hash requirement (spec Section 9) and the reserved-value
/// guards (Section 7.2).
pub fn signed_entry_from_partition(e: &PartitionEntry) -> Result<SignedEntry> {
    if !is_crypto_hash(e.data_hash_algo) {
        return Err(Error::NonCryptoTargetHash);
    }
    Ok(SignedEntry {
        uid: e.uid,
        partition_type: e.partition_type,
        label: e.label,
        used_bytes: e.used_bytes,
        data_hash_algo: e.data_hash_algo,
        data_hash: e.data_hash,
    })
}

/// Sign a chosen set of partitions and write the resulting PCFSIG_SIG
/// partition into `container`. Returns the PCF uid of the signature
/// partition.
///
/// * `signer` carries the private key and algorithm.
/// * `target_uids` lists the partitions to cover; duplicates and the
///   `sig_partition_uid` (which would be self-reference) are rejected.
/// * `sig_partition_uid` is the PCF uid of the new PCFSIG_SIG partition;
///   it MUST be unique within the container.
/// * `key_partition_uid` is used only if a fresh PCFSIG_KEY needs to be
///   written (see [`ensure_key_partition`]).
/// * `signed_at_unix_seconds` is recorded verbatim into the manifest.
#[allow(clippy::too_many_arguments)]
pub fn sign_partitions<S: Read + Write + Seek>(
    container: &mut Container<S>,
    signer: &SigningMaterial,
    target_uids: &[[u8; UID_SIZE]],
    sig_partition_uid: [u8; UID_SIZE],
    key_partition_uid: [u8; UID_SIZE],
    signed_at_unix_seconds: i64,
    sig_label: &str,
    key_label: &str,
) -> Result<[u8; UID_SIZE]> {
    if target_uids.is_empty() {
        return Err(Error::EmptyManifest);
    }
    if target_uids.iter().any(|u| u == &sig_partition_uid) {
        return Err(Error::SelfSignedEntry);
    }
    let mut seen = std::collections::HashSet::with_capacity(target_uids.len());
    for u in target_uids {
        if !seen.insert(*u) {
            return Err(Error::DuplicateSignedUid);
        }
    }

    ensure_key_partition(container, signer, key_partition_uid, key_label)?;

    let entries = container.entries()?;
    let mut signed_entries = Vec::with_capacity(target_uids.len());
    for uid in target_uids {
        let p = entries
            .iter()
            .find(|e| &e.uid == uid)
            .ok_or(Error::TargetPartitionMissing)?;
        signed_entries.push(signed_entry_from_partition(p)?);
    }

    let manifest_hash = signer
        .sig_algo()
        .required_manifest_hash()
        .expect("implemented algorithms bind a manifest hash");
    let manifest = Manifest::new(
        signer.sig_algo(),
        manifest_hash,
        signer.fingerprint(),
        signed_at_unix_seconds,
        signed_entries,
    );
    let manifest_bytes = manifest.to_bytes();
    let sig = signer.sign(&manifest_bytes);
    let payload = SignaturePartition {
        manifest,
        manifest_bytes,
        signature: sig,
        trailer: Vec::new(),
    };
    let data = payload.to_bytes();
    container.add_partition(
        TYPE_PCFSIG_SIG,
        sig_partition_uid,
        sig_label,
        &data,
        0,
        HashAlgo::Sha256,
    )?;
    Ok(sig_partition_uid)
}
