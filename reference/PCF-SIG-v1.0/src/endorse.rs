//! Pattern B helpers (spec Section 12.2 and 12.2.1): produce and embed CA
//! endorsements of leaf PCFSIG_KEY partitions, without the CA ever touching
//! the leaf's container file.
//!
//! Two stages:
//!
//! * **CA side** ([`issue_endorsement`]) is a pure function over a private
//!   key plus the leaf's planned PCFSIG_KEY identity. It needs no I/O and no
//!   container -- the stateless-server workflow W2 of spec Section 12.2.1.
//!
//! * **Client side** ([`embed_endorsement`]) takes the response and writes
//!   the CA's PCFSIG_KEY and PCFSIG_SIG partitions into the local container.

use std::io::{Read, Seek, Write};

use pcf::{Container, HashAlgo, LABEL_SIZE, UID_SIZE};

use crate::algo::KeyFormat;
use crate::consts::*;
use crate::error::{Error, Result};
use crate::key::{compute_fingerprint, KeyRecord};
use crate::manifest::{is_crypto_hash, Manifest, SignedEntry};
use crate::sig::SignaturePartition;
use crate::sign::SigningMaterial;

/// CA-side input: everything the CA needs to compute a key endorsement
/// without seeing the leaf's container.
#[derive(Debug, Clone)]
pub struct EndorsementRequest {
    /// Leaf key's format id (spec Section 6.2).
    pub key_format: KeyFormat,
    /// Leaf key's raw bytes in the encoding named by `key_format`.
    pub key_data: Vec<u8>,
    /// PCF uid that the leaf PCFSIG_KEY partition will use in the client's
    /// container. MUST be agreed before issuance and not changed afterwards.
    pub intended_uid: [u8; UID_SIZE],
    /// PCF 32-byte label field that the leaf PCFSIG_KEY partition will use.
    pub intended_label: [u8; LABEL_SIZE],
    /// PCF data_hash algorithm the leaf PCFSIG_KEY partition will use.
    /// MUST be cryptographic (16, 17, or 18) per spec Section 9.
    pub data_hash_algo: HashAlgo,
}

/// CA-side output: bytes the client embeds in its container to publish the
/// endorsement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndorsementResponse {
    /// CA's Key Record bytes (becomes the CA PCFSIG_KEY partition data).
    pub ca_key_record_bytes: Vec<u8>,
    /// Assembled PCFSIG_SIG partition bytes (manifest || sig_len || sig
    /// || trailer_len=0) ready to be added as a single PCF partition.
    pub ca_sig_partition_bytes: Vec<u8>,
}

/// Produce a key endorsement (spec Section 12.2.1, workflow W2).
///
/// This function performs NO I/O: it consumes only the CA's signing key and
/// the leaf's planned identity. It can therefore be hosted behind an
/// HSM-fronted, stateless endpoint with no per-issuance database.
pub fn issue_endorsement(
    ca: &SigningMaterial,
    request: &EndorsementRequest,
    signed_at_unix_seconds: i64,
) -> Result<EndorsementResponse> {
    if !is_crypto_hash(request.data_hash_algo) {
        return Err(Error::NonCryptoTargetHash);
    }
    if request.intended_uid == pcf::NIL_UID {
        return Err(Error::EntryNilUid);
    }

    // 1. Serialise the leaf Key Record exactly as the client will write it.
    let leaf_key_record = KeyRecord::new(request.key_format, request.key_data.clone())?.to_bytes();

    // 2. Build the SignedEntry committing to the leaf PCFSIG_KEY partition's
    //    identity and to the bytes of its Key Record.
    let signed_entry = SignedEntry {
        uid: request.intended_uid,
        partition_type: TYPE_PCFSIG_KEY,
        label: request.intended_label,
        used_bytes: leaf_key_record.len() as u64,
        data_hash_algo: request.data_hash_algo,
        data_hash: request.data_hash_algo.compute(&leaf_key_record),
    };

    // 3. Build the Manifest and sign it.
    let manifest_hash = ca
        .sig_algo()
        .required_manifest_hash()
        .expect("implemented algorithms bind a manifest hash");
    let manifest = Manifest::new(
        ca.sig_algo(),
        manifest_hash,
        ca.fingerprint(),
        signed_at_unix_seconds,
        vec![signed_entry],
    );
    let manifest_bytes = manifest.to_bytes();
    let signature = ca.sign(&manifest_bytes);

    // 4. Compose the CA's Key Record and the PCFSIG_SIG partition bytes.
    let ca_key_record_bytes = ca.to_key_record().to_bytes();
    let ca_sig_partition_bytes = SignaturePartition {
        manifest,
        manifest_bytes,
        signature,
        trailer: Vec::new(),
    }
    .to_bytes();

    Ok(EndorsementResponse {
        ca_key_record_bytes,
        ca_sig_partition_bytes,
    })
}

/// Client-side: embed an [`EndorsementResponse`] into the local container.
///
/// Adds the CA's PCFSIG_KEY partition (skipped if a partition with that
/// fingerprint is already present) and the CA's PCFSIG_SIG partition.
pub fn embed_endorsement<S: Read + Write + Seek>(
    container: &mut Container<S>,
    response: &EndorsementResponse,
    ca_key_uid: [u8; UID_SIZE],
    ca_sig_uid: [u8; UID_SIZE],
    ca_key_label: &str,
    ca_sig_label: &str,
) -> Result<()> {
    // Refuse to duplicate an existing CA key partition.
    let new_key = KeyRecord::from_bytes(&response.ca_key_record_bytes)?;
    let mut ca_key_already_present = false;
    for e in container.entries()? {
        if e.partition_type == TYPE_PCFSIG_KEY {
            let data = container.read_partition_data(&e)?;
            if let Ok(existing) = KeyRecord::from_bytes(&data) {
                if existing.fingerprint == new_key.fingerprint {
                    ca_key_already_present = true;
                    break;
                }
            }
        }
    }
    if !ca_key_already_present {
        container.add_partition(
            TYPE_PCFSIG_KEY,
            ca_key_uid,
            ca_key_label,
            &response.ca_key_record_bytes,
            0,
            HashAlgo::Sha256,
        )?;
    }
    container.add_partition(
        TYPE_PCFSIG_SIG,
        ca_sig_uid,
        ca_sig_label,
        &response.ca_sig_partition_bytes,
        0,
        HashAlgo::Sha256,
    )?;
    Ok(())
}

/// Convenience: compute the PCF data_hash that a leaf PCFSIG_KEY partition
/// will publish, given the same inputs the CA used. Lets a client verify
/// locally that the EndorsementRequest it sent and the partition it intends
/// to write agree byte-for-byte.
pub fn expected_leaf_key_data_hash(
    key_format: KeyFormat,
    key_data: &[u8],
    data_hash_algo: HashAlgo,
) -> Result<[u8; pcf::HASH_FIELD_SIZE]> {
    let leaf_key_record = KeyRecord::new(key_format, key_data.to_vec())?.to_bytes();
    Ok(data_hash_algo.compute(&leaf_key_record))
}

/// Convenience: SHA-256 fingerprint of raw key bytes (spec Section 6.3).
/// Re-exported here so client code can build an [`EndorsementRequest`]
/// without importing `key::compute_fingerprint` directly.
pub fn fingerprint_of(key_data: &[u8]) -> [u8; FINGERPRINT_SIZE] {
    compute_fingerprint(key_data)
}
