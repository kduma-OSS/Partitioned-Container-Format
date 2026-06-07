//! The Manifest and Signed Entry stored in a `PCFSIG_SIG` partition
//! (spec Section 7).
//!
//! The Manifest is the byte sequence that is hashed and signed. Its length is
//! deterministic from `signed_count`: `MANIFEST_PREFIX_SIZE + SIGNED_ENTRY_SIZE *
//! signed_count`.

use std::collections::HashSet;

use pcf::{HashAlgo, LABEL_SIZE, NIL_UID, TYPE_RESERVED, UID_SIZE};

use crate::algo::SigAlgo;
use crate::consts::*;
use crate::error::{Error, Result};

/// One Signed Entry inside a Manifest (spec Section 7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEntry {
    /// PCF uid of the covered partition (verbatim).
    pub uid: [u8; UID_SIZE],
    /// PCF type of the covered partition (verbatim).
    pub partition_type: u32,
    /// PCF label of the covered partition (verbatim 32-byte field).
    pub label: [u8; LABEL_SIZE],
    /// PCF `used_bytes` of the covered partition.
    pub used_bytes: u64,
    /// PCF `data_hash_algo_id`. MUST be cryptographic in v1.0 (16/17/18).
    pub data_hash_algo: HashAlgo,
    /// PCF `data_hash` field bytes (verbatim 64-byte field).
    pub data_hash: [u8; pcf::HASH_FIELD_SIZE],
}

impl SignedEntry {
    /// Serialise to the on-disk 218-byte layout (spec Section 7.2).
    pub fn to_bytes(&self) -> [u8; SIGNED_ENTRY_SIZE] {
        let mut b = [0u8; SIGNED_ENTRY_SIZE];
        b[0..16].copy_from_slice(&self.uid);
        b[16..20].copy_from_slice(&self.partition_type.to_le_bytes());
        b[20..52].copy_from_slice(&self.label);
        b[52..60].copy_from_slice(&self.used_bytes.to_le_bytes());
        b[60] = self.data_hash_algo.id();
        // b[61] reserved = 0
        b[62..126].copy_from_slice(&self.data_hash);
        // b[126..218] reserved = 0
        b
    }

    /// Parse from the on-disk 218-byte layout (spec Section 7.2). Validates
    /// the reserved spans, the cryptographic-hash constraint (Section 9), and
    /// the PCF reserved-value guards (Section 11, V7).
    pub fn from_bytes(b: &[u8; SIGNED_ENTRY_SIZE]) -> Result<Self> {
        if b[61] != 0 {
            return Err(Error::NonZeroEntryReserved);
        }
        if b[126..218].iter().any(|&x| x != 0) {
            return Err(Error::NonZeroEntryReserved);
        }
        let mut uid = [0u8; UID_SIZE];
        uid.copy_from_slice(&b[0..16]);
        if uid == NIL_UID {
            return Err(Error::EntryNilUid);
        }
        let partition_type = u32::from_le_bytes([b[16], b[17], b[18], b[19]]);
        if partition_type == TYPE_RESERVED {
            return Err(Error::EntryReservedType);
        }
        let mut label = [0u8; LABEL_SIZE];
        label.copy_from_slice(&b[20..52]);
        let used_bytes = u64::from_le_bytes(b[52..60].try_into().unwrap());
        let data_hash_algo = HashAlgo::from_id(b[60]).map_err(Error::Pcf)?;
        if !is_crypto_hash(data_hash_algo) {
            return Err(Error::NonCryptoEntryHash(b[60]));
        }
        let mut data_hash = [0u8; pcf::HASH_FIELD_SIZE];
        data_hash.copy_from_slice(&b[62..126]);
        Ok(Self {
            uid,
            partition_type,
            label,
            used_bytes,
            data_hash_algo,
            data_hash,
        })
    }
}

/// A parsed Manifest (spec Section 7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// `manifest_version_major`.
    pub version_major: u16,
    /// `manifest_version_minor`.
    pub version_minor: u16,
    /// `sig_algo_id`.
    pub sig_algo: SigAlgo,
    /// `manifest_hash_algo_id`. MUST be cryptographic (16/17/18) and MUST
    /// satisfy the binding required by `sig_algo`.
    pub manifest_hash_algo: HashAlgo,
    /// Reserved `flags` field; v1.0 MUST be 0.
    pub flags: u16,
    /// Signer key fingerprint (SHA-256 of the matching PCFSIG_KEY's
    /// `key_data`).
    pub signer_key_fingerprint: [u8; FINGERPRINT_SIZE],
    /// `signed_at_unix_seconds` (i64).
    pub signed_at_unix_seconds: i64,
    /// `signed_entries`, packed in writer-chosen order.
    pub signed_entries: Vec<SignedEntry>,
}

impl Manifest {
    /// Build a Manifest from its component parts. Does not enforce
    /// duplicate-uid or self-reference checks (those are enforced at parse
    /// time and during signing/verification).
    pub fn new(
        sig_algo: SigAlgo,
        manifest_hash_algo: HashAlgo,
        signer_key_fingerprint: [u8; FINGERPRINT_SIZE],
        signed_at_unix_seconds: i64,
        signed_entries: Vec<SignedEntry>,
    ) -> Self {
        Self {
            version_major: PROFILE_VERSION_MAJOR,
            version_minor: PROFILE_VERSION_MINOR,
            sig_algo,
            manifest_hash_algo,
            flags: 0,
            signer_key_fingerprint,
            signed_at_unix_seconds,
            signed_entries,
        }
    }

    /// Serialised length in bytes.
    pub fn byte_len(&self) -> usize {
        MANIFEST_PREFIX_SIZE + SIGNED_ENTRY_SIZE * self.signed_entries.len()
    }

    /// Serialise to the on-disk byte layout (spec Section 7.1).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.byte_len());
        out.extend_from_slice(&SIG_MAGIC);
        out.extend_from_slice(&self.version_major.to_le_bytes());
        out.extend_from_slice(&self.version_minor.to_le_bytes());
        out.push(self.sig_algo.id());
        out.push(self.manifest_hash_algo.id());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.signer_key_fingerprint);
        out.extend_from_slice(&self.signed_at_unix_seconds.to_le_bytes());
        out.extend_from_slice(&(self.signed_entries.len() as u32).to_le_bytes());
        for e in &self.signed_entries {
            out.extend_from_slice(&e.to_bytes());
        }
        out
    }

    /// Parse from the on-disk byte layout. Validates: magic, major version,
    /// algorithm registry membership, hash-algo binding (Section 8),
    /// cryptographic hash requirement (Section 9), reserved flags, non-empty
    /// signed_count, and per-entry reserved spans (Section 7.2). Does NOT
    /// validate duplicate uids or self-reference; the verifier does that with
    /// context from the enclosing partition.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < MANIFEST_PREFIX_SIZE {
            return Err(Error::MalformedSignaturePartition);
        }
        if b[0..8] != SIG_MAGIC {
            return Err(Error::BadManifestMagic);
        }
        let version_major = u16::from_le_bytes([b[8], b[9]]);
        let version_minor = u16::from_le_bytes([b[10], b[11]]);
        if version_major != PROFILE_VERSION_MAJOR {
            return Err(Error::UnsupportedMajor(version_major));
        }
        let sig_algo = SigAlgo::from_id(b[12])?;
        let mh_id = b[13];
        let manifest_hash_algo = HashAlgo::from_id(mh_id).map_err(Error::Pcf)?;
        if !is_crypto_hash(manifest_hash_algo) {
            return Err(Error::NonCryptoManifestHash(mh_id));
        }
        if let Some(required) = sig_algo.required_manifest_hash() {
            if required != manifest_hash_algo {
                return Err(Error::HashAlgoBindingMismatch);
            }
        }
        let flags = u16::from_le_bytes([b[14], b[15]]);
        if flags != 0 {
            return Err(Error::NonZeroFlags);
        }
        let mut fingerprint = [0u8; FINGERPRINT_SIZE];
        fingerprint.copy_from_slice(&b[16..48]);
        let signed_at_unix_seconds = i64::from_le_bytes(b[48..56].try_into().unwrap());
        let signed_count = u32::from_le_bytes([b[56], b[57], b[58], b[59]]) as usize;
        if signed_count == 0 {
            return Err(Error::EmptyManifest);
        }

        let expected_len = MANIFEST_PREFIX_SIZE + SIGNED_ENTRY_SIZE * signed_count;
        if b.len() < expected_len {
            return Err(Error::MalformedSignaturePartition);
        }

        let mut signed_entries = Vec::with_capacity(signed_count);
        let mut seen = HashSet::with_capacity(signed_count);
        for i in 0..signed_count {
            let off = MANIFEST_PREFIX_SIZE + i * SIGNED_ENTRY_SIZE;
            let chunk: &[u8; SIGNED_ENTRY_SIZE] =
                (&b[off..off + SIGNED_ENTRY_SIZE]).try_into().unwrap();
            let e = SignedEntry::from_bytes(chunk)?;
            if !seen.insert(e.uid) {
                return Err(Error::DuplicateSignedUid);
            }
            signed_entries.push(e);
        }

        Ok(Self {
            version_major,
            version_minor,
            sig_algo,
            manifest_hash_algo,
            flags,
            signer_key_fingerprint: fingerprint,
            signed_at_unix_seconds,
            signed_entries,
        })
    }
}

/// Whether a PCF hash algorithm id is cryptographic (spec Section 9).
pub fn is_crypto_hash(a: HashAlgo) -> bool {
    matches!(a, HashAlgo::Sha256 | HashAlgo::Sha512 | HashAlgo::Blake3)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> SignedEntry {
        SignedEntry {
            uid: [0x11u8; 16],
            partition_type: 0x10,
            label: {
                let mut l = [0u8; LABEL_SIZE];
                l[..5].copy_from_slice(b"alpha");
                l
            },
            used_bytes: 11,
            data_hash_algo: HashAlgo::Sha256,
            data_hash: HashAlgo::Sha256.compute(b"Hello, PCF!"),
        }
    }

    #[test]
    fn manifest_roundtrip() {
        let entry = sample_entry();
        let m = Manifest::new(
            SigAlgo::Ed25519,
            HashAlgo::Sha512,
            [0u8; 32],
            0,
            vec![entry],
        );
        let bytes = m.to_bytes();
        assert_eq!(bytes.len(), m.byte_len());
        let parsed = Manifest::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, m);
    }

    #[test]
    fn rejects_weak_entry_hash() {
        let mut e = sample_entry();
        e.data_hash_algo = HashAlgo::Crc32c;
        let m = Manifest::new(SigAlgo::Ed25519, HashAlgo::Sha512, [0u8; 32], 0, vec![e]);
        let bytes = m.to_bytes();
        assert!(matches!(
            Manifest::from_bytes(&bytes),
            Err(Error::NonCryptoEntryHash(_))
        ));
    }

    #[test]
    fn rejects_weak_manifest_hash() {
        // Build the bytes by hand because Manifest::new + to_bytes go through
        // SigAlgo / HashAlgo which round-trip cleanly.
        let entry = sample_entry();
        let mut bytes = Manifest::new(
            SigAlgo::Ed25519,
            HashAlgo::Sha512,
            [0u8; 32],
            0,
            vec![entry],
        )
        .to_bytes();
        bytes[13] = HashAlgo::Sha1.id();
        assert!(matches!(
            Manifest::from_bytes(&bytes),
            Err(Error::NonCryptoManifestHash(_))
        ));
    }

    #[test]
    fn rejects_hash_binding_mismatch() {
        let entry = sample_entry();
        let mut bytes = Manifest::new(
            SigAlgo::Ed25519,
            HashAlgo::Sha512,
            [0u8; 32],
            0,
            vec![entry],
        )
        .to_bytes();
        // Ed25519 requires SHA-512; flip the manifest hash to SHA-256.
        bytes[13] = HashAlgo::Sha256.id();
        assert!(matches!(
            Manifest::from_bytes(&bytes),
            Err(Error::HashAlgoBindingMismatch)
        ));
    }

    #[test]
    fn rejects_non_zero_flags() {
        let entry = sample_entry();
        let mut bytes = Manifest::new(
            SigAlgo::Ed25519,
            HashAlgo::Sha512,
            [0u8; 32],
            0,
            vec![entry],
        )
        .to_bytes();
        bytes[14] = 0x01;
        assert!(matches!(
            Manifest::from_bytes(&bytes),
            Err(Error::NonZeroFlags)
        ));
    }

    #[test]
    fn rejects_empty_signed_count() {
        let entry = sample_entry();
        let mut bytes = Manifest::new(
            SigAlgo::Ed25519,
            HashAlgo::Sha512,
            [0u8; 32],
            0,
            vec![entry],
        )
        .to_bytes();
        bytes[56] = 0;
        bytes[57] = 0;
        bytes[58] = 0;
        bytes[59] = 0;
        // Truncate to the prefix only so the byte stream really represents
        // signed_count == 0 with no trailing entries.
        bytes.truncate(MANIFEST_PREFIX_SIZE);
        assert!(matches!(
            Manifest::from_bytes(&bytes),
            Err(Error::EmptyManifest)
        ));
    }

    #[test]
    fn rejects_duplicate_uid() {
        let entry = sample_entry();
        let m = Manifest::new(
            SigAlgo::Ed25519,
            HashAlgo::Sha512,
            [0u8; 32],
            0,
            vec![entry.clone(), entry],
        );
        let bytes = m.to_bytes();
        assert!(matches!(
            Manifest::from_bytes(&bytes),
            Err(Error::DuplicateSignedUid)
        ));
    }

    #[test]
    fn rejects_non_zero_reserved_entry_byte() {
        let entry = sample_entry();
        let mut bytes = Manifest::new(
            SigAlgo::Ed25519,
            HashAlgo::Sha512,
            [0u8; 32],
            0,
            vec![entry],
        )
        .to_bytes();
        // Reserved byte at offset 61 within the first SignedEntry.
        bytes[MANIFEST_PREFIX_SIZE + 61] = 0x01;
        assert!(matches!(
            Manifest::from_bytes(&bytes),
            Err(Error::NonZeroEntryReserved)
        ));
    }

    #[test]
    fn rejects_non_zero_reserved_entry_tail() {
        let entry = sample_entry();
        let mut bytes = Manifest::new(
            SigAlgo::Ed25519,
            HashAlgo::Sha512,
            [0u8; 32],
            0,
            vec![entry],
        )
        .to_bytes();
        // Reserved tail at offset 126 within the first SignedEntry.
        bytes[MANIFEST_PREFIX_SIZE + 200] = 0x01;
        assert!(matches!(
            Manifest::from_bytes(&bytes),
            Err(Error::NonZeroEntryReserved)
        ));
    }
}
