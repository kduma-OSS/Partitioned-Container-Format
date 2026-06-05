//! The Key Record stored in a `PCFSIG_KEY` partition (spec Section 6).
//!
//! A Key Record is a fixed prefix (`KEY_PREFIX_SIZE` bytes) carrying the
//! 32-byte SHA-256 fingerprint plus a length-prefixed `key_data` blob, then
//! an optional Type-Length-Value metadata stream that runs to `used_bytes`.

use sha2::{Digest, Sha256};

use crate::algo::KeyFormat;
use crate::consts::*;
use crate::error::{Error, Result};

/// One metadata TLV entry (spec Section 6.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyMetadata {
    /// 16-bit tag from the registry (Appendix B).
    pub tag: u16,
    /// Value bytes; interpretation depends on `tag`.
    pub value: Vec<u8>,
}

/// A parsed Key Record (spec Section 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    /// `record_version_major`. v1.0 implementations require 1.
    pub version_major: u16,
    /// `record_version_minor`.
    pub version_minor: u16,
    /// `key_format_id` (spec Section 6.2).
    pub key_format: KeyFormat,
    /// 32-byte SHA-256 fingerprint of `key_data` (spec Section 6.3).
    pub fingerprint: [u8; FINGERPRINT_SIZE],
    /// Raw key material in the encoding named by `key_format`.
    pub key_data: Vec<u8>,
    /// Optional metadata entries (spec Section 6.4).
    pub metadata: Vec<KeyMetadata>,
}

impl KeyRecord {
    /// Build a Key Record from raw key bytes; fills in version and
    /// fingerprint deterministically.
    pub fn new(key_format: KeyFormat, key_data: Vec<u8>) -> Result<Self> {
        if key_data.is_empty() {
            return Err(Error::EmptyKeyData);
        }
        let fingerprint = compute_fingerprint(&key_data);
        Ok(Self {
            version_major: PROFILE_VERSION_MAJOR,
            version_minor: PROFILE_VERSION_MINOR,
            key_format,
            fingerprint,
            key_data,
            metadata: Vec::new(),
        })
    }

    /// Append a metadata TLV entry.
    pub fn with_metadata(mut self, tag: u16, value: Vec<u8>) -> Self {
        self.metadata.push(KeyMetadata { tag, value });
        self
    }

    /// Serialise to the on-disk byte layout (spec Section 6.1).
    pub fn to_bytes(&self) -> Vec<u8> {
        let key_len = self.key_data.len();
        let mut meta_len = 0usize;
        for m in &self.metadata {
            meta_len += 6 + m.value.len();
        }
        let mut out = Vec::with_capacity(KEY_PREFIX_SIZE + key_len + meta_len);

        out.extend_from_slice(&KEY_MAGIC);
        out.extend_from_slice(&self.version_major.to_le_bytes());
        out.extend_from_slice(&self.version_minor.to_le_bytes());
        out.push(self.key_format.id());
        out.extend_from_slice(&[0u8; 3]); // reserved
        out.extend_from_slice(&self.fingerprint);
        out.extend_from_slice(&(key_len as u32).to_le_bytes());
        out.extend_from_slice(&self.key_data);

        for m in &self.metadata {
            out.extend_from_slice(&m.tag.to_le_bytes());
            out.extend_from_slice(&(m.value.len() as u32).to_le_bytes());
            out.extend_from_slice(&m.value);
        }
        out
    }

    /// Parse from the on-disk byte layout (spec Section 6.1).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < KEY_PREFIX_SIZE {
            return Err(Error::MalformedSignaturePartition);
        }
        if b[0..8] != KEY_MAGIC {
            return Err(Error::BadKeyMagic);
        }
        let version_major = u16::from_le_bytes([b[8], b[9]]);
        let version_minor = u16::from_le_bytes([b[10], b[11]]);
        if version_major != PROFILE_VERSION_MAJOR {
            return Err(Error::UnsupportedMajor(version_major));
        }
        let key_format = KeyFormat::from_id(b[12])?;
        if b[13] != 0 || b[14] != 0 || b[15] != 0 {
            return Err(Error::NonZeroKeyReserved);
        }
        let mut fingerprint = [0u8; FINGERPRINT_SIZE];
        fingerprint.copy_from_slice(&b[16..48]);
        let key_data_length = u32::from_le_bytes([b[48], b[49], b[50], b[51]]) as usize;
        if key_data_length == 0 {
            return Err(Error::EmptyKeyData);
        }
        let key_end = KEY_PREFIX_SIZE
            .checked_add(key_data_length)
            .ok_or(Error::MalformedSignaturePartition)?;
        if b.len() < key_end {
            return Err(Error::MalformedSignaturePartition);
        }
        let key_data = b[KEY_PREFIX_SIZE..key_end].to_vec();

        let computed = compute_fingerprint(&key_data);
        if computed != fingerprint {
            return Err(Error::FingerprintMismatch);
        }

        let mut metadata = Vec::new();
        let mut cur = key_end;
        while cur < b.len() {
            if b.len() - cur < 6 {
                return Err(Error::MalformedSignaturePartition);
            }
            let tag = u16::from_le_bytes([b[cur], b[cur + 1]]);
            let len = u32::from_le_bytes([b[cur + 2], b[cur + 3], b[cur + 4], b[cur + 5]]) as usize;
            let value_start = cur + 6;
            let value_end = value_start
                .checked_add(len)
                .ok_or(Error::MalformedSignaturePartition)?;
            if value_end > b.len() {
                return Err(Error::MalformedSignaturePartition);
            }
            metadata.push(KeyMetadata {
                tag,
                value: b[value_start..value_end].to_vec(),
            });
            cur = value_end;
        }

        Ok(Self {
            version_major,
            version_minor,
            key_format,
            fingerprint,
            key_data,
            metadata,
        })
    }
}

/// Compute the SHA-256 fingerprint of a key's `key_data` (spec Section 6.3).
pub fn compute_fingerprint(key_data: &[u8]) -> [u8; FINGERPRINT_SIZE] {
    let digest = Sha256::digest(key_data);
    let mut out = [0u8; FINGERPRINT_SIZE];
    out.copy_from_slice(digest.as_slice());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_record_roundtrip() {
        let key = vec![0x42u8; ED25519_PUBLIC_KEY_LEN];
        let rec = KeyRecord::new(KeyFormat::Ed25519Raw, key.clone()).unwrap();
        let bytes = rec.to_bytes();
        let parsed = KeyRecord::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, rec);
        assert_eq!(parsed.fingerprint, compute_fingerprint(&key));
    }

    #[test]
    fn rejects_truncated_record() {
        let short = vec![0u8; KEY_PREFIX_SIZE - 1];
        assert!(matches!(
            KeyRecord::from_bytes(&short),
            Err(Error::MalformedSignaturePartition)
        ));
    }

    #[test]
    fn rejects_bad_magic() {
        let key = vec![0x42u8; 32];
        let mut bytes = KeyRecord::new(KeyFormat::Ed25519Raw, key)
            .unwrap()
            .to_bytes();
        bytes[0] = b'X';
        assert!(matches!(
            KeyRecord::from_bytes(&bytes),
            Err(Error::BadKeyMagic)
        ));
    }

    #[test]
    fn rejects_non_zero_reserved() {
        let key = vec![0x42u8; 32];
        let mut bytes = KeyRecord::new(KeyFormat::Ed25519Raw, key)
            .unwrap()
            .to_bytes();
        bytes[13] = 0xFF;
        assert!(matches!(
            KeyRecord::from_bytes(&bytes),
            Err(Error::NonZeroKeyReserved)
        ));
    }

    #[test]
    fn rejects_fingerprint_mismatch() {
        let key = vec![0x42u8; 32];
        let mut bytes = KeyRecord::new(KeyFormat::Ed25519Raw, key)
            .unwrap()
            .to_bytes();
        bytes[16] ^= 0x01;
        assert!(matches!(
            KeyRecord::from_bytes(&bytes),
            Err(Error::FingerprintMismatch)
        ));
    }

    #[test]
    fn metadata_roundtrip() {
        let key = vec![0x10u8; 32];
        let rec = KeyRecord::new(KeyFormat::Ed25519Raw, key)
            .unwrap()
            .with_metadata(0x0005, b"hello".to_vec())
            .with_metadata(0x0001, b"CN=test".to_vec());
        let bytes = rec.to_bytes();
        let parsed = KeyRecord::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.metadata, rec.metadata);
    }

    #[test]
    fn rejects_unknown_major() {
        let key = vec![0x10u8; 32];
        let mut bytes = KeyRecord::new(KeyFormat::Ed25519Raw, key)
            .unwrap()
            .to_bytes();
        bytes[8] = 2;
        assert!(matches!(
            KeyRecord::from_bytes(&bytes),
            Err(Error::UnsupportedMajor(2))
        ));
    }
}
