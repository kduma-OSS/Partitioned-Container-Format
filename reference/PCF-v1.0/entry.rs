//! The fixed 141-byte partition entry (spec section 5.2).

use crate::consts::{HASH_FIELD_SIZE, LABEL_SIZE, NIL_UID, TYPE_RESERVED, UID_SIZE};
use crate::error::Error;
use crate::hash::HashAlgo;

/// One partition's metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionEntry {
    /// Application-defined type (`0` and `0xFFFFFFFF` are reserved).
    pub partition_type: u32,
    /// 16-byte unique identifier.
    pub uid: [u8; UID_SIZE],
    /// 32-byte ASCII label, NUL-padded.
    pub label: [u8; LABEL_SIZE],
    /// Absolute offset of the partition's data region.
    pub start_offset: u64,
    /// Bytes reserved for the partition.
    pub max_length: u64,
    /// Bytes currently used (a contiguous prefix of the reservation).
    pub used_bytes: u64,
    /// Algorithm used for `data_hash`.
    pub data_hash_algo: HashAlgo,
    /// 64-byte data hash field.
    pub data_hash: [u8; HASH_FIELD_SIZE],
}

impl PartitionEntry {
    /// Serialise to the on-disk 141-byte layout.
    pub fn to_bytes(&self) -> [u8; 141] {
        let mut b = [0u8; 141];
        b[0..4].copy_from_slice(&self.partition_type.to_le_bytes());
        b[4..20].copy_from_slice(&self.uid);
        b[20..52].copy_from_slice(&self.label);
        b[52..60].copy_from_slice(&self.start_offset.to_le_bytes());
        b[60..68].copy_from_slice(&self.max_length.to_le_bytes());
        b[68..76].copy_from_slice(&self.used_bytes.to_le_bytes());
        b[76] = self.data_hash_algo.id();
        b[77..141].copy_from_slice(&self.data_hash);
        b
    }

    /// Parse from the on-disk 141-byte layout.
    pub fn from_bytes(b: &[u8; 141]) -> Result<Self, Error> {
        let partition_type = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let mut uid = [0u8; UID_SIZE];
        uid.copy_from_slice(&b[4..20]);
        let mut label = [0u8; LABEL_SIZE];
        label.copy_from_slice(&b[20..52]);
        let start_offset = u64::from_le_bytes(b[52..60].try_into().unwrap());
        let max_length = u64::from_le_bytes(b[60..68].try_into().unwrap());
        let used_bytes = u64::from_le_bytes(b[68..76].try_into().unwrap());
        let data_hash_algo = HashAlgo::from_id(b[76])?;
        let mut data_hash = [0u8; HASH_FIELD_SIZE];
        data_hash.copy_from_slice(&b[77..141]);
        Ok(PartitionEntry {
            partition_type,
            uid,
            label,
            start_offset,
            max_length,
            used_bytes,
            data_hash_algo,
            data_hash,
        })
    }

    /// Apply the conformance checks a reader must run on a live entry
    /// (spec C5, C6, C7).
    pub fn validate(&self) -> Result<(), Error> {
        if self.partition_type == TYPE_RESERVED {
            return Err(Error::ReservedType);
        }
        if self.uid == NIL_UID {
            return Err(Error::NilUid);
        }
        if self.used_bytes > self.max_length {
            return Err(Error::UsedExceedsMax);
        }
        decode_label(&self.label)?; // validates label bytes
        Ok(())
    }

    /// Decode the label as a `String` (reads up to the first NUL).
    pub fn label_string(&self) -> Result<String, Error> {
        decode_label(&self.label)
    }

    /// Free bytes remaining in the partition (`max_length - used_bytes`).
    pub fn free_bytes(&self) -> u64 {
        self.max_length.saturating_sub(self.used_bytes)
    }
}

/// Build a 32-byte label field from a string (spec section 10).
pub fn encode_label(s: &str) -> Result<[u8; LABEL_SIZE], Error> {
    let bytes = s.as_bytes();
    if bytes.len() > LABEL_SIZE {
        return Err(Error::InvalidLabel);
    }
    for &c in bytes {
        if c == 0 || c >= 0x80 {
            return Err(Error::InvalidLabel);
        }
    }
    let mut l = [0u8; LABEL_SIZE];
    l[..bytes.len()].copy_from_slice(bytes);
    Ok(l)
}

/// Decode a 32-byte label field: read until the first NUL or 32 bytes,
/// rejecting any byte >= 0x80 (spec section 10).
pub fn decode_label(label: &[u8; LABEL_SIZE]) -> Result<String, Error> {
    let mut end = LABEL_SIZE;
    for (i, &c) in label.iter().enumerate() {
        if c == 0 {
            end = i;
            break;
        }
        if c >= 0x80 {
            return Err(Error::InvalidLabel);
        }
    }
    Ok(String::from_utf8_lossy(&label[..end]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PartitionEntry {
        PartitionEntry {
            partition_type: 7,
            uid: [1; 16],
            label: encode_label("hello").unwrap(),
            start_offset: 1024,
            max_length: 4096,
            used_bytes: 100,
            data_hash_algo: HashAlgo::Sha256,
            data_hash: HashAlgo::Sha256.compute(b"x"),
        }
    }

    #[test]
    fn entry_roundtrip() {
        let e = sample();
        assert_eq!(PartitionEntry::from_bytes(&e.to_bytes()).unwrap(), e);
    }

    #[test]
    fn label_roundtrip() {
        let l = encode_label("config.bin").unwrap();
        assert_eq!(decode_label(&l).unwrap(), "config.bin");
    }

    #[test]
    fn full_label_no_terminator() {
        let s = "a".repeat(32);
        let l = encode_label(&s).unwrap();
        assert_eq!(decode_label(&l).unwrap(), s);
    }

    #[test]
    fn label_too_long() {
        assert!(matches!(
            encode_label(&"a".repeat(33)),
            Err(Error::InvalidLabel)
        ));
    }

    #[test]
    fn validate_rejects_reserved_and_nil() {
        let mut e = sample();
        e.partition_type = 0;
        assert!(matches!(e.validate(), Err(Error::ReservedType)));
        let mut e = sample();
        e.uid = [0; 16];
        assert!(matches!(e.validate(), Err(Error::NilUid)));
    }
}
