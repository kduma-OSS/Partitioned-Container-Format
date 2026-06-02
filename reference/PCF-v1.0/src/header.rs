//! The fixed 20-byte file header (spec section 4).

use crate::consts::{MAGIC, VERSION_MAJOR};
use crate::error::Error;

/// Parsed file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileHeader {
    /// Major format version.
    pub version_major: u16,
    /// Minor format version.
    pub version_minor: u16,
    /// Absolute offset of the first table block.
    pub partition_table_offset: u64,
}

impl FileHeader {
    /// Serialise to the on-disk 20-byte layout.
    pub fn to_bytes(&self) -> [u8; 20] {
        let mut b = [0u8; 20];
        b[0..8].copy_from_slice(&MAGIC);
        b[8..10].copy_from_slice(&self.version_major.to_le_bytes());
        b[10..12].copy_from_slice(&self.version_minor.to_le_bytes());
        b[12..20].copy_from_slice(&self.partition_table_offset.to_le_bytes());
        b
    }

    /// Parse from the on-disk 20-byte layout, validating magic and major
    /// version (spec conformance checks C1, C2).
    pub fn from_bytes(b: &[u8; 20]) -> Result<Self, Error> {
        if b[0..8] != MAGIC {
            return Err(Error::BadMagic);
        }
        let version_major = u16::from_le_bytes([b[8], b[9]]);
        if version_major != VERSION_MAJOR {
            return Err(Error::UnsupportedMajor(version_major));
        }
        let version_minor = u16::from_le_bytes([b[10], b[11]]);
        let mut o = [0u8; 8];
        o.copy_from_slice(&b[12..20]);
        Ok(FileHeader {
            version_major,
            version_minor,
            partition_table_offset: u64::from_le_bytes(o),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = FileHeader {
            version_major: 1,
            version_minor: 0,
            partition_table_offset: 20,
        };
        assert_eq!(FileHeader::from_bytes(&h.to_bytes()).unwrap(), h);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut b = FileHeader {
            version_major: 1,
            version_minor: 0,
            partition_table_offset: 20,
        }
        .to_bytes();
        b[0] = 0x00;
        assert!(matches!(FileHeader::from_bytes(&b), Err(Error::BadMagic)));
    }
}
