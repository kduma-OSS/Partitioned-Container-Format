//! The fixed 24-byte DCP Header at arena offset 0 (spec Section 6).

use crate::consts::{DCP_HEADER_SIZE, DCP_MAGIC};
use crate::error::{Error, Result};

/// Parsed DCP Header. All offsets it carries are arena-relative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DcpHeader {
    /// PCF-DCP profile major version (MUST be implemented by the reader).
    pub profile_version_major: u8,
    /// PCF-DCP profile minor version (a reader SHOULD accept a higher value).
    pub profile_version_minor: u8,
    /// Reserved; MUST be 0 in v1.0.
    pub flags: u16,
    /// Arena-relative offset of the first Inner Table Block (0 = no inner
    /// partitions).
    pub inner_table_offset: u64,
    /// Bump pointer: arena-relative offset of the first free byte. Every stored
    /// structure and extent lies within `[0, arena_used)`.
    pub arena_used: u64,
}

impl DcpHeader {
    /// Serialise to the on-disk 24-byte layout.
    pub fn to_bytes(&self) -> [u8; 24] {
        let mut b = [0u8; 24];
        b[0..4].copy_from_slice(&DCP_MAGIC);
        b[4] = self.profile_version_major;
        b[5] = self.profile_version_minor;
        b[6..8].copy_from_slice(&self.flags.to_le_bytes());
        b[8..16].copy_from_slice(&self.inner_table_offset.to_le_bytes());
        b[16..24].copy_from_slice(&self.arena_used.to_le_bytes());
        b
    }

    /// Parse from the on-disk 24-byte layout, validating the magic.
    pub fn from_bytes(b: &[u8; 24]) -> Result<Self> {
        if b[0..4] != DCP_MAGIC {
            return Err(Error::BadDcpMagic);
        }
        Ok(DcpHeader {
            profile_version_major: b[4],
            profile_version_minor: b[5],
            flags: u16::from_le_bytes([b[6], b[7]]),
            inner_table_offset: u64::from_le_bytes(b[8..16].try_into().unwrap()),
            arena_used: u64::from_le_bytes(b[16..24].try_into().unwrap()),
        })
    }
}

/// Read a DCP Header from the start of an arena byte slice.
pub(crate) fn read_header(arena: &[u8]) -> Result<DcpHeader> {
    let fixed: [u8; 24] = arena
        .get(0..DCP_HEADER_SIZE as usize)
        .ok_or(Error::BadDcpMagic)?
        .try_into()
        .unwrap();
    DcpHeader::from_bytes(&fixed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = DcpHeader {
            profile_version_major: 1,
            profile_version_minor: 0,
            flags: 0,
            inner_table_offset: 109,
            arena_used: 465,
        };
        assert_eq!(DcpHeader::from_bytes(&h.to_bytes()).unwrap(), h);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut b = [0u8; 24];
        b[0..4].copy_from_slice(b"XXXX");
        assert!(matches!(DcpHeader::from_bytes(&b), Err(Error::BadDcpMagic)));
    }
}
