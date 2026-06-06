//! The optional fixed 20-byte file trailer (spec section 4, "File Trailer").
//!
//! A trailer is present only when the file header's `partition_table_offset`
//! holds the [`crate::PT_OFFSET_TRAILER`] sentinel. It occupies the final
//! [`crate::TRAILER_SIZE`] bytes of the file and records the real offset of the
//! partition-table head together with the chain direction. Because every append
//! places a fresh trailer at the new end of file, the file's last bytes always
//! point at the newest table — enabling truly append-only writers with no
//! in-place header rewrite.

use crate::consts::TRAILER_MAGIC;
use crate::error::Error;

/// Parsed file trailer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Trailer {
    /// Absolute offset of the partition-table head block, or 0 when the file
    /// holds no table yet (empty container).
    pub partition_table_offset: u64,
    /// Chain-direction flags. Bit 0 selects forward ([`crate::CHAIN_FORWARD`])
    /// or backward ([`crate::CHAIN_BACKWARD`]) linking; all other bits are
    /// reserved and MUST be 0.
    pub chain_flags: u8,
}

impl Trailer {
    /// Serialise to the on-disk 20-byte layout. The reserved bytes 9..12 are
    /// zero and the final 8 bytes are [`TRAILER_MAGIC`].
    pub fn to_bytes(&self) -> [u8; 20] {
        let mut b = [0u8; 20];
        b[0..8].copy_from_slice(&self.partition_table_offset.to_le_bytes());
        b[8] = self.chain_flags;
        // bytes 9..12 are reserved and remain 0.
        b[12..20].copy_from_slice(&TRAILER_MAGIC);
        b
    }

    /// Parse from the on-disk 20-byte layout, validating the trailer magic.
    /// Returns [`Error::BadTrailer`] if the magic does not match (for example a
    /// truncated file).
    pub fn from_bytes(b: &[u8; 20]) -> Result<Self, Error> {
        if b[12..20] != TRAILER_MAGIC {
            return Err(Error::BadTrailer);
        }
        let mut o = [0u8; 8];
        o.copy_from_slice(&b[0..8]);
        Ok(Trailer {
            partition_table_offset: u64::from_le_bytes(o),
            chain_flags: b[8],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::{CHAIN_BACKWARD, CHAIN_FORWARD};

    #[test]
    fn trailer_roundtrip_forward() {
        let t = Trailer {
            partition_table_offset: 0x1234_5678,
            chain_flags: CHAIN_FORWARD,
        };
        let b = t.to_bytes();
        // Reserved bytes are zero; magic occupies the tail.
        assert_eq!(&b[9..12], &[0, 0, 0]);
        assert_eq!(&b[12..20], &TRAILER_MAGIC);
        assert_eq!(Trailer::from_bytes(&b).unwrap(), t);
    }

    #[test]
    fn trailer_roundtrip_backward() {
        let t = Trailer {
            partition_table_offset: 0,
            chain_flags: CHAIN_BACKWARD,
        };
        assert_eq!(Trailer::from_bytes(&t.to_bytes()).unwrap(), t);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut b = Trailer {
            partition_table_offset: 20,
            chain_flags: CHAIN_FORWARD,
        }
        .to_bytes();
        b[19] = 0x00;
        assert!(matches!(Trailer::from_bytes(&b), Err(Error::BadTrailer)));
    }
}
