//! Hash-algorithm registry (spec section 8).
//!
//! Each hash field in the format is a fixed 64-byte field accompanied by a
//! `u8` algorithm identifier. Digests are stored left-aligned and zero-padded;
//! CRC values are stored as little-endian integers, left-aligned and
//! zero-padded (spec section 8.2).

use crate::consts::HASH_FIELD_SIZE;
use crate::error::Error;

use crc::{Crc, CRC_32_ISCSI, CRC_32_ISO_HDLC, CRC_64_XZ};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
// `md-5` exposes its `Digest` trait too, but it is the same `digest::Digest`
// already imported from `sha2`, so we only pull in the hasher type here.
use md5::Md5;

/// A hash algorithm from the PCF registry (spec section 8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    /// `0` — no verification.
    None,
    /// `1` — CRC-32/ISO-HDLC.
    Crc32,
    /// `2` — CRC-32C (Castagnoli).
    Crc32c,
    /// `3` — CRC-64/XZ.
    Crc64,
    /// `4` — MD5 (checksum use only).
    Md5,
    /// `5` — SHA-1 (checksum use only).
    Sha1,
    /// `16` — SHA-256 (default).
    Sha256,
    /// `17` — SHA-512.
    Sha512,
    /// `18` — BLAKE3.
    Blake3,
}

impl HashAlgo {
    /// Map a registry id byte to an algorithm.
    pub fn from_id(id: u8) -> Result<Self, Error> {
        Ok(match id {
            0 => HashAlgo::None,
            1 => HashAlgo::Crc32,
            2 => HashAlgo::Crc32c,
            3 => HashAlgo::Crc64,
            4 => HashAlgo::Md5,
            5 => HashAlgo::Sha1,
            16 => HashAlgo::Sha256,
            17 => HashAlgo::Sha512,
            18 => HashAlgo::Blake3,
            other => return Err(Error::UnknownHashAlgo(other)),
        })
    }

    /// The registry id byte for this algorithm.
    pub fn id(self) -> u8 {
        match self {
            HashAlgo::None => 0,
            HashAlgo::Crc32 => 1,
            HashAlgo::Crc32c => 2,
            HashAlgo::Crc64 => 3,
            HashAlgo::Md5 => 4,
            HashAlgo::Sha1 => 5,
            HashAlgo::Sha256 => 16,
            HashAlgo::Sha512 => 17,
            HashAlgo::Blake3 => 18,
        }
    }

    /// Number of significant bytes this algorithm writes into a hash field.
    pub fn digest_len(self) -> usize {
        match self {
            HashAlgo::None => 0,
            HashAlgo::Crc32 | HashAlgo::Crc32c => 4,
            HashAlgo::Crc64 => 8,
            HashAlgo::Md5 => 16,
            HashAlgo::Sha1 => 20,
            HashAlgo::Sha256 | HashAlgo::Blake3 => 32,
            HashAlgo::Sha512 => 64,
        }
    }

    /// Whether this algorithm performs any verification (everything but `None`).
    pub fn verifies(self) -> bool {
        self != HashAlgo::None
    }

    /// Compute the full 64-byte hash field for `data` per spec section 8.2.
    pub fn compute(self, data: &[u8]) -> [u8; HASH_FIELD_SIZE] {
        let mut field = [0u8; HASH_FIELD_SIZE];
        match self {
            HashAlgo::None => {}
            HashAlgo::Crc32 => {
                const C: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);
                field[..4].copy_from_slice(&C.checksum(data).to_le_bytes());
            }
            HashAlgo::Crc32c => {
                const C: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);
                field[..4].copy_from_slice(&C.checksum(data).to_le_bytes());
            }
            HashAlgo::Crc64 => {
                const C: Crc<u64> = Crc::<u64>::new(&CRC_64_XZ);
                field[..8].copy_from_slice(&C.checksum(data).to_le_bytes());
            }
            HashAlgo::Md5 => {
                let d = Md5::digest(data);
                field[..16].copy_from_slice(d.as_slice());
            }
            HashAlgo::Sha1 => {
                let d = Sha1::digest(data);
                field[..20].copy_from_slice(d.as_slice());
            }
            HashAlgo::Sha256 => {
                let d = Sha256::digest(data);
                field[..32].copy_from_slice(d.as_slice());
            }
            HashAlgo::Sha512 => {
                let d = Sha512::digest(data);
                field[..64].copy_from_slice(d.as_slice());
            }
            HashAlgo::Blake3 => {
                field[..32].copy_from_slice(blake3::hash(data).as_bytes());
            }
        }
        field
    }

    /// Verify `data` against a stored hash field. `None` always succeeds (no
    /// verification). Only the significant prefix is compared, per spec 8.2.
    pub fn verify(self, data: &[u8], stored: &[u8; HASH_FIELD_SIZE]) -> bool {
        if !self.verifies() {
            return true;
        }
        let computed = self.compute(data);
        let n = self.digest_len();
        computed[..n] == stored[..n]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc64_xz_check_value() {
        // The canonical CRC-64/XZ check value for the ASCII input "123456789".
        let field = HashAlgo::Crc64.compute(b"123456789");
        let mut v = [0u8; 8];
        v.copy_from_slice(&field[..8]);
        assert_eq!(u64::from_le_bytes(v), 0x995D_C9BB_DF19_39FA);
    }

    #[test]
    fn crc32_iso_hdlc_check_value() {
        // CRC-32/ISO-HDLC check value for "123456789" is 0xCBF43926.
        let field = HashAlgo::Crc32.compute(b"123456789");
        let mut v = [0u8; 4];
        v.copy_from_slice(&field[..4]);
        assert_eq!(u32::from_le_bytes(v), 0xCBF4_3926);
    }

    #[test]
    fn crc32c_check_value() {
        // CRC-32C check value for "123456789" is 0xE3069283.
        let field = HashAlgo::Crc32c.compute(b"123456789");
        let mut v = [0u8; 4];
        v.copy_from_slice(&field[..4]);
        assert_eq!(u32::from_le_bytes(v), 0xE306_9283);
    }

    #[test]
    fn sha256_empty() {
        // SHA-256 of the empty string.
        let field = HashAlgo::Sha256.compute(b"");
        let expect = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(&field[..32], &expect);
        // The tail must be zero-padded.
        assert!(field[32..].iter().all(|&b| b == 0));
    }

    #[test]
    fn none_is_all_zero_and_skips() {
        let field = HashAlgo::None.compute(b"anything");
        assert!(field.iter().all(|&b| b == 0));
        assert!(HashAlgo::None.verify(b"anything", &[0u8; HASH_FIELD_SIZE]));
    }

    #[test]
    fn roundtrip_ids() {
        for a in [
            HashAlgo::None,
            HashAlgo::Crc32,
            HashAlgo::Crc32c,
            HashAlgo::Crc64,
            HashAlgo::Md5,
            HashAlgo::Sha1,
            HashAlgo::Sha256,
            HashAlgo::Sha512,
            HashAlgo::Blake3,
        ] {
            assert_eq!(HashAlgo::from_id(a.id()).unwrap(), a);
        }
    }
}
