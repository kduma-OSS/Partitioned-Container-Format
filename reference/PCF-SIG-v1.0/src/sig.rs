//! The byte payload of a `PCFSIG_SIG` partition: Manifest, length-prefixed
//! signature bytes, length-prefixed trailer (spec Section 7.3).

use crate::consts::MANIFEST_PREFIX_SIZE;
use crate::error::{Error, Result};
use crate::manifest::Manifest;

/// One PCFSIG_SIG partition's full payload (spec Section 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignaturePartition {
    /// Parsed Manifest.
    pub manifest: Manifest,
    /// Raw bytes of the Manifest as serialised in the partition; this is the
    /// signing input and MUST be byte-exact, so we cache it.
    pub manifest_bytes: Vec<u8>,
    /// Raw signature bytes (the algorithm's natural output).
    pub signature: Vec<u8>,
    /// Trailer bytes; MUST be empty in v1.0.
    pub trailer: Vec<u8>,
}

impl SignaturePartition {
    /// Compose a partition payload from its parts; computes `manifest_bytes`
    /// from `manifest`.
    pub fn new(manifest: Manifest, signature: Vec<u8>) -> Self {
        let manifest_bytes = manifest.to_bytes();
        Self {
            manifest,
            manifest_bytes,
            signature,
            trailer: Vec::new(),
        }
    }

    /// Serialise to the on-disk byte layout (spec Section 7).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            self.manifest_bytes.len() + 4 + self.signature.len() + 4 + self.trailer.len(),
        );
        out.extend_from_slice(&self.manifest_bytes);
        out.extend_from_slice(&(self.signature.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&(self.trailer.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.trailer);
        out
    }

    /// Parse the on-disk byte layout. Validates: manifest, sig_length present,
    /// sig_bytes available, trailer_length present and 0 in v1.0, total length
    /// equals partition `used_bytes`. Verification of the signature itself is
    /// done by `verify::Verifier`, not here.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < MANIFEST_PREFIX_SIZE {
            return Err(Error::MalformedSignaturePartition);
        }
        let manifest = Manifest::from_bytes(b)?;
        let manifest_len = manifest.byte_len();
        // Manifest::from_bytes already verified that b is long enough for the
        // declared signed_count; defend against junk past the manifest.
        if b.len() < manifest_len + 4 {
            return Err(Error::MalformedSignaturePartition);
        }
        let sig_length =
            u32::from_le_bytes(b[manifest_len..manifest_len + 4].try_into().unwrap()) as usize;
        if sig_length == 0 {
            return Err(Error::SignatureLengthMismatch);
        }
        let sig_start = manifest_len + 4;
        let sig_end = sig_start
            .checked_add(sig_length)
            .ok_or(Error::MalformedSignaturePartition)?;
        if b.len() < sig_end + 4 {
            return Err(Error::MalformedSignaturePartition);
        }
        let signature = b[sig_start..sig_end].to_vec();
        let trailer_length =
            u32::from_le_bytes(b[sig_end..sig_end + 4].try_into().unwrap()) as usize;
        if trailer_length != 0 {
            return Err(Error::NonZeroTrailer);
        }
        let total_end = sig_end + 4 + trailer_length;
        if b.len() != total_end {
            return Err(Error::MalformedSignaturePartition);
        }

        let manifest_bytes = b[..manifest_len].to_vec();
        Ok(Self {
            manifest,
            manifest_bytes,
            signature,
            trailer: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algo::SigAlgo;
    use crate::manifest::SignedEntry;
    use pcf::{HashAlgo, LABEL_SIZE};

    fn sample_payload() -> SignaturePartition {
        let entry = SignedEntry {
            uid: [0x11; 16],
            partition_type: 0x10,
            label: {
                let mut l = [0u8; LABEL_SIZE];
                l[..5].copy_from_slice(b"alpha");
                l
            },
            used_bytes: 11,
            data_hash_algo: HashAlgo::Sha256,
            data_hash: HashAlgo::Sha256.compute(b"Hello, PCF!"),
        };
        let m = Manifest::new(
            SigAlgo::Ed25519,
            HashAlgo::Sha512,
            [0u8; 32],
            0,
            vec![entry],
        );
        SignaturePartition::new(m, vec![0xAAu8; 64])
    }

    #[test]
    fn signature_partition_roundtrip() {
        let p = sample_payload();
        let bytes = p.to_bytes();
        let parsed = SignaturePartition::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.manifest, p.manifest);
        assert_eq!(parsed.manifest_bytes, p.manifest_bytes);
        assert_eq!(parsed.signature, p.signature);
        assert!(parsed.trailer.is_empty());
    }

    #[test]
    fn rejects_non_zero_trailer() {
        let mut p = sample_payload();
        p.trailer = vec![1, 2, 3];
        let bytes = p.to_bytes();
        assert!(matches!(
            SignaturePartition::from_bytes(&bytes),
            Err(Error::NonZeroTrailer)
        ));
    }

    #[test]
    fn rejects_truncated_after_manifest() {
        let p = sample_payload();
        let mut bytes = p.to_bytes();
        bytes.truncate(p.manifest_bytes.len() + 3); // chop in the middle of sig_length
        assert!(matches!(
            SignaturePartition::from_bytes(&bytes),
            Err(Error::MalformedSignaturePartition)
        ));
    }

    #[test]
    fn rejects_zero_sig_length() {
        let p = sample_payload();
        let ml = p.manifest_bytes.len();
        // Build a minimal payload: manifest || u32(0) || u32(0).
        let mut bytes = Vec::with_capacity(ml + 8);
        bytes.extend_from_slice(&p.manifest_bytes);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            SignaturePartition::from_bytes(&bytes),
            Err(Error::SignatureLengthMismatch)
        ));
    }
}
