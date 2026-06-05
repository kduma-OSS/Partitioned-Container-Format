//! Signature algorithm registry (spec Section 8) and key-format registry
//! (spec Section 6.2).
//!
//! This crate implements `Ed25519` as the MUST-support baseline. All other
//! registry entries are recognised by id so that a Reader can correctly
//! report "unsupported" without misclassifying a well-formed file as
//! malformed (spec Section 15, R9).

use crate::error::Error;
use pcf::HashAlgo;

/// A signature algorithm id (spec Section 8, Appendix B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAlgo {
    /// `1` — Ed25519 (RFC 8032). Manifest hash is intrinsically SHA-512.
    Ed25519,
    /// `2` — RSA-PSS-SHA-256. Recognised but not implemented in this crate.
    RsaPssSha256,
    /// `4` — RSA-PSS-SHA-512. Recognised but not implemented in this crate.
    RsaPssSha512,
    /// `5` — RSA-PKCS1v15-SHA-256. Recognised but not implemented.
    RsaPkcs1v15Sha256,
    /// `7` — RSA-PKCS1v15-SHA-512. Recognised but not implemented.
    RsaPkcs1v15Sha512,
    /// `16` — ECDSA-P256-SHA-256. Recognised but not implemented.
    EcdsaP256Sha256,
    /// `18` — ECDSA-P521-SHA-512. Recognised but not implemented.
    EcdsaP521Sha512,
    /// `32` — X.509 chain. Recognised but not implemented.
    X509Chain,
}

impl SigAlgo {
    /// Map a registry id byte to an algorithm.
    pub fn from_id(id: u8) -> Result<Self, Error> {
        Ok(match id {
            0 => return Err(Error::UnknownSigAlgo(0)),
            1 => SigAlgo::Ed25519,
            2 => SigAlgo::RsaPssSha256,
            4 => SigAlgo::RsaPssSha512,
            5 => SigAlgo::RsaPkcs1v15Sha256,
            7 => SigAlgo::RsaPkcs1v15Sha512,
            16 => SigAlgo::EcdsaP256Sha256,
            18 => SigAlgo::EcdsaP521Sha512,
            32 => SigAlgo::X509Chain,
            other => return Err(Error::UnknownSigAlgo(other)),
        })
    }

    /// The registry id byte for this algorithm.
    pub fn id(self) -> u8 {
        match self {
            SigAlgo::Ed25519 => 1,
            SigAlgo::RsaPssSha256 => 2,
            SigAlgo::RsaPssSha512 => 4,
            SigAlgo::RsaPkcs1v15Sha256 => 5,
            SigAlgo::RsaPkcs1v15Sha512 => 7,
            SigAlgo::EcdsaP256Sha256 => 16,
            SigAlgo::EcdsaP521Sha512 => 18,
            SigAlgo::X509Chain => 32,
        }
    }

    /// The `manifest_hash_algo_id` an implementation MUST require for this
    /// algorithm (spec Section 8). `None` means the binding is not fixed
    /// by this crate's registry view (the X.509 chain case, where the leaf
    /// certificate names the actual hash).
    pub fn required_manifest_hash(self) -> Option<HashAlgo> {
        match self {
            SigAlgo::Ed25519 => Some(HashAlgo::Sha512),
            SigAlgo::RsaPssSha256 | SigAlgo::RsaPkcs1v15Sha256 | SigAlgo::EcdsaP256Sha256 => {
                Some(HashAlgo::Sha256)
            }
            SigAlgo::RsaPssSha512 | SigAlgo::RsaPkcs1v15Sha512 | SigAlgo::EcdsaP521Sha512 => {
                Some(HashAlgo::Sha512)
            }
            SigAlgo::X509Chain => None,
        }
    }

    /// Whether this build implements signing and verification for the
    /// algorithm. In v1.0 of this reference, only Ed25519 is implemented;
    /// the remaining entries are listed for correct id-level recognition.
    pub fn is_implemented(self) -> bool {
        matches!(self, SigAlgo::Ed25519)
    }
}

/// A key-format id (spec Section 6.2, Appendix B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    /// `1` — Ed25519 raw public key (32 bytes, RFC 8032).
    Ed25519Raw,
    /// `2` — RSA SPKI DER. Recognised but not implemented in this crate.
    RsaSpkiDer,
    /// `3` — ECDSA SPKI DER. Recognised but not implemented.
    EcdsaSpkiDer,
    /// `16` — X.509 single certificate (DER). Recognised but not implemented.
    X509Cert,
    /// `17` — X.509 length-prefixed chain. Recognised but not implemented.
    X509Chain,
}

impl KeyFormat {
    /// Map a registry id byte to a format.
    pub fn from_id(id: u8) -> Result<Self, Error> {
        Ok(match id {
            0 => return Err(Error::UnknownKeyFormat(0)),
            1 => KeyFormat::Ed25519Raw,
            2 => KeyFormat::RsaSpkiDer,
            3 => KeyFormat::EcdsaSpkiDer,
            16 => KeyFormat::X509Cert,
            17 => KeyFormat::X509Chain,
            other => return Err(Error::UnknownKeyFormat(other)),
        })
    }

    /// The registry id byte for this format.
    pub fn id(self) -> u8 {
        match self {
            KeyFormat::Ed25519Raw => 1,
            KeyFormat::RsaSpkiDer => 2,
            KeyFormat::EcdsaSpkiDer => 3,
            KeyFormat::X509Cert => 16,
            KeyFormat::X509Chain => 17,
        }
    }

    /// Whether this build can extract a verification key from records using
    /// this format. Only `Ed25519Raw` is implemented in v1.0 of this
    /// reference.
    pub fn is_implemented(self) -> bool {
        matches!(self, KeyFormat::Ed25519Raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sig_algo_roundtrip_ids() {
        for a in [
            SigAlgo::Ed25519,
            SigAlgo::RsaPssSha256,
            SigAlgo::RsaPssSha512,
            SigAlgo::RsaPkcs1v15Sha256,
            SigAlgo::RsaPkcs1v15Sha512,
            SigAlgo::EcdsaP256Sha256,
            SigAlgo::EcdsaP521Sha512,
            SigAlgo::X509Chain,
        ] {
            assert_eq!(SigAlgo::from_id(a.id()).unwrap(), a);
        }
    }

    #[test]
    fn key_format_roundtrip_ids() {
        for f in [
            KeyFormat::Ed25519Raw,
            KeyFormat::RsaSpkiDer,
            KeyFormat::EcdsaSpkiDer,
            KeyFormat::X509Cert,
            KeyFormat::X509Chain,
        ] {
            assert_eq!(KeyFormat::from_id(f.id()).unwrap(), f);
        }
    }

    #[test]
    fn sig_algo_id_zero_is_reserved() {
        assert!(matches!(SigAlgo::from_id(0), Err(Error::UnknownSigAlgo(0))));
    }

    #[test]
    fn key_format_id_zero_is_reserved() {
        assert!(matches!(
            KeyFormat::from_id(0),
            Err(Error::UnknownKeyFormat(0))
        ));
    }

    #[test]
    fn ed25519_requires_sha512_manifest_hash() {
        assert_eq!(
            SigAlgo::Ed25519.required_manifest_hash(),
            Some(HashAlgo::Sha512)
        );
    }
}
