//! # `pcf-sig` — PCF Cryptographic Signatures (reference implementation)
//!
//! This crate is the reference reader/writer for **PCF-SIG v1.0**, an
//! application-level profile that adds cryptographic authentication to
//! [PCF v1.0](../pcf/index.html) without changing the PCF byte container.
//!
//! It mirrors the written specification (`specs/PCF-SIG-spec-v1.0.txt`)
//! field-for-field and favours auditability over performance.
//!
//! ## Layout at a glance
//!
//! Two new PCF partition types are defined:
//!
//! * **`PCFSIG_KEY`** (type `0xAAAB0001`) — one Key Record carrying a
//!   signer's raw public key or X.509 certificate (chain), identified by a
//!   32-byte SHA-256 fingerprint of the key material.
//! * **`PCFSIG_SIG`** (type `0xAAAB0002`) — one Manifest enumerating the
//!   partitions this signature covers (by uid + protected fields), followed
//!   by the raw bytes of a signature over the manifest.
//!
//! Signatures cover `uid`, `partition_type`, `label`, `used_bytes`,
//! `data_hash_algo_id`, and `data_hash` of each named partition. They do
//! NOT cover `start_offset` or `max_length`, so PCF compaction and other
//! relocations leave signatures valid as long as partition bytes do not
//! change.
//!
//! ## Example
//!
//! ```no_run
//! use std::io::Cursor;
//! use pcf::{Container, HashAlgo};
//! use pcf_sig::{sign_partitions, verify_all, DataRecheck, SigningMaterial};
//!
//! let mut c = Container::create(Cursor::new(Vec::new()))?;
//! let alpha = [1u8; 16];
//! c.add_partition(0x10, alpha, "alpha", b"hello", 0, HashAlgo::Sha256)?;
//!
//! let signer = SigningMaterial::ed25519_from_seed(&[0x42u8; 32]);
//! let key_uid = [0xA0u8; 16];
//! let sig_uid = [0xA1u8; 16];
//! sign_partitions(
//!     &mut c, &signer, &[alpha], sig_uid, key_uid, 0, "pcfsig", "pcfkey",
//! )?;
//!
//! let reports = verify_all(&mut c, DataRecheck::Recompute)?;
//! assert_eq!(reports.len(), 1);
//! # Ok::<(), pcf_sig::Error>(())
//! ```

mod algo;
pub mod consts;
mod error;
mod key;
mod manifest;
mod sig;
mod sign;
mod verify;

pub use algo::{KeyFormat, SigAlgo};
pub use consts::*;
pub use error::{Error, Result};
pub use key::{compute_fingerprint, KeyMetadata, KeyRecord};
pub use manifest::{is_crypto_hash, Manifest, SignedEntry};
pub use sig::SignaturePartition;
pub use sign::{
    ensure_key_partition, sign_partitions, signed_entry_from_partition, SigningMaterial,
};
pub use verify::{
    verify_all, verify_all_with_recheck, DataRecheck, EntryReport, EntryVerdict, ManifestVerdict,
    SignatureReport, UnverifiableReason,
};
