//! Generates the canonical PCF-SIG v1.0 test-vector file used in spec
//! section 19.
//!
//! Run with: `cargo run --example gen_testvector -- <output-path>`
//! (defaults to ./pcfsig_testvector.bin).
//!
//! The Ed25519 keypair is generated deterministically from a fixed 32-byte
//! seed of 0x00..0x1F, so independent implementations can reproduce the file
//! byte-for-byte.

use std::io::Cursor;

use pcf::{Container, HashAlgo};
use pcf_sig::{sign_partitions, verify_all, DataRecheck, ManifestVerdict, SigningMaterial};
use sha2::{Digest, Sha256};

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "pcfsig_testvector.bin".to_string());

    let seed: [u8; 32] = std::array::from_fn(|i| i as u8);
    let signer = SigningMaterial::ed25519_from_seed(&seed);

    let mut c = Container::create_with(Cursor::new(Vec::new()), 8, HashAlgo::Sha256).unwrap();

    // Partition "alpha": the partition to be signed.
    c.add_partition(
        0x0000_0010,
        [0x11u8; 16],
        "alpha",
        b"Hello, PCF-SIG!",
        0,
        HashAlgo::Sha256,
    )
    .unwrap();

    // Sign it. This adds a PCFSIG_KEY partition (uid = 0x22..) and a
    // PCFSIG_SIG partition (uid = 0x33..).
    sign_partitions(
        &mut c,
        &signer,
        &[[0x11u8; 16]],
        [0x33u8; 16], // sig partition uid
        [0x22u8; 16], // key partition uid
        0,            // signed_at = unspecified
        "pcfsig",
        "pcfkey",
    )
    .unwrap();

    // Compact to the canonical layout and re-verify.
    let image = c.compacted_image().unwrap();
    std::fs::write(&path, &image).unwrap();

    let mut v = Container::open(Cursor::new(image.clone())).unwrap();
    v.verify().unwrap();
    let reports = verify_all(&mut v, DataRecheck::Recompute).unwrap();
    assert_eq!(reports.len(), 1);
    assert!(matches!(reports[0].verdict, ManifestVerdict::Valid));

    let digest = Sha256::digest(&image);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    eprintln!("wrote {} ({} bytes)", path, image.len());
    eprintln!("sha256 = {hex}");
    eprintln!(
        "signer fingerprint = {}",
        signer
            .fingerprint()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
}
