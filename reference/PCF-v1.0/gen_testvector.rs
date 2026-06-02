//! Generates the canonical PCF v1.0 test-vector file used in spec section 15.
//!
//! Run with: `cargo run --example gen_testvector -- <output-path>`
//! (defaults to ./pcf_testvector.bin). Everything is fixed and deterministic so
//! that ports can reproduce the file byte-for-byte.

use std::io::Cursor;

use pcf::{Container, HashAlgo};

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "pcf_testvector.bin".to_string());

    let mut c = Container::create_with(Cursor::new(Vec::new()), 8, HashAlgo::Sha256).unwrap();

    // Partition 0: a SHA-256-protected text region.
    c.add_partition(
        0x0000_0010,
        [0x11u8; 16],
        "alpha",
        b"Hello, PCF!",
        0,
        HashAlgo::Sha256,
    )
    .unwrap();

    // Partition 1: a RAW region protected by CRC-32C.
    c.add_partition(
        0xFFFF_FFFF,
        [0x22u8; 16],
        "raw",
        &[0, 1, 2, 3, 4, 5, 6, 7],
        0,
        HashAlgo::Crc32c,
    )
    .unwrap();

    // Compact to the canonical, tightly-packed layout.
    let image = c.compacted_image().unwrap();
    std::fs::write(&path, &image).unwrap();

    // Re-open the produced bytes and verify, then print a short report.
    let mut v = Container::open(Cursor::new(image.clone())).unwrap();
    v.verify().unwrap();

    eprintln!("wrote {} ({} bytes)", path, image.len());
    for e in v.entries().unwrap() {
        let n = e.data_hash_algo.digest_len();
        let hex: String = e.data_hash[..n].iter().map(|b| format!("{b:02x}")).collect();
        eprintln!(
            "  {:<6} type=0x{:08X} algo={:?} start={} used={} data_hash={}",
            e.label_string().unwrap(),
            e.partition_type,
            e.data_hash_algo,
            e.start_offset,
            e.used_bytes,
            hex
        );
    }
}
