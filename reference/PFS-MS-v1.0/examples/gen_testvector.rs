//! Generate the canonical PFS-MS reference test vector for the Section 17
//! scenario, write it to `pfs_ms_testvector.bin`, and print a hex dump plus the
//! key hashes — mirroring `pcf`'s `gen_testvector` example.
//!
//! Run with: `cargo run --example gen_testvector`

use std::io::Cursor;

use pcf::{Container, HashAlgo};
use pfs_ms::{build_reference_vector, FsReader, PFS_NODE_TYPE, PFS_SESSION_TYPE};

fn hexdump(bytes: &[u8]) {
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02X}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7F).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!("{:04X}  {:<48}  {}", i * 16, hex.join(" "), ascii);
    }
}

fn main() {
    let bytes = build_reference_vector().expect("build vector");

    std::fs::write("pfs_ms_testvector.bin", &bytes).expect("write file");
    println!("wrote pfs_ms_testvector.bin ({} bytes)\n", bytes.len());

    println!(
        "SHA-256(file) = {}",
        hex(&HashAlgo::Sha256.compute(&bytes)[..32])
    );
    println!();

    println!("==== full file hex dump ====");
    hexdump(&bytes);
    println!();

    // Dump each record type by reading the partitions back out via PCF.
    let mut c = Container::open(Cursor::new(bytes.clone())).expect("pcf open");
    c.verify().expect("pcf verify");
    for e in c.entries().expect("entries") {
        let data = c.read_partition_data(&e).expect("data");
        let label = match e.partition_type {
            t if t == PFS_NODE_TYPE => "PFS_NODE",
            t if t == PFS_SESSION_TYPE => "PFS_SESSION",
            _ => "RAW",
        };
        println!(
            "---- {label} (uid {}, {} bytes, data_hash {}) ----",
            hex(&e.uid),
            data.len(),
            hex(&e.data_hash[..32])
        );
        hexdump(&data);
        println!();
    }

    // Confirm the vector reconstructs.
    let mut r = FsReader::open(Cursor::new(bytes)).expect("pfs open");
    r.verify().expect("pfs verify");
    println!("reconstruction verified OK");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
