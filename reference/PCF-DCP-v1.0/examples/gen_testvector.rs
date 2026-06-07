//! Generates the canonical PCF-DCP v1.0 test-vector file used in spec
//! Section 17.
//!
//! Run with: `cargo run --example gen_testvector -- <output-path>`
//! (defaults to ./pcf_dcp_testvector.bin). Everything is fixed and
//! deterministic so that ports can reproduce the file byte-for-byte.

use std::io::Cursor;

use pcf::Container;
use pcf_dcp::{build_reference_vector, DcpReader};

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "pcf_dcp_testvector.bin".to_string());

    let image = build_reference_vector().expect("build reference vector");
    std::fs::write(&path, &image).expect("write file");

    // It is a conforming PCF v1.0 file ...
    let mut pcf = Container::open(Cursor::new(image.clone())).expect("pcf open");
    pcf.verify().expect("pcf verify");

    // ... and a conforming DCP file.
    let mut dcp = DcpReader::open(Cursor::new(image.clone())).expect("dcp open");
    dcp.verify().expect("dcp verify");

    eprintln!("wrote {} ({} bytes)", path, image.len());
    for c in dcp.containers().expect("containers") {
        let arena = dcp.open_arena(&c).expect("arena");
        eprintln!(
            "  container {:<6} type=0x{:08X} used={} inners={}",
            c.label_string().unwrap_or_default(),
            c.partition_type,
            c.used_bytes,
            arena.len()
        );
        for info in arena.inners() {
            let n = info.data_hash_algo.digest_len();
            let hex: String = info.data_hash[..n]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let shared = info.extents.iter().filter(|e| e.shared).count();
            eprintln!(
                "    inner {:<3} type=0x{:08X} used={} extents={} shared={} data_hash={}",
                info.label,
                info.partition_type,
                info.used_bytes,
                info.extents.len(),
                shared,
                hex
            );
        }
    }
}
