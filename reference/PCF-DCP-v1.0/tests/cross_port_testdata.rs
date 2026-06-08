//! Cross-port test-vector parity check.
//!
//! Every PCF-DCP language port ships its own copy of the canonical 700-byte
//! container vector under `implementations/<lang>/pcf-dcp/testdata/
//! canonical.bin`. Each port's own test suite asserts that its writer produces
//! this byte sequence; this Rust workspace test additionally asserts that the
//! shipped *files* are byte-identical, so that any future regeneration of the
//! reference vector cannot leave one port out of sync.

use std::fs;
use std::path::{Path, PathBuf};

/// The reference vector compiled into the test binary.
const REFERENCE: &[u8] = include_bytes!("../testdata/canonical.bin");

/// Locate the repository root from this crate's `CARGO_MANIFEST_DIR`.
/// reference/PCF-DCP-v1.0 → repository root is two levels up.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("PCF-DCP-v1.0 crate has a parent (reference/)")
        .parent()
        .expect("reference/ has a parent (repo root)")
        .to_path_buf()
}

fn read_port_vector(rel: &str) -> Vec<u8> {
    let path = repo_root().join(rel);
    fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "failed to read {}: {e}\n\
             every PCF-DCP language port MUST ship a copy of the canonical \
             test vector identical to reference/PCF-DCP-v1.0/testdata/canonical.bin",
            path.display(),
        )
    })
}

fn assert_byte_identical(label: &str, port: &[u8]) {
    assert_eq!(
        port.len(),
        REFERENCE.len(),
        "{label} ships canonical.bin of length {} bytes; reference is {} bytes",
        port.len(),
        REFERENCE.len(),
    );
    if port != REFERENCE {
        let first_diff = port
            .iter()
            .zip(REFERENCE.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(REFERENCE.len());
        panic!(
            "{label} canonical.bin diverges from reference at offset {first_diff}: \
             port byte = 0x{:02x}, reference byte = 0x{:02x}",
            port.get(first_diff).copied().unwrap_or(0),
            REFERENCE.get(first_diff).copied().unwrap_or(0),
        );
    }
}

#[test]
fn typescript_port_testdata_matches_reference() {
    let port = read_port_vector("implementations/ts/pcf-dcp/testdata/canonical.bin");
    assert_byte_identical("TypeScript port", &port);
}

#[test]
fn php_port_testdata_matches_reference() {
    let port = read_port_vector("implementations/php/pcf-dcp/testdata/canonical.bin");
    assert_byte_identical("PHP port", &port);
}

#[test]
fn dotnet_port_testdata_matches_reference() {
    let port = read_port_vector("implementations/dotnet/pcf-dcp/testdata/canonical.bin");
    assert_byte_identical(".NET port", &port);
}

/// Sanity: the reference itself is the canonical 700-byte vector we expect.
#[test]
fn reference_has_canonical_length() {
    assert_eq!(REFERENCE.len(), 700);
}
