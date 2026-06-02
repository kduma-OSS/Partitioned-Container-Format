//! Shared fixtures for the integration tests: the canonical PCF file and
//! hand-built PFS-MS records. Lives under `tests/common/` so Cargo does not
//! compile it as its own test binary.
//!
// Each test binary uses only a subset of these helpers; silence the resulting
// per-crate dead-code warnings.
#![allow(dead_code)]

use std::io::Cursor;

use pcf::{Container, HashAlgo};

/// The canonical 395-byte spec test vector (same recipe as `gen_testvector`).
pub fn canonical() -> Vec<u8> {
    let mut c = Container::create_with(Cursor::new(Vec::new()), 8, HashAlgo::Sha256).unwrap();
    c.add_partition(
        0x0000_0010,
        [0x11u8; 16],
        "alpha",
        b"Hello, PCF!",
        0,
        HashAlgo::Sha256,
    )
    .unwrap();
    c.add_partition(
        0xFFFF_FFFF,
        [0x22u8; 16],
        "raw",
        &[0, 1, 2, 3, 4, 5, 6, 7],
        0,
        HashAlgo::Crc32c,
    )
    .unwrap();
    c.compacted_image().unwrap()
}

/// Wrap a set of `(type, uid, label, data)` partitions into a compacted PCF
/// image, so the full walk → decode pipeline can be exercised.
pub fn wrap(partitions: &[(u32, [u8; 16], &str, Vec<u8>)]) -> Vec<u8> {
    let mut c = Container::create_with(Cursor::new(Vec::new()), 8, HashAlgo::Sha256).unwrap();
    for (ty, uid, label, data) in partitions {
        c.add_partition(*ty, *uid, label, data, 0, HashAlgo::Sha256)
            .unwrap();
    }
    c.compacted_image().unwrap()
}

/// Build a PFS_NODE record for a file with a DIRECT content section.
pub fn pfs_node_direct(name: &str) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(b"PFSN"); // magic
    r.push(1); // record_version
    r.push(1); // kind = file
    r.extend_from_slice(&0u16.to_le_bytes()); // flags
    r.extend_from_slice(&[0xAB; 16]); // node_id
    r.extend_from_slice(&[0xCD; 16]); // parent_id
    r.extend_from_slice(&1700000000000u64.to_le_bytes()); // mtime_unix_ms
    r.extend_from_slice(&0o644u32.to_le_bytes()); // mode
    r.extend_from_slice(&(name.len() as u16).to_le_bytes()); // name_len
    r.extend_from_slice(name.as_bytes()); // name
                                          // content section (DIRECT, 91 bytes)
    r.push(1); // content_kind = DIRECT
    r.push(1); // compression_algo_id = DEFLATE
    r.extend_from_slice(&[0xEE; 16]); // content_uid
    r.extend_from_slice(&42u64.to_le_bytes()); // full_size
    r.push(16); // full_hash_algo_id = SHA-256
    let mut hash = [0u8; 64];
    hash[..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    r.extend_from_slice(&hash); // full_hash
    r
}

/// Build a PFS_SESSION record (first session, no members) with a writer string.
pub fn pfs_session(writer: &str) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(b"PFSS"); // magic
    r.push(1); // profile_version_major
    r.push(0); // profile_version_minor
    r.extend_from_slice(&0u16.to_le_bytes()); // reserved
    r.extend_from_slice(&1u64.to_le_bytes()); // session_seq
    r.extend_from_slice(&1700000000000u64.to_le_bytes()); // timestamp_unix_ms
    r.push(0); // prev_session_hash_algo_id (first session)
    r.extend_from_slice(&[0u8; 64]); // prev_session_hash
    r.extend_from_slice(&1u32.to_le_bytes()); // block_count = 1
    r.push(0); // member_digest_algo_id
    r.extend_from_slice(&[0u8; 64]); // member_blocks_digest
    r.extend_from_slice(&3u16.to_le_bytes()); // change_count
    r.extend_from_slice(&(writer.len() as u16).to_le_bytes()); // writer_len
    r.extend_from_slice(writer.as_bytes()); // writer
    r
}
