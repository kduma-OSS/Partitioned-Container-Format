//! The canonical PCF-DCP v1.0 test vector (spec Section 17).

use pcf::HashAlgo;

use crate::arena::{Arena, Chunker};
use crate::error::Result;
use crate::writer::DcpWriter;

/// Build the byte-exact 700-byte reference file from spec Section 17.
///
/// The file is one DCP container ("dcp", uid 16×0xDC, unsealed) holding two
/// inner partitions:
///
/// * **A** ("Hello, World!", 13 B) stored as two extents — `"Hello, "` (7 B,
///   private) and `"World!"` (6 B, shared) — via fixed-7 chunking.
/// * **B** ("World!", 6 B) stored as one extent that *deduplicates* onto A's
///   second extent; both references carry SHARED = 1.
///
/// Building the same logical container and emitting the canonical layout MUST
/// reproduce these exact bytes.
pub fn build_reference_vector() -> Result<Vec<u8>> {
    let mut arena = Arena::new();
    arena.add_inner(
        0x0000_0010,
        [0xA1u8; 16],
        "A",
        b"Hello, World!",
        HashAlgo::Sha256,
        Chunker::Fixed(7),
    )?;
    arena.add_inner(
        0x0000_0010,
        [0xB2u8; 16],
        "B",
        b"World!",
        HashAlgo::Sha256,
        Chunker::Whole,
    )?;

    let mut w = DcpWriter::new();
    w.add_container([0xDCu8; 16], "dcp", arena)?;
    w.to_image()
}
