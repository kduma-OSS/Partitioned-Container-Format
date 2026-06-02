//! Content compression (Section 9.4). DEFLATE (RFC 1951, `compression_algo_id =
//! 1`) is the required default and is implemented via the pure-Rust
//! `flate2`/`miniz_oxide` backend.
//!
//! Only the bytes stored in a RAW content partition are compressed: the DIRECT
//! full content, or the DELTA patch. The PCF `data_hash` protects the stored
//! (compressed) bytes; the Node Record's `full_hash`/`full_size` protect the
//! reconstructed (decompressed) content.

use std::io::{Read, Write};

use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;

use crate::consts::{COMPRESS_DEFLATE, COMPRESS_NONE};
use crate::error::{Error, Result};

/// DEFLATE-compress `data`. A fixed compression level keeps the output
/// deterministic so byte-exact test vectors are reproducible.
pub fn compress_deflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::new(6));
    enc.write_all(data)
        .map_err(|e| Error::Compression(format!("deflate: {e}")))?;
    enc.finish()
        .map_err(|e| Error::Compression(format!("deflate finish: {e}")))
}

/// Decompress `data` according to `compression_algo_id`.
///
/// An unimplemented id yields [`Error::UnsupportedCompressionAlgo`] so the
/// caller can report the affected file as unreadable without treating the
/// container as malformed (Section 9.4).
pub fn decompress(compression_algo_id: u8, data: &[u8]) -> Result<Vec<u8>> {
    match compression_algo_id {
        COMPRESS_NONE => Ok(data.to_vec()),
        COMPRESS_DEFLATE => {
            let mut out = Vec::new();
            DeflateDecoder::new(data)
                .read_to_end(&mut out)
                .map_err(|e| Error::Compression(format!("inflate: {e}")))?;
            Ok(out)
        }
        other => Err(Error::UnsupportedCompressionAlgo(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deflate_roundtrips() {
        let data = b"the quick brown fox".repeat(50);
        let packed = compress_deflate(&data).unwrap();
        assert!(packed.len() < data.len(), "repetitive input should shrink");
        assert_eq!(decompress(COMPRESS_DEFLATE, &packed).unwrap(), data);
    }

    #[test]
    fn none_is_verbatim() {
        assert_eq!(decompress(COMPRESS_NONE, b"abc").unwrap(), b"abc");
    }

    #[test]
    fn unknown_algo_is_reported() {
        assert!(matches!(
            decompress(2, b"x"),
            Err(Error::UnsupportedCompressionAlgo(2))
        ));
    }
}
