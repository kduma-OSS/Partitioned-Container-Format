//! Delta encoding (Section 9.2). VCDIFF (RFC 3284, `patch_algo_id = 1`) is the
//! required default and is implemented via the pure-Rust `oxidelta` crate.

use oxidelta::compress::{decoder, encoder};

use crate::consts::PATCH_VCDIFF;
use crate::error::{Error, Result};

/// Produce a VCDIFF patch transforming `base` into `target`.
pub fn diff_vcdiff(base: &[u8], target: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encoder::encode_all(&mut out, base, target, encoder::CompressOptions::default())
        .map_err(|e| Error::Vcdiff(format!("encode: {e}")))?;
    Ok(out)
}

/// Apply a patch of algorithm `patch_algo` to `base`, returning the result.
///
/// An unimplemented `patch_algo` yields [`Error::UnsupportedPatchAlgo`] so the
/// caller can report the affected file as unreadable without treating the
/// container as malformed (Section 9.2).
pub fn apply(patch_algo: u8, base: &[u8], patch: &[u8]) -> Result<Vec<u8>> {
    match patch_algo {
        PATCH_VCDIFF => {
            decoder::decode_all(base, patch).map_err(|e| Error::Vcdiff(format!("decode: {e}")))
        }
        other => Err(Error::UnsupportedPatchAlgo(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcdiff_roundtrips() {
        let base = b"Hello\n";
        let target = b"Hello, world\n";
        let patch = diff_vcdiff(base, target).unwrap();
        assert_eq!(apply(PATCH_VCDIFF, base, &patch).unwrap(), target);
    }

    #[test]
    fn unknown_algo_is_reported() {
        assert!(matches!(
            apply(2, b"a", b"b"),
            Err(Error::UnsupportedPatchAlgo(2))
        ));
    }
}
