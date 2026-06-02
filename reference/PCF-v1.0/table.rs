//! The 74-byte table-block header and table-block hashing (spec section 5.1,
//! 8.4).

use crate::consts::HASH_FIELD_SIZE;
use crate::entry::PartitionEntry;
use crate::error::Error;
use crate::hash::HashAlgo;

/// Parsed table-block header (the entries follow it on disk).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableBlockHeader {
    /// Number of entries stored in this block (0..=255).
    pub partition_count: u8,
    /// Absolute offset of the next block, or 0 for end-of-chain.
    pub next_table_offset: u64,
    /// Algorithm used for `table_hash`.
    pub table_hash_algo: HashAlgo,
    /// 64-byte table hash field.
    pub table_hash: [u8; HASH_FIELD_SIZE],
}

impl TableBlockHeader {
    /// Serialise to the on-disk 74-byte layout.
    pub fn to_bytes(&self) -> [u8; 74] {
        let mut b = [0u8; 74];
        b[0] = self.partition_count;
        b[1..9].copy_from_slice(&self.next_table_offset.to_le_bytes());
        b[9] = self.table_hash_algo.id();
        b[10..74].copy_from_slice(&self.table_hash);
        b
    }

    /// Parse from the on-disk 74-byte layout.
    pub fn from_bytes(b: &[u8; 74]) -> Result<Self, Error> {
        let partition_count = b[0];
        let next_table_offset = u64::from_le_bytes(b[1..9].try_into().unwrap());
        let table_hash_algo = HashAlgo::from_id(b[9])?;
        let mut table_hash = [0u8; HASH_FIELD_SIZE];
        table_hash.copy_from_slice(&b[10..74]);
        Ok(TableBlockHeader {
            partition_count,
            next_table_offset,
            table_hash_algo,
            table_hash,
        })
    }
}

/// Compute the table hash over `[header-with-zeroed-hash || entries]`
/// (spec section 8.4). The `table_hash_algo` byte is included; the 64-byte
/// hash field is treated as zero; trailing reserved space is excluded.
pub fn compute_table_hash(
    algo: HashAlgo,
    next_table_offset: u64,
    entries: &[PartitionEntry],
) -> [u8; HASH_FIELD_SIZE] {
    let header = TableBlockHeader {
        partition_count: entries.len() as u8,
        next_table_offset,
        table_hash_algo: algo,
        table_hash: [0u8; HASH_FIELD_SIZE], // zeroed for the computation
    };
    let mut image = Vec::with_capacity(74 + entries.len() * 141);
    image.extend_from_slice(&header.to_bytes());
    for e in entries {
        image.extend_from_slice(&e.to_bytes());
    }
    algo.compute(&image)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = TableBlockHeader {
            partition_count: 3,
            next_table_offset: 4096,
            table_hash_algo: HashAlgo::Sha256,
            table_hash: HashAlgo::Sha256.compute(b"abc"),
        };
        assert_eq!(TableBlockHeader::from_bytes(&h.to_bytes()).unwrap(), h);
    }

    #[test]
    fn empty_block_hash_is_stable() {
        let a = compute_table_hash(HashAlgo::Sha256, 0, &[]);
        let b = compute_table_hash(HashAlgo::Sha256, 0, &[]);
        assert_eq!(a, b);
    }
}
