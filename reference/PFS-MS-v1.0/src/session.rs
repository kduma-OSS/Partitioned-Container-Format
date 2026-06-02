//! The Session Record stored as the data of the single `PFS_SESSION` partition
//! in a session's HEAD block (Section 8, Appendix A).

use pcf::HashAlgo;

use crate::consts::*;
use crate::error::{Error, Result};

/// A parsed Session Record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// Profile major version of the writer that produced this session.
    pub profile_version_major: u8,
    /// Profile minor version of the writer that produced this session.
    pub profile_version_minor: u8,
    /// 1-based, strictly increasing session number.
    pub session_seq: u64,
    /// Optional commit timestamp (0 = unspecified).
    pub timestamp_unix_ms: u64,
    /// Algorithm of `prev_session_hash` (0 for the first session).
    pub prev_session_hash_algo: HashAlgo,
    /// Previous session HEAD block's table_hash (zero for the first session).
    pub prev_session_hash: [u8; HASH_FIELD_SIZE],
    /// Number of Table Blocks in this session (>= 1).
    pub block_count: u32,
    /// Algorithm of `member_blocks_digest` (0 when block_count == 1).
    pub member_digest_algo: HashAlgo,
    /// Digest over this session's MEMBER block table_hashes (zero if none).
    pub member_blocks_digest: [u8; HASH_FIELD_SIZE],
    /// Number of PFS_NODE records in this session (informational).
    pub change_count: u16,
    /// Optional free-form writer identifier (UTF-8).
    pub writer: Vec<u8>,
}

fn rd_u16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn rd_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn rd_u64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[0..8].try_into().unwrap())
}

impl SessionRecord {
    /// Serialise to the on-disk layout (length `162 + writer_len`).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(SESSION_PREFIX_LEN + self.writer.len());
        b.extend_from_slice(&SESSION_MAGIC);
        b.push(self.profile_version_major);
        b.push(self.profile_version_minor);
        b.extend_from_slice(&0u16.to_le_bytes()); // reserved
        b.extend_from_slice(&self.session_seq.to_le_bytes());
        b.extend_from_slice(&self.timestamp_unix_ms.to_le_bytes());
        b.push(self.prev_session_hash_algo.id());
        b.extend_from_slice(&self.prev_session_hash);
        b.extend_from_slice(&self.block_count.to_le_bytes());
        b.push(self.member_digest_algo.id());
        b.extend_from_slice(&self.member_blocks_digest);
        b.extend_from_slice(&self.change_count.to_le_bytes());
        b.extend_from_slice(&(self.writer.len() as u16).to_le_bytes());
        b.extend_from_slice(&self.writer);
        debug_assert_eq!(b.len(), SESSION_PREFIX_LEN + self.writer.len());
        b
    }

    /// Parse and validate a Session Record (spec R3).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < SESSION_PREFIX_LEN {
            return Err(Error::MalformedSession("record shorter than fixed prefix"));
        }
        if b[0..4] != SESSION_MAGIC {
            return Err(Error::MalformedSession("bad record_magic"));
        }
        let profile_version_major = b[4];
        if profile_version_major != PROFILE_VERSION_MAJOR {
            return Err(Error::MalformedSession("unsupported profile major version"));
        }
        let profile_version_minor = b[5];
        let session_seq = rd_u64(&b[8..16]);
        let timestamp_unix_ms = rd_u64(&b[16..24]);
        let prev_session_hash_algo = HashAlgo::from_id(b[24])?;
        let mut prev_session_hash = [0u8; HASH_FIELD_SIZE];
        prev_session_hash.copy_from_slice(&b[25..89]);
        let block_count = rd_u32(&b[89..93]);
        if block_count < 1 {
            return Err(Error::MalformedSession("block_count must be >= 1"));
        }
        let member_digest_algo = HashAlgo::from_id(b[93])?;
        let mut member_blocks_digest = [0u8; HASH_FIELD_SIZE];
        member_blocks_digest.copy_from_slice(&b[94..158]);
        let change_count = rd_u16(&b[158..160]);
        let writer_len = rd_u16(&b[160..162]) as usize;
        if b.len() != SESSION_PREFIX_LEN + writer_len {
            return Err(Error::MalformedSession(
                "writer_len does not match record length",
            ));
        }
        let writer = b[162..162 + writer_len].to_vec();

        Ok(SessionRecord {
            profile_version_major,
            profile_version_minor,
            session_seq,
            timestamp_unix_ms,
            prev_session_hash_algo,
            prev_session_hash,
            block_count,
            member_digest_algo,
            member_blocks_digest,
            change_count,
            writer,
        })
    }
}

/// Compute `member_blocks_digest = H(member[0].table_hash || member[1] || ...)`
/// over the stored 64-byte table_hash fields in chain-traversal order
/// (Section 8.2). With no member blocks the digest is 64 zero bytes under
/// algorithm `None`.
pub fn member_blocks_digest(
    algo: HashAlgo,
    member_table_hashes: &[[u8; HASH_FIELD_SIZE]],
) -> [u8; HASH_FIELD_SIZE] {
    if member_table_hashes.is_empty() {
        return [0u8; HASH_FIELD_SIZE];
    }
    let mut image = Vec::with_capacity(member_table_hashes.len() * HASH_FIELD_SIZE);
    for h in member_table_hashes {
        image.extend_from_slice(h);
    }
    algo.compute(&image)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_roundtrip_no_members() {
        let r = SessionRecord {
            profile_version_major: PROFILE_VERSION_MAJOR,
            profile_version_minor: PROFILE_VERSION_MINOR,
            session_seq: 1,
            timestamp_unix_ms: 0,
            prev_session_hash_algo: HashAlgo::None,
            prev_session_hash: [0u8; HASH_FIELD_SIZE],
            block_count: 1,
            member_digest_algo: HashAlgo::None,
            member_blocks_digest: [0u8; HASH_FIELD_SIZE],
            change_count: 3,
            writer: b"pfs-ref".to_vec(),
        };
        let bytes = r.to_bytes();
        assert_eq!(bytes.len(), SESSION_PREFIX_LEN + 7);
        assert_eq!(SessionRecord::from_bytes(&bytes).unwrap(), r);
    }

    #[test]
    fn session_roundtrip_with_members() {
        let m0 = HashAlgo::Sha256.compute(b"m0");
        let m1 = HashAlgo::Sha256.compute(b"m1");
        let digest = member_blocks_digest(HashAlgo::Sha256, &[m0, m1]);
        let r = SessionRecord {
            profile_version_major: PROFILE_VERSION_MAJOR,
            profile_version_minor: PROFILE_VERSION_MINOR,
            session_seq: 42,
            timestamp_unix_ms: 7,
            prev_session_hash_algo: HashAlgo::Sha256,
            prev_session_hash: HashAlgo::Sha256.compute(b"prev"),
            block_count: 3,
            member_digest_algo: HashAlgo::Sha256,
            member_blocks_digest: digest,
            change_count: 600,
            writer: Vec::new(),
        };
        assert_eq!(SessionRecord::from_bytes(&r.to_bytes()).unwrap(), r);
    }

    #[test]
    fn rejects_bad_magic_and_length() {
        let mut bytes = SessionRecord {
            profile_version_major: PROFILE_VERSION_MAJOR,
            profile_version_minor: PROFILE_VERSION_MINOR,
            session_seq: 1,
            timestamp_unix_ms: 0,
            prev_session_hash_algo: HashAlgo::None,
            prev_session_hash: [0u8; HASH_FIELD_SIZE],
            block_count: 1,
            member_digest_algo: HashAlgo::None,
            member_blocks_digest: [0u8; HASH_FIELD_SIZE],
            change_count: 0,
            writer: Vec::new(),
        }
        .to_bytes();
        let good = bytes.clone();
        bytes[0] = 0;
        assert!(SessionRecord::from_bytes(&bytes).is_err());
        // Truncated writer region.
        assert!(SessionRecord::from_bytes(&good[..good.len() - 1]).is_err());
    }
}
