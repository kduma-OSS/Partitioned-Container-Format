//! The Node Record stored as the data of a `PFS_NODE` partition (Section 7).
//!
//! A record is a fixed 54-byte prefix, a variable-length UTF-8 name, and — for
//! live files only — a content section (Section 7.3). The byte layout mirrors
//! Appendix A exactly.

use pcf::HashAlgo;

use crate::consts::*;
use crate::error::{Error, Result};

/// The content section of a live file's Node Record (Section 7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentSection {
    /// `content_kind = 0`: the empty byte string.
    Empty,
    /// `content_kind = 1`: full bytes in one RAW partition.
    Direct {
        /// PCF uid of the RAW partition holding the full content.
        content_uid: [u8; 16],
        /// Length of the content.
        full_size: u64,
        /// Hash algorithm of `full_hash`.
        full_hash_algo: HashAlgo,
        /// Hash of the full content.
        full_hash: [u8; HASH_FIELD_SIZE],
    },
    /// `content_kind = 2`: a patch against the previous content-bearing version.
    Delta {
        /// Patch algorithm (1 = VCDIFF).
        patch_algo: u8,
        /// PCF uid of the RAW partition holding the patch.
        patch_uid: [u8; 16],
        /// Length of the reconstructed content.
        full_size: u64,
        /// Hash algorithm of `full_hash`.
        full_hash_algo: HashAlgo,
        /// Hash of the reconstructed content.
        full_hash: [u8; HASH_FIELD_SIZE],
        /// Length of the base (previous version).
        base_full_size: u64,
        /// Hash algorithm of `base_full_hash`.
        base_full_hash_algo: HashAlgo,
        /// Hash of the base.
        base_full_hash: [u8; HASH_FIELD_SIZE],
    },
    /// `content_kind = 3`: identical bytes to the previous version.
    Inherit,
}

/// A parsed Node Record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecord {
    /// `1` = file, `2` = directory.
    pub kind: u8,
    /// Node flags (bit 0 = TOMBSTONE).
    pub flags: u16,
    /// Stable 16-byte node identity (all-zero only for the root).
    pub node_id: [u8; 16],
    /// node_id of the containing directory (equals node_id for the root).
    pub parent_id: [u8; 16],
    /// Optional modification time (0 = unspecified).
    pub mtime_unix_ms: u64,
    /// Optional POSIX permission bits (0 = unset).
    pub mode: u32,
    /// The node's UTF-8 name within its parent (empty for the root).
    pub name: Vec<u8>,
    /// Content section, present iff `kind == file` and not tombstoned.
    pub content: Option<ContentSection>,
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

impl NodeRecord {
    /// True if the TOMBSTONE flag is set.
    pub fn is_tombstone(&self) -> bool {
        self.flags & FLAG_TOMBSTONE != 0
    }
    /// True if this record describes a file.
    pub fn is_file(&self) -> bool {
        self.kind == KIND_FILE
    }
    /// True if this record describes a directory.
    pub fn is_dir(&self) -> bool {
        self.kind == KIND_DIR
    }
    /// The name as a UTF-8 string (lossless; names are validated on parse).
    pub fn name_str(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }

    /// Validate a name per Section 7.2 (no NUL or '/', not "." or "..").
    fn validate_name(name: &[u8]) -> Result<()> {
        if name.len() > PFS_MAX_NAME {
            return Err(Error::MalformedNode("name_len out of range"));
        }
        if name.contains(&0x00) || name.contains(&b'/') {
            return Err(Error::MalformedNode("name contains NUL or '/'"));
        }
        if name == b"." || name == b".." {
            return Err(Error::MalformedNode("name is '.' or '..'"));
        }
        Ok(())
    }

    /// Serialise to the on-disk Node Record layout (Section 7, Appendix A).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(NODE_PREFIX_LEN + self.name.len());
        b.extend_from_slice(&NODE_MAGIC);
        b.push(NODE_RECORD_VERSION);
        b.push(self.kind);
        b.extend_from_slice(&self.flags.to_le_bytes());
        b.extend_from_slice(&self.node_id);
        b.extend_from_slice(&self.parent_id);
        b.extend_from_slice(&self.mtime_unix_ms.to_le_bytes());
        b.extend_from_slice(&self.mode.to_le_bytes());
        b.extend_from_slice(&(self.name.len() as u16).to_le_bytes());
        b.extend_from_slice(&self.name);
        debug_assert_eq!(b.len(), NODE_PREFIX_LEN + self.name.len());

        if let Some(c) = &self.content {
            match c {
                ContentSection::Empty => b.push(CONTENT_EMPTY),
                ContentSection::Inherit => b.push(CONTENT_INHERIT),
                ContentSection::Direct {
                    content_uid,
                    full_size,
                    full_hash_algo,
                    full_hash,
                } => {
                    b.push(CONTENT_DIRECT);
                    b.extend_from_slice(content_uid);
                    b.extend_from_slice(&full_size.to_le_bytes());
                    b.push(full_hash_algo.id());
                    b.extend_from_slice(full_hash);
                }
                ContentSection::Delta {
                    patch_algo,
                    patch_uid,
                    full_size,
                    full_hash_algo,
                    full_hash,
                    base_full_size,
                    base_full_hash_algo,
                    base_full_hash,
                } => {
                    b.push(CONTENT_DELTA);
                    b.push(*patch_algo);
                    b.extend_from_slice(patch_uid);
                    b.extend_from_slice(&full_size.to_le_bytes());
                    b.push(full_hash_algo.id());
                    b.extend_from_slice(full_hash);
                    b.extend_from_slice(&base_full_size.to_le_bytes());
                    b.push(base_full_hash_algo.id());
                    b.extend_from_slice(base_full_hash);
                }
            }
        }
        b
    }

    /// Parse and validate a Node Record from a partition's data (spec R4).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < NODE_PREFIX_LEN {
            return Err(Error::MalformedNode("record shorter than fixed prefix"));
        }
        if b[0..4] != NODE_MAGIC {
            return Err(Error::MalformedNode("bad record_magic"));
        }
        if b[4] != NODE_RECORD_VERSION {
            return Err(Error::MalformedNode("unsupported record_version"));
        }
        let kind = b[5];
        if kind != KIND_FILE && kind != KIND_DIR {
            return Err(Error::MalformedNode("unknown kind"));
        }
        let flags = rd_u16(&b[6..8]);
        if flags & !FLAG_DEFINED_MASK != 0 {
            return Err(Error::MalformedNode("reserved flag bit set"));
        }
        let mut node_id = [0u8; 16];
        node_id.copy_from_slice(&b[8..24]);
        let mut parent_id = [0u8; 16];
        parent_id.copy_from_slice(&b[24..40]);
        let mtime_unix_ms = rd_u64(&b[40..48]);
        let mode = rd_u32(&b[48..52]);
        let name_len = rd_u16(&b[52..54]) as usize;
        if name_len > PFS_MAX_NAME {
            return Err(Error::MalformedNode("name_len out of range"));
        }
        let name_end = NODE_PREFIX_LEN + name_len;
        if b.len() < name_end {
            return Err(Error::MalformedNode("record truncated within name"));
        }
        let name = b[NODE_PREFIX_LEN..name_end].to_vec();
        Self::validate_name(&name)?;

        let tombstone = flags & FLAG_TOMBSTONE != 0;
        let has_content = kind == KIND_FILE && !tombstone;
        let rest = &b[name_end..];

        let content = if has_content {
            Some(Self::parse_content(rest)?)
        } else {
            // Directories and tombstones end after the name.
            if !rest.is_empty() {
                return Err(Error::MalformedNode("unexpected trailing bytes"));
            }
            None
        };

        Ok(NodeRecord {
            kind,
            flags,
            node_id,
            parent_id,
            mtime_unix_ms,
            mode,
            name,
            content,
        })
    }

    fn parse_content(rest: &[u8]) -> Result<ContentSection> {
        if rest.is_empty() {
            return Err(Error::MalformedNode("missing content section"));
        }
        let kind = rest[0];
        match kind {
            CONTENT_EMPTY => {
                if rest.len() != 1 {
                    return Err(Error::MalformedNode("EMPTY section has trailing bytes"));
                }
                Ok(ContentSection::Empty)
            }
            CONTENT_INHERIT => {
                if rest.len() != 1 {
                    return Err(Error::MalformedNode("INHERIT section has trailing bytes"));
                }
                Ok(ContentSection::Inherit)
            }
            CONTENT_DIRECT => {
                if rest.len() != DIRECT_SECTION_LEN {
                    return Err(Error::MalformedNode("DIRECT section wrong length"));
                }
                let mut content_uid = [0u8; 16];
                content_uid.copy_from_slice(&rest[1..17]);
                let full_size = rd_u64(&rest[17..25]);
                let full_hash_algo = HashAlgo::from_id(rest[25])?;
                let mut full_hash = [0u8; HASH_FIELD_SIZE];
                full_hash.copy_from_slice(&rest[26..90]);
                Ok(ContentSection::Direct {
                    content_uid,
                    full_size,
                    full_hash_algo,
                    full_hash,
                })
            }
            CONTENT_DELTA => {
                if rest.len() != DELTA_SECTION_LEN {
                    return Err(Error::MalformedNode("DELTA section wrong length"));
                }
                let patch_algo = rest[1];
                let mut patch_uid = [0u8; 16];
                patch_uid.copy_from_slice(&rest[2..18]);
                let full_size = rd_u64(&rest[18..26]);
                let full_hash_algo = HashAlgo::from_id(rest[26])?;
                let mut full_hash = [0u8; HASH_FIELD_SIZE];
                full_hash.copy_from_slice(&rest[27..91]);
                let base_full_size = rd_u64(&rest[91..99]);
                let base_full_hash_algo = HashAlgo::from_id(rest[99])?;
                let mut base_full_hash = [0u8; HASH_FIELD_SIZE];
                base_full_hash.copy_from_slice(&rest[100..164]);
                Ok(ContentSection::Delta {
                    patch_algo,
                    patch_uid,
                    full_size,
                    full_hash_algo,
                    full_hash,
                    base_full_size,
                    base_full_hash_algo,
                    base_full_hash,
                })
            }
            _ => Err(Error::MalformedNode("unknown content_kind")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(algo: HashAlgo, data: &[u8]) -> [u8; HASH_FIELD_SIZE] {
        algo.compute(data)
    }

    #[test]
    fn dir_roundtrip() {
        let r = NodeRecord {
            kind: KIND_DIR,
            flags: 0,
            node_id: [7u8; 16],
            parent_id: ROOT_NODE_ID,
            mtime_unix_ms: 123,
            mode: 0o755,
            name: b"docs".to_vec(),
            content: None,
        };
        let bytes = r.to_bytes();
        assert_eq!(bytes.len(), NODE_PREFIX_LEN + 4);
        assert_eq!(NodeRecord::from_bytes(&bytes).unwrap(), r);
    }

    #[test]
    fn direct_file_roundtrip() {
        let r = NodeRecord {
            kind: KIND_FILE,
            flags: 0,
            node_id: [9u8; 16],
            parent_id: [7u8; 16],
            mtime_unix_ms: 0,
            mode: 0,
            name: b"hello.txt".to_vec(),
            content: Some(ContentSection::Direct {
                content_uid: [3u8; 16],
                full_size: 6,
                full_hash_algo: HashAlgo::Sha256,
                full_hash: h(HashAlgo::Sha256, b"Hello\n"),
            }),
        };
        let bytes = r.to_bytes();
        assert_eq!(bytes.len(), NODE_PREFIX_LEN + 9 + DIRECT_SECTION_LEN);
        assert_eq!(NodeRecord::from_bytes(&bytes).unwrap(), r);
    }

    #[test]
    fn delta_file_roundtrip() {
        let r = NodeRecord {
            kind: KIND_FILE,
            flags: 0,
            node_id: [9u8; 16],
            parent_id: [7u8; 16],
            mtime_unix_ms: 0,
            mode: 0,
            name: b"hello.txt".to_vec(),
            content: Some(ContentSection::Delta {
                patch_algo: PATCH_VCDIFF,
                patch_uid: [4u8; 16],
                full_size: 13,
                full_hash_algo: HashAlgo::Sha256,
                full_hash: h(HashAlgo::Sha256, b"Hello, world\n"),
                base_full_size: 6,
                base_full_hash_algo: HashAlgo::Sha256,
                base_full_hash: h(HashAlgo::Sha256, b"Hello\n"),
            }),
        };
        let bytes = r.to_bytes();
        assert_eq!(bytes.len(), NODE_PREFIX_LEN + 9 + DELTA_SECTION_LEN);
        assert_eq!(NodeRecord::from_bytes(&bytes).unwrap(), r);
    }

    #[test]
    fn tombstone_has_no_content() {
        let r = NodeRecord {
            kind: KIND_FILE,
            flags: FLAG_TOMBSTONE,
            node_id: [9u8; 16],
            parent_id: [7u8; 16],
            mtime_unix_ms: 0,
            mode: 0,
            name: b"gone.txt".to_vec(),
            content: None,
        };
        let bytes = r.to_bytes();
        let back = NodeRecord::from_bytes(&bytes).unwrap();
        assert!(back.is_tombstone());
        assert!(back.content.is_none());
    }

    #[test]
    fn rejects_bad_name_and_flags() {
        let base = NodeRecord {
            kind: KIND_DIR,
            flags: 0,
            node_id: [1u8; 16],
            parent_id: ROOT_NODE_ID,
            mtime_unix_ms: 0,
            mode: 0,
            name: b"ok".to_vec(),
            content: None,
        };
        let mut slash = base.clone();
        slash.name = b"a/b".to_vec();
        assert!(NodeRecord::from_bytes(&slash.to_bytes()).is_err());

        let mut dotdot = base.clone();
        dotdot.name = b"..".to_vec();
        assert!(NodeRecord::from_bytes(&dotdot.to_bytes()).is_err());

        // A reserved flag bit must be rejected on parse.
        let mut bytes = base.to_bytes();
        bytes[6] = 0x02; // set a reserved flag bit
        assert!(matches!(
            NodeRecord::from_bytes(&bytes),
            Err(Error::MalformedNode(_))
        ));
    }
}
