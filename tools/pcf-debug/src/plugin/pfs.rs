//! Decoders for PFS-MS records (see `specs/PFS-MS-spec-v1.0.txt`):
//! `PFS_NODE` (partition type `0xAAAA0001`, magic `"PFSN"`) and `PFS_SESSION`
//! (partition type `0xAAAA0002`, magic `"PFSS"`).
//!
//! Both decoders mirror the spec's byte tables field-for-field and report spec
//! violations as warnings rather than failing.

use pcf::HashAlgo;

use super::{
    le_u16, le_u32, le_u64, uid_at, Decoded, FieldNode, FieldValue, PartitionDecoder, PartitionMeta,
};

const PFS_NODE_TYPE: u32 = 0xAAAA_0001;
const PFS_SESSION_TYPE: u32 = 0xAAAA_0002;
const NODE_MAGIC: &[u8; 4] = b"PFSN";
const SESSION_MAGIC: &[u8; 4] = b"PFSS";
const PFS_MAX_NAME: u16 = 1024;

/// Render a `<algo_id><64-byte hash>` pair as a labelled field, truncated to the
/// algorithm's significant digest length.
fn hash_pair(
    label: &str,
    data: &[u8],
    algo_off: usize,
    hash_off: usize,
    warnings: &mut Vec<String>,
) -> FieldNode {
    let mut node = FieldNode::group(label);
    let algo_id = data.get(algo_off).copied().unwrap_or(0);
    let (algo_name, digest_len) = match HashAlgo::from_id(algo_id) {
        Ok(a) => (crate::model::algo_name(a), a.digest_len()),
        Err(_) => {
            warnings.push(format!("{label}: unknown hash algorithm id {algo_id}"));
            ("unknown", 0)
        }
    };
    node.push(FieldNode::leaf(
        "algo_id",
        FieldValue::Enum {
            raw: algo_id as u64,
            name: algo_name.into(),
        },
        (algo_off as u64, algo_off as u64 + 1),
    ));
    if let Some(bytes) = data.get(hash_off..hash_off + 64) {
        let sig = &bytes[..digest_len.min(64)];
        node.push(FieldNode::leaf(
            "hash",
            FieldValue::Bytes(sig.to_vec()),
            (hash_off as u64, hash_off as u64 + 64),
        ));
    } else {
        warnings.push(format!("{label}: hash field runs past end of record"));
    }
    node
}

/// Render a `compression_algo_id` byte as a labelled enum field (Section 9.5).
fn compression_field(data: &[u8], off: usize) -> FieldNode {
    let id = data.get(off).copied().unwrap_or(0);
    let name = match id {
        0 => "none",
        1 => "DEFLATE",
        2 => "zstd",
        3 => "brotli",
        _ => "reserved",
    };
    FieldNode::leaf(
        "compression_algo_id",
        FieldValue::Enum {
            raw: id as u64,
            name: name.into(),
        },
        (off as u64, off as u64 + 1),
    )
}

// ---------------------------------------------------------------------------
// PFS_NODE
// ---------------------------------------------------------------------------

pub struct PfsNodeDecoder;

impl PartitionDecoder for PfsNodeDecoder {
    fn name(&self) -> &'static str {
        "pfs-node"
    }

    fn matches(&self, meta: &PartitionMeta, data: &[u8]) -> bool {
        meta.partition_type == PFS_NODE_TYPE || data.get(0..4) == Some(NODE_MAGIC)
    }

    fn decode(&self, _meta: &PartitionMeta, data: &[u8]) -> Decoded {
        let mut warnings = Vec::new();
        let mut fields = Vec::new();

        if data.len() < 54 {
            warnings.push(format!(
                "record is {} bytes; PFS_NODE needs at least a 54-byte prefix",
                data.len()
            ));
        }

        // ---- fixed prefix (54 bytes) ------------------------------------
        let mut prefix = FieldNode::group("fixed prefix");

        let magic_ok = data.get(0..4) == Some(NODE_MAGIC);
        if !magic_ok {
            warnings.push("record_magic is not \"PFSN\"".into());
        }
        prefix.push(
            FieldNode::leaf(
                "record_magic",
                FieldValue::Text(ascii_or_hex(data.get(0..4).unwrap_or(&[]))),
                (0, 4),
            )
            .with_note(if magic_ok {
                "magic OK"
            } else {
                "expected \"PFSN\""
            }),
        );

        let version = data.get(4).copied().unwrap_or(0);
        prefix.push(FieldNode::leaf(
            "record_version",
            FieldValue::U64(version as u64),
            (4, 5),
        ));

        let kind = data.get(5).copied().unwrap_or(0);
        let kind_name = match kind {
            1 => "file",
            2 => "directory",
            _ => {
                warnings.push(format!(
                    "kind {kind} is reserved (valid: 1=file, 2=directory)"
                ));
                "reserved"
            }
        };
        prefix.push(FieldNode::leaf(
            "kind",
            FieldValue::Enum {
                raw: kind as u64,
                name: kind_name.into(),
            },
            (5, 6),
        ));

        let flags = le_u16(data, 6).unwrap_or(0);
        let tombstone = flags & 0x0001 != 0;
        let mut set = Vec::new();
        if tombstone {
            set.push("TOMBSTONE".to_string());
        }
        if flags & !0x0001 != 0 {
            warnings.push(format!("flags {flags:#06x} sets reserved bits (must be 0)"));
        }
        prefix.push(FieldNode::leaf(
            "flags",
            FieldValue::Flags {
                raw: flags as u64,
                set,
            },
            (6, 8),
        ));

        if let Some(node_id) = uid_at(data, 8) {
            prefix.push(FieldNode::leaf(
                "node_id",
                FieldValue::Uid(node_id),
                (8, 24),
            ));
        }
        if let Some(parent_id) = uid_at(data, 24) {
            prefix.push(FieldNode::leaf(
                "parent_id",
                FieldValue::Uid(parent_id),
                (24, 40),
            ));
        }
        let mtime = le_u64(data, 40).unwrap_or(0);
        prefix.push(FieldNode::leaf(
            "mtime_unix_ms",
            FieldValue::U64(mtime),
            (40, 48),
        ));
        let mode = le_u32(data, 48).unwrap_or(0);
        prefix.push(
            FieldNode::leaf("mode", FieldValue::U64(mode as u64), (48, 52))
                .with_note(format!("{mode:#o}")),
        );
        let name_len = le_u16(data, 52).unwrap_or(0);
        if name_len > PFS_MAX_NAME {
            warnings.push(format!(
                "name_len {name_len} exceeds PFS_MAX_NAME ({PFS_MAX_NAME})"
            ));
        }
        prefix.push(FieldNode::leaf(
            "name_len",
            FieldValue::U64(name_len as u64),
            (52, 54),
        ));
        fields.push(prefix);

        // ---- name --------------------------------------------------------
        let name_end = 54usize + name_len as usize;
        let name_bytes = data.get(54..name_end).unwrap_or(&[]);
        if name_bytes.len() != name_len as usize {
            warnings.push("name runs past end of record".into());
        }
        if name_bytes.contains(&0x00) || name_bytes.contains(&b'/') {
            warnings.push("name must not contain NUL or '/'".into());
        }
        let name = String::from_utf8_lossy(name_bytes).into_owned();
        fields.push(FieldNode::leaf(
            "name",
            FieldValue::Text(name),
            (54, name_end as u64),
        ));

        // ---- content section (files only, when not tombstoned) ----------
        if kind == 1 && !tombstone {
            fields.push(decode_content(data, name_end, &mut warnings));
        }

        Decoded {
            format_name: "PFS_NODE".into(),
            fields,
            warnings,
        }
    }
}

fn decode_content(data: &[u8], s: usize, warnings: &mut Vec<String>) -> FieldNode {
    let mut content = FieldNode::group("content");
    let content_kind = data.get(s).copied().unwrap_or(0xff);
    let ck_name = match content_kind {
        0 => "EMPTY",
        1 => "DIRECT",
        2 => "DELTA",
        3 => "INHERIT",
        _ => {
            warnings.push(format!("content_kind {content_kind} is unknown"));
            "unknown"
        }
    };
    content.push(FieldNode::leaf(
        "content_kind",
        FieldValue::Enum {
            raw: content_kind as u64,
            name: ck_name.into(),
        },
        (s as u64, s as u64 + 1),
    ));

    match content_kind {
        0 | 3 => {} // EMPTY / INHERIT: no further bytes.
        1 => {
            // DIRECT, 91 bytes total (Section 7.3).
            content.push(compression_field(data, s + 1));
            if let Some(uid) = uid_at(data, s + 2) {
                content.push(FieldNode::leaf(
                    "content_uid",
                    FieldValue::Uid(uid),
                    (s as u64 + 2, s as u64 + 18),
                ));
            }
            let full_size = le_u64(data, s + 18).unwrap_or(0);
            content.push(FieldNode::leaf(
                "full_size",
                FieldValue::U64(full_size),
                (s as u64 + 18, s as u64 + 26),
            ));
            content.push(hash_pair("full_hash", data, s + 26, s + 27, warnings));
            check_trailing(data, s + 91, warnings);
        }
        2 => {
            // DELTA, 165 bytes total (Section 7.3).
            let patch_algo = data.get(s + 1).copied().unwrap_or(0);
            let patch_name = if patch_algo == 1 {
                "VCDIFF"
            } else {
                "reserved"
            };
            content.push(FieldNode::leaf(
                "patch_algo_id",
                FieldValue::Enum {
                    raw: patch_algo as u64,
                    name: patch_name.into(),
                },
                (s as u64 + 1, s as u64 + 2),
            ));
            content.push(compression_field(data, s + 2));
            if let Some(uid) = uid_at(data, s + 3) {
                content.push(FieldNode::leaf(
                    "patch_uid",
                    FieldValue::Uid(uid),
                    (s as u64 + 3, s as u64 + 19),
                ));
            }
            let full_size = le_u64(data, s + 19).unwrap_or(0);
            content.push(FieldNode::leaf(
                "full_size",
                FieldValue::U64(full_size),
                (s as u64 + 19, s as u64 + 27),
            ));
            content.push(hash_pair("full_hash", data, s + 27, s + 28, warnings));
            let base_size = le_u64(data, s + 92).unwrap_or(0);
            content.push(FieldNode::leaf(
                "base_full_size",
                FieldValue::U64(base_size),
                (s as u64 + 92, s as u64 + 100),
            ));
            content.push(hash_pair(
                "base_full_hash",
                data,
                s + 100,
                s + 101,
                warnings,
            ));
            check_trailing(data, s + 165, warnings);
        }
        _ => {}
    }
    content
}

fn check_trailing(data: &[u8], end: usize, warnings: &mut Vec<String>) {
    if data.len() > end {
        warnings.push(format!(
            "{} trailing byte(s) after record",
            data.len() - end
        ));
    }
}

// ---------------------------------------------------------------------------
// PFS_SESSION
// ---------------------------------------------------------------------------

pub struct PfsSessionDecoder;

impl PartitionDecoder for PfsSessionDecoder {
    fn name(&self) -> &'static str {
        "pfs-session"
    }

    fn matches(&self, meta: &PartitionMeta, data: &[u8]) -> bool {
        meta.partition_type == PFS_SESSION_TYPE || data.get(0..4) == Some(SESSION_MAGIC)
    }

    fn decode(&self, _meta: &PartitionMeta, data: &[u8]) -> Decoded {
        let mut warnings = Vec::new();
        let mut fields = Vec::new();

        if data.len() < 162 {
            warnings.push(format!(
                "record is {} bytes; PFS_SESSION needs at least 162",
                data.len()
            ));
        }

        let magic_ok = data.get(0..4) == Some(SESSION_MAGIC);
        if !magic_ok {
            warnings.push("record_magic is not \"PFSS\"".into());
        }
        fields.push(
            FieldNode::leaf(
                "record_magic",
                FieldValue::Text(ascii_or_hex(data.get(0..4).unwrap_or(&[]))),
                (0, 4),
            )
            .with_note(if magic_ok {
                "magic OK"
            } else {
                "expected \"PFSS\""
            }),
        );

        fields.push(FieldNode::leaf(
            "profile_version_major",
            FieldValue::U64(data.get(4).copied().unwrap_or(0) as u64),
            (4, 5),
        ));
        fields.push(FieldNode::leaf(
            "profile_version_minor",
            FieldValue::U64(data.get(5).copied().unwrap_or(0) as u64),
            (5, 6),
        ));

        let reserved = le_u16(data, 6).unwrap_or(0);
        if reserved != 0 {
            warnings.push(format!("reserved field is {reserved:#06x} (must be 0)"));
        }
        fields.push(FieldNode::leaf(
            "reserved",
            FieldValue::U64(reserved as u64),
            (6, 8),
        ));

        let session_seq = le_u64(data, 8).unwrap_or(0);
        fields.push(FieldNode::leaf(
            "session_seq",
            FieldValue::U64(session_seq),
            (8, 16),
        ));
        let timestamp = le_u64(data, 16).unwrap_or(0);
        fields.push(FieldNode::leaf(
            "timestamp_unix_ms",
            FieldValue::U64(timestamp),
            (16, 24),
        ));

        let prev_algo = data.get(24).copied().unwrap_or(0);
        fields.push(hash_pair("prev_session_hash", data, 24, 25, &mut warnings));

        let block_count = le_u32(data, 89).unwrap_or(0);
        if block_count == 0 {
            warnings.push("block_count must be >= 1".into());
        }
        fields.push(FieldNode::leaf(
            "block_count",
            FieldValue::U64(block_count as u64),
            (89, 93),
        ));

        let member_algo = data.get(93).copied().unwrap_or(0);
        fields.push(hash_pair(
            "member_blocks_digest",
            data,
            93,
            94,
            &mut warnings,
        ));

        // Spec consistency rules.
        if prev_algo == 0 && !all_zero(data.get(25..89).unwrap_or(&[])) {
            warnings.push("prev_session_hash must be 64 zero bytes when its algo id is 0".into());
        }
        if block_count == 1 && (member_algo != 0 || !all_zero(data.get(94..158).unwrap_or(&[]))) {
            warnings.push("member_blocks_digest must be zero when block_count == 1".into());
        }

        let change_count = le_u16(data, 158).unwrap_or(0);
        fields.push(
            FieldNode::leaf(
                "change_count",
                FieldValue::U64(change_count as u64),
                (158, 160),
            )
            .with_note("informational"),
        );

        let writer_len = le_u16(data, 160).unwrap_or(0);
        fields.push(FieldNode::leaf(
            "writer_len",
            FieldValue::U64(writer_len as u64),
            (160, 162),
        ));
        let writer_end = 162usize + writer_len as usize;
        let writer_bytes = data.get(162..writer_end).unwrap_or(&[]);
        if writer_bytes.len() != writer_len as usize {
            warnings.push("writer runs past end of record".into());
        }
        if writer_len > 0 {
            fields.push(FieldNode::leaf(
                "writer",
                FieldValue::Text(String::from_utf8_lossy(writer_bytes).into_owned()),
                (162, writer_end as u64),
            ));
        }
        check_trailing(data, writer_end, &mut warnings);

        Decoded {
            format_name: "PFS_SESSION".into(),
            fields,
            warnings,
        }
    }
}

fn all_zero(b: &[u8]) -> bool {
    b.iter().all(|&x| x == 0)
}

/// Render up to four bytes as ASCII if printable, else as hex.
fn ascii_or_hex(b: &[u8]) -> String {
    if !b.is_empty() && b.iter().all(|&c| (0x20..0x7f).contains(&c)) {
        String::from_utf8_lossy(b).into_owned()
    } else {
        b.iter()
            .map(|c| format!("{c:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}
