//! Decoder for PCF-DCP containers (see `specs/PCF-DCP-spec-v1.0.txt`):
//! `DCP_CONTAINER` (partition type `0xAAAC0001`, arena magic `"PDCP"`).
//!
//! The decoder mirrors the spec's byte tables field-for-field — DCP Header,
//! Inner Table Block chain, and a Fragment Table per inner partition — and
//! reports spec violations as warnings rather than failing. Parsing is inline
//! (it does not depend on the `pcf-dcp` reader), but it borrows the profile's
//! constants from the `pcf-dcp` crate so the two never drift.

use pcf::{HashAlgo, ENTRY_SIZE, TABLE_HEADER_SIZE};
use pcf_dcp::{
    DCP_CONTAINER_TYPE, DCP_HEADER_SIZE, DCP_MAGIC, FRAGMENT_ENTRY_SIZE, FRAGTABLE_HEADER_SIZE,
    KIND_DATA,
};

use super::{
    le_u16, le_u32, le_u64, uid_at, Decoded, DecodedChild, FieldNode, FieldValue, PartitionDecoder,
    PartitionMeta,
};

fn kind_name(kind: u8) -> &'static str {
    match kind {
        0 => "INVALID (reserved)",
        1 => "DATA",
        2 => "HOLE (reserved)",
        3 => "REF (reserved)",
        _ => "unknown",
    }
}

fn hash_algo_name(id: u8) -> &'static str {
    match HashAlgo::from_id(id) {
        Ok(a) => crate::model::algo_name(a),
        Err(_) => "unknown",
    }
}

/// Render a `<algo_id><64-byte hash>` pair, truncated to the digest length.
fn hash_field(data: &[u8], algo_off: usize, hash_off: usize) -> FieldNode {
    let id = data.get(algo_off).copied().unwrap_or(0);
    let len = HashAlgo::from_id(id).map(|a| a.digest_len()).unwrap_or(0);
    let bytes = data
        .get(hash_off..hash_off + 64)
        .map(|b| b[..len.min(64)].to_vec())
        .unwrap_or_default();
    FieldNode::group("data_hash")
        .child(FieldNode::leaf(
            "algo_id",
            FieldValue::Enum {
                raw: id as u64,
                name: hash_algo_name(id).into(),
            },
            (algo_off as u64, algo_off as u64 + 1),
        ))
        .child(FieldNode::leaf(
            "hash",
            FieldValue::Bytes(bytes),
            (hash_off as u64, hash_off as u64 + 64),
        ))
}

pub struct DcpContainerDecoder;

impl PartitionDecoder for DcpContainerDecoder {
    fn name(&self) -> &'static str {
        "dcp-container"
    }

    fn matches(&self, meta: &PartitionMeta, data: &[u8]) -> bool {
        meta.partition_type == DCP_CONTAINER_TYPE || data.get(0..4) == Some(&DCP_MAGIC)
    }

    fn decode(&self, _meta: &PartitionMeta, data: &[u8]) -> Decoded {
        let mut warnings = Vec::new();
        let mut fields = Vec::new();

        if (data.len() as u64) < DCP_HEADER_SIZE {
            warnings.push(format!(
                "arena is {} bytes; DCP Header needs at least {DCP_HEADER_SIZE}",
                data.len()
            ));
        }

        // ---- DCP Header ---------------------------------------------------
        let magic_ok = data.get(0..4) == Some(&DCP_MAGIC);
        if !magic_ok {
            warnings.push("dcp_magic is not \"PDCP\"".into());
        }
        let mut header = FieldNode::group("DCP Header");
        header.push(
            FieldNode::leaf(
                "dcp_magic",
                FieldValue::Text(ascii4(data.get(0..4).unwrap_or(&[]))),
                (0, 4),
            )
            .with_note(if magic_ok {
                "magic OK"
            } else {
                "expected \"PDCP\""
            }),
        );
        let major = data.get(4).copied().unwrap_or(0);
        if major != 1 {
            warnings.push(format!(
                "profile_version_major is {major} (v1.0 reader expects 1)"
            ));
        }
        header.push(FieldNode::leaf(
            "profile_version_major",
            FieldValue::U64(major as u64),
            (4, 5),
        ));
        header.push(FieldNode::leaf(
            "profile_version_minor",
            FieldValue::U64(data.get(5).copied().unwrap_or(0) as u64),
            (5, 6),
        ));
        let flags = le_u16(data, 6).unwrap_or(0);
        if flags != 0 {
            warnings.push(format!("flags is {flags:#06x}; v1.0 requires 0"));
        }
        header.push(FieldNode::leaf(
            "flags",
            FieldValue::U64(flags as u64),
            (6, 8),
        ));
        let inner_table_offset = le_u64(data, 8).unwrap_or(0);
        header.push(FieldNode::leaf(
            "inner_table_offset",
            FieldValue::U64(inner_table_offset),
            (8, 16),
        ));
        let arena_used = le_u64(data, 16).unwrap_or(0);
        header.push(FieldNode::leaf(
            "arena_used",
            FieldValue::U64(arena_used),
            (16, 24),
        ));
        fields.push(header);

        // ---- Inner Table Block chain --------------------------------------
        let mut inner_group = FieldNode::group("Inner Table Block(s)");
        let mut frag_offsets: Vec<(String, u64)> = Vec::new(); // (label, start_offset)
        let mut off = inner_table_offset;
        let mut block_idx = 0usize;
        let mut budget = data.len() / TABLE_HEADER_SIZE as usize + 1;
        while off != 0 {
            if budget == 0 {
                warnings.push("inner table chain does not terminate".into());
                break;
            }
            budget -= 1;
            let base = off as usize;
            if base + TABLE_HEADER_SIZE as usize > data.len() {
                warnings.push(format!("inner Table Block at {off} runs past end of arena"));
                break;
            }
            let count = data[base];
            let next = le_u64(data, base + 1).unwrap_or(0);
            let th_algo = data.get(base + 9).copied().unwrap_or(0);
            let mut block = FieldNode::group(format!("block[{block_idx}] @ {off}"));
            block.push(FieldNode::leaf(
                "partition_count",
                FieldValue::U64(count as u64),
                (base as u64, base as u64 + 1),
            ));
            block.push(FieldNode::leaf(
                "next_table_offset",
                FieldValue::U64(next),
                (base as u64 + 1, base as u64 + 9),
            ));
            block.push(
                hash_field(data, base + 9, base + 10)
                    .with_note(format!("table_hash ({})", hash_algo_name(th_algo))),
            );

            for i in 0..count as usize {
                let eo = base + TABLE_HEADER_SIZE as usize + i * ENTRY_SIZE as usize;
                if eo + ENTRY_SIZE as usize > data.len() {
                    warnings.push(format!("inner entry {i} runs past end of arena"));
                    break;
                }
                let ptype = le_u32(data, eo).unwrap_or(0);
                let uid = uid_at(data, eo + 4).unwrap_or([0; 16]);
                let label = label32(data, eo + 20);
                let start_offset = le_u64(data, eo + 52).unwrap_or(0);
                let max_length = le_u64(data, eo + 60).unwrap_or(0);
                let used_bytes = le_u64(data, eo + 68).unwrap_or(0);

                if ptype == DCP_CONTAINER_TYPE {
                    warnings.push(format!(
                        "inner entry \"{label}\" is itself a DCP container (nesting forbidden)"
                    ));
                }
                if max_length != used_bytes {
                    warnings.push(format!(
                        "inner entry \"{label}\": max_length ({max_length}) != used_bytes ({used_bytes}) (spec 7.2)"
                    ));
                }
                frag_offsets.push((label.clone(), start_offset));

                let mut entry = FieldNode::group(format!("inner[{label}]"));
                entry.push(FieldNode::leaf(
                    "type",
                    FieldValue::U64(ptype as u64),
                    (eo as u64, eo as u64 + 4),
                ));
                entry.push(FieldNode::leaf(
                    "uid",
                    FieldValue::Uid(uid),
                    (eo as u64 + 4, eo as u64 + 20),
                ));
                entry.push(FieldNode::leaf(
                    "label",
                    FieldValue::Text(label),
                    (eo as u64 + 20, eo as u64 + 52),
                ));
                entry.push(
                    FieldNode::leaf(
                        "start_offset",
                        FieldValue::U64(start_offset),
                        (eo as u64 + 52, eo as u64 + 60),
                    )
                    .with_note("reinterpreted -> Fragment Table"),
                );
                entry.push(
                    FieldNode::leaf(
                        "max_length",
                        FieldValue::U64(max_length),
                        (eo as u64 + 60, eo as u64 + 68),
                    )
                    .with_note("reinterpreted = used_bytes"),
                );
                entry.push(FieldNode::leaf(
                    "used_bytes",
                    FieldValue::U64(used_bytes),
                    (eo as u64 + 68, eo as u64 + 76),
                ));
                entry.push(hash_field(data, eo + 76, eo + 77));
                block.push(entry);
            }
            inner_group.push(block);
            off = next;
            block_idx += 1;
        }
        fields.push(inner_group);

        // ---- Fragment Tables, one chain per inner partition ---------------
        let mut frag_group = FieldNode::group("Fragment Tables");
        let mut total_extents = 0usize;
        let mut shared_extents = 0usize;
        for (label, start) in &frag_offsets {
            let mut inner = FieldNode::group(format!("frags[{label}] @ {start}"));
            let mut foff = *start;
            let mut fbudget = data.len() / FRAGTABLE_HEADER_SIZE as usize + 1;
            let mut chain_idx = 0usize;
            while foff != 0 {
                if fbudget == 0 {
                    warnings.push(format!("fragment table for \"{label}\" does not terminate"));
                    break;
                }
                fbudget -= 1;
                let base = foff as usize;
                if base + FRAGTABLE_HEADER_SIZE as usize > data.len() {
                    warnings.push(format!(
                        "fragment table for \"{label}\" runs past end of arena"
                    ));
                    break;
                }
                let next = le_u64(data, base).unwrap_or(0);
                let fcount = data[base + 8];
                let mut blk = FieldNode::group(format!("block[{chain_idx}] @ {foff}"));
                blk.push(FieldNode::leaf(
                    "next_fragtable_offset",
                    FieldValue::U64(next),
                    (base as u64, base as u64 + 8),
                ));
                blk.push(FieldNode::leaf(
                    "fragment_count",
                    FieldValue::U64(fcount as u64),
                    (base as u64 + 8, base as u64 + 9),
                ));
                for i in 0..fcount as usize {
                    let xo =
                        base + FRAGTABLE_HEADER_SIZE as usize + i * FRAGMENT_ENTRY_SIZE as usize;
                    if xo + FRAGMENT_ENTRY_SIZE as usize > data.len() {
                        warnings.push(format!(
                            "fragment {i} of \"{label}\" runs past end of arena"
                        ));
                        break;
                    }
                    let ext_off = le_u64(data, xo).unwrap_or(0);
                    let ext_len = le_u64(data, xo + 8).unwrap_or(0);
                    let kind = data.get(xo + 16).copied().unwrap_or(0);
                    let eflags = data.get(xo + 17).copied().unwrap_or(0);
                    let shared = eflags & 1 != 0;
                    total_extents += 1;
                    if shared {
                        shared_extents += 1;
                    }
                    if kind != KIND_DATA {
                        warnings.push(format!(
                            "fragment {i} of \"{label}\" has kind {kind} ({}) — unreadable in v1.0",
                            kind_name(kind)
                        ));
                    }
                    if eflags & !1 != 0 {
                        warnings.push(format!(
                            "fragment {i} of \"{label}\" has reserved flag bits set"
                        ));
                    }
                    let mut frag = FieldNode::group(format!("extent[{i}]"));
                    frag.push(FieldNode::leaf(
                        "extent_offset",
                        FieldValue::U64(ext_off),
                        (xo as u64, xo as u64 + 8),
                    ));
                    frag.push(FieldNode::leaf(
                        "extent_length",
                        FieldValue::U64(ext_len),
                        (xo as u64 + 8, xo as u64 + 16),
                    ));
                    frag.push(FieldNode::leaf(
                        "kind",
                        FieldValue::Enum {
                            raw: kind as u64,
                            name: kind_name(kind).into(),
                        },
                        (xo as u64 + 16, xo as u64 + 17),
                    ));
                    frag.push(FieldNode::leaf(
                        "flags",
                        FieldValue::Flags {
                            raw: eflags as u64,
                            set: if shared {
                                vec!["SHARED".into()]
                            } else {
                                Vec::new()
                            },
                        },
                        (xo as u64 + 17, xo as u64 + 18),
                    ));
                    blk.push(frag);
                }
                inner.push(blk);
                foff = next;
                chain_idx += 1;
            }
            frag_group.push(inner);
        }
        fields.push(frag_group);

        // ---- Summary ------------------------------------------------------
        let mut summary = FieldNode::group("summary");
        summary.push(FieldNode::leaf(
            "inner_partitions",
            FieldValue::U64(frag_offsets.len() as u64),
            (0, 0),
        ));
        summary.push(FieldNode::leaf(
            "extents",
            FieldValue::U64(total_extents as u64),
            (0, 0),
        ));
        summary.push(FieldNode::leaf(
            "shared_extents",
            FieldValue::U64(shared_extents as u64),
            (0, 0),
        ));
        fields.push(summary);

        Decoded {
            format_name: "DCP_CONTAINER".into(),
            fields,
            warnings,
        }
    }

    /// The inner partitions of the DCP container, each with its reconstructed
    /// logical content, so the pipeline can decode them recursively (spec
    /// Sections 7–8). Defensive: a malformed arena or an inner partition whose
    /// content cannot be reconstructed (reserved fragment kind, length
    /// mismatch) is simply omitted — `decode` already surfaces the structural
    /// detail and any warnings.
    fn children(&self, _meta: &PartitionMeta, data: &[u8]) -> Vec<DecodedChild> {
        let arena = match pcf_dcp::Arena::parse(data) {
            Ok(a) => a,
            Err(_) => return Vec::new(),
        };
        arena
            .inners()
            .into_iter()
            .filter_map(|info| {
                arena.content(&info.uid).ok().map(|content| DecodedChild {
                    partition_type: info.partition_type,
                    uid: info.uid,
                    label: info.label,
                    data: content,
                })
            })
            .collect()
    }
}

/// Render a 4-byte magic as ASCII (non-printable bytes shown as `\xNN`).
fn ascii4(b: &[u8]) -> String {
    b.iter()
        .map(|&c| {
            if (0x20..0x7f).contains(&c) {
                (c as char).to_string()
            } else {
                format!("\\x{c:02x}")
            }
        })
        .collect()
}

/// Decode a 32-byte label field (read until the first NUL).
fn label32(data: &[u8], off: usize) -> String {
    let bytes = data.get(off..off + 32).unwrap_or(&[]);
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
