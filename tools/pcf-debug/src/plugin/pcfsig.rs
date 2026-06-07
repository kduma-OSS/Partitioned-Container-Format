//! Decoders for PCF-SIG records (see `specs/PCF-SIG-spec-v1.0.txt`):
//! `PCFSIG_KEY` (partition type `0xAAAB0001`, magic `"PCFKEY\0\0"`) and
//! `PCFSIG_SIG` (partition type `0xAAAB0002`, magic `"PCFSIG\0\0"`).
//!
//! Both decoders mirror the spec's byte tables field-for-field and report spec
//! violations as warnings rather than failing.

use pcf::HashAlgo;
use pcf_sig::{
    compute_fingerprint, is_crypto_hash, KeyFormat, SigAlgo, FINGERPRINT_SIZE, KEY_MAGIC,
    KEY_PREFIX_SIZE, MANIFEST_PREFIX_SIZE, SIGNED_ENTRY_SIZE, SIG_MAGIC, TYPE_PCFSIG_KEY,
    TYPE_PCFSIG_SIG,
};

use super::{
    le_u16, le_u32, le_u64, uid_at, Decoded, FieldNode, FieldValue, PartitionDecoder, PartitionMeta,
};

/// Render an 8-byte magic field as ASCII (with embedded NULs shown as `\0`).
fn magic8(b: &[u8]) -> String {
    b.iter()
        .map(|&c| {
            if c == 0 {
                "\\0".to_string()
            } else if (0x20..0x7f).contains(&c) {
                (c as char).to_string()
            } else {
                format!("\\x{c:02x}")
            }
        })
        .collect()
}

fn sig_algo_name(id: u8) -> &'static str {
    match SigAlgo::from_id(id) {
        Ok(SigAlgo::Ed25519) => "Ed25519",
        Ok(SigAlgo::RsaPssSha256) => "RSA-PSS-SHA-256",
        Ok(SigAlgo::RsaPssSha512) => "RSA-PSS-SHA-512",
        Ok(SigAlgo::RsaPkcs1v15Sha256) => "RSA-PKCS1v15-SHA-256",
        Ok(SigAlgo::RsaPkcs1v15Sha512) => "RSA-PKCS1v15-SHA-512",
        Ok(SigAlgo::EcdsaP256Sha256) => "ECDSA-P256-SHA-256",
        Ok(SigAlgo::EcdsaP521Sha512) => "ECDSA-P521-SHA-512",
        Ok(SigAlgo::X509Chain) => "X.509 chain",
        Err(_) => "unknown",
    }
}

fn key_format_name(id: u8) -> &'static str {
    match KeyFormat::from_id(id) {
        Ok(KeyFormat::Ed25519Raw) => "Ed25519 raw",
        Ok(KeyFormat::RsaSpkiDer) => "RSA SPKI DER",
        Ok(KeyFormat::EcdsaSpkiDer) => "ECDSA SPKI DER",
        Ok(KeyFormat::X509Cert) => "X.509 certificate",
        Ok(KeyFormat::X509Chain) => "X.509 certificate chain",
        Err(_) => "unknown",
    }
}

fn metadata_tag_name(tag: u16) -> &'static str {
    match tag {
        0x0000 => "reserved",
        0x0001 => "subject_dn",
        0x0002 => "not_before",
        0x0003 => "not_after",
        0x0004 => "issuer_dn",
        0x0005 => "comment",
        t if t >= 0x8000 => "application-private",
        _ => "reserved (future)",
    }
}

// ---------------------------------------------------------------------------
// PCFSIG_KEY
// ---------------------------------------------------------------------------

pub struct PcfSigKeyDecoder;

impl PartitionDecoder for PcfSigKeyDecoder {
    fn name(&self) -> &'static str {
        "pcfsig-key"
    }

    fn matches(&self, meta: &PartitionMeta, data: &[u8]) -> bool {
        meta.partition_type == TYPE_PCFSIG_KEY || data.get(0..8) == Some(&KEY_MAGIC)
    }

    fn decode(&self, _meta: &PartitionMeta, data: &[u8]) -> Decoded {
        let mut warnings = Vec::new();
        let mut fields = Vec::new();

        if data.len() < KEY_PREFIX_SIZE {
            warnings.push(format!(
                "record is {} bytes; PCFSIG_KEY needs at least a {KEY_PREFIX_SIZE}-byte prefix",
                data.len()
            ));
        }

        let magic_ok = data.get(0..8) == Some(&KEY_MAGIC);
        if !magic_ok {
            warnings.push("record_magic is not \"PCFKEY\\0\\0\"".into());
        }
        fields.push(
            FieldNode::leaf(
                "record_magic",
                FieldValue::Text(magic8(data.get(0..8).unwrap_or(&[]))),
                (0, 8),
            )
            .with_note(if magic_ok {
                "magic OK"
            } else {
                "expected \"PCFKEY\\0\\0\""
            }),
        );

        let version_major = le_u16(data, 8).unwrap_or(0);
        let version_minor = le_u16(data, 10).unwrap_or(0);
        if version_major != 1 {
            warnings.push(format!(
                "record_version_major is {version_major} (v1.0 reader expects 1)"
            ));
        }
        fields.push(FieldNode::leaf(
            "record_version_major",
            FieldValue::U64(version_major as u64),
            (8, 10),
        ));
        fields.push(FieldNode::leaf(
            "record_version_minor",
            FieldValue::U64(version_minor as u64),
            (10, 12),
        ));

        let key_format_id = data.get(12).copied().unwrap_or(0);
        if key_format_id == 0 {
            warnings.push("key_format_id is 0 (reserved)".into());
        } else if KeyFormat::from_id(key_format_id).is_err() {
            warnings.push(format!("key_format_id {key_format_id} is unknown"));
        }
        fields.push(FieldNode::leaf(
            "key_format_id",
            FieldValue::Enum {
                raw: key_format_id as u64,
                name: key_format_name(key_format_id).into(),
            },
            (12, 13),
        ));

        let reserved = data.get(13..16).unwrap_or(&[]);
        if reserved.iter().any(|&b| b != 0) {
            warnings.push("reserved bytes (offset 13..16) must be 0".into());
        }
        fields.push(FieldNode::leaf(
            "reserved",
            FieldValue::Bytes(reserved.to_vec()),
            (13, 16),
        ));

        let fingerprint_stored = data.get(16..16 + FINGERPRINT_SIZE).unwrap_or(&[]);
        fields.push(FieldNode::leaf(
            "fingerprint",
            FieldValue::Bytes(fingerprint_stored.to_vec()),
            (16, 16 + FINGERPRINT_SIZE as u64),
        ));

        let key_data_length = le_u32(data, 48).unwrap_or(0) as usize;
        if key_data_length == 0 {
            warnings.push("key_data_length is 0".into());
        }
        fields.push(FieldNode::leaf(
            "key_data_length",
            FieldValue::U64(key_data_length as u64),
            (48, 52),
        ));

        let key_end = KEY_PREFIX_SIZE.saturating_add(key_data_length);
        if key_end > data.len() {
            warnings.push(format!(
                "key_data runs past end of record ({key_end} > {})",
                data.len()
            ));
        }
        let key_data = data
            .get(KEY_PREFIX_SIZE..key_end.min(data.len()))
            .unwrap_or(&[]);
        fields.push(FieldNode::leaf(
            "key_data",
            FieldValue::Bytes(key_data.to_vec()),
            (KEY_PREFIX_SIZE as u64, key_end as u64),
        ));

        // Cross-check: recompute SHA-256(key_data) and compare to stored fingerprint.
        if !key_data.is_empty() && fingerprint_stored.len() == FINGERPRINT_SIZE {
            let recomputed = compute_fingerprint(key_data);
            if recomputed.as_slice() != fingerprint_stored {
                warnings.push(
                    "stored fingerprint does not equal SHA-256(key_data) (spec Section 6.3)".into(),
                );
            }
        }

        // Optional metadata TLV stream.
        if key_end < data.len() {
            let mut tlv_group = FieldNode::group("optional_metadata");
            let mut cur = key_end;
            let mut entry_idx = 0usize;
            while cur < data.len() {
                if data.len() - cur < 6 {
                    warnings.push(format!(
                        "metadata TLV entry {entry_idx} is truncated ({} bytes left)",
                        data.len() - cur
                    ));
                    break;
                }
                let tag = le_u16(data, cur).unwrap_or(0);
                let len = le_u32(data, cur + 2).unwrap_or(0) as usize;
                let value_start = cur + 6;
                let value_end = value_start.saturating_add(len);
                let mut entry = FieldNode::group(format!("entry[{entry_idx}]"));
                entry.push(FieldNode::leaf(
                    "tag",
                    FieldValue::Enum {
                        raw: tag as u64,
                        name: metadata_tag_name(tag).into(),
                    },
                    (cur as u64, cur as u64 + 2),
                ));
                entry.push(FieldNode::leaf(
                    "length",
                    FieldValue::U64(len as u64),
                    (cur as u64 + 2, cur as u64 + 6),
                ));
                if value_end > data.len() {
                    warnings.push(format!(
                        "metadata TLV entry {entry_idx} value ({len} bytes) runs past end of record"
                    ));
                    entry.push(FieldNode::leaf(
                        "value",
                        FieldValue::Bytes(data.get(value_start..).unwrap_or(&[]).to_vec()),
                        (value_start as u64, data.len() as u64),
                    ));
                    tlv_group.push(entry);
                    break;
                }
                let value = &data[value_start..value_end];
                entry.push(FieldNode::leaf(
                    "value",
                    FieldValue::Bytes(value.to_vec()),
                    (value_start as u64, value_end as u64),
                ));
                tlv_group.push(entry);
                cur = value_end;
                entry_idx += 1;
            }
            if entry_idx > 0 {
                fields.push(tlv_group);
            }
        }

        Decoded {
            format_name: "PCFSIG_KEY".into(),
            fields,
            warnings,
        }
    }
}

// ---------------------------------------------------------------------------
// PCFSIG_SIG
// ---------------------------------------------------------------------------

pub struct PcfSigSignatureDecoder;

impl PartitionDecoder for PcfSigSignatureDecoder {
    fn name(&self) -> &'static str {
        "pcfsig-sig"
    }

    fn matches(&self, meta: &PartitionMeta, data: &[u8]) -> bool {
        meta.partition_type == TYPE_PCFSIG_SIG || data.get(0..8) == Some(&SIG_MAGIC)
    }

    fn decode(&self, _meta: &PartitionMeta, data: &[u8]) -> Decoded {
        let mut warnings = Vec::new();
        let mut fields = Vec::new();

        if data.len() < MANIFEST_PREFIX_SIZE {
            warnings.push(format!(
                "record is {} bytes; PCFSIG_SIG manifest needs at least {MANIFEST_PREFIX_SIZE}",
                data.len()
            ));
        }

        // ---- manifest prefix --------------------------------------------------
        let mut manifest = FieldNode::group("manifest");

        let magic_ok = data.get(0..8) == Some(&SIG_MAGIC);
        if !magic_ok {
            warnings.push("manifest_magic is not \"PCFSIG\\0\\0\"".into());
        }
        manifest.push(
            FieldNode::leaf(
                "manifest_magic",
                FieldValue::Text(magic8(data.get(0..8).unwrap_or(&[]))),
                (0, 8),
            )
            .with_note(if magic_ok {
                "magic OK"
            } else {
                "expected \"PCFSIG\\0\\0\""
            }),
        );

        let version_major = le_u16(data, 8).unwrap_or(0);
        let version_minor = le_u16(data, 10).unwrap_or(0);
        if version_major != 1 {
            warnings.push(format!(
                "manifest_version_major is {version_major} (v1.0 reader expects 1)"
            ));
        }
        manifest.push(FieldNode::leaf(
            "manifest_version_major",
            FieldValue::U64(version_major as u64),
            (8, 10),
        ));
        manifest.push(FieldNode::leaf(
            "manifest_version_minor",
            FieldValue::U64(version_minor as u64),
            (10, 12),
        ));

        let sig_algo_id = data.get(12).copied().unwrap_or(0);
        if sig_algo_id == 0 {
            warnings.push("sig_algo_id is 0 (reserved)".into());
        } else if SigAlgo::from_id(sig_algo_id).is_err() {
            warnings.push(format!("sig_algo_id {sig_algo_id} is unknown"));
        }
        manifest.push(FieldNode::leaf(
            "sig_algo_id",
            FieldValue::Enum {
                raw: sig_algo_id as u64,
                name: sig_algo_name(sig_algo_id).into(),
            },
            (12, 13),
        ));

        let manifest_hash_id = data.get(13).copied().unwrap_or(0);
        let (manifest_hash_name, hash_is_crypto) = match HashAlgo::from_id(manifest_hash_id) {
            Ok(a) => (crate::model::algo_name(a), is_crypto_hash(a)),
            Err(_) => ("unknown", false),
        };
        if !hash_is_crypto {
            warnings.push(format!(
                "manifest_hash_algo_id {manifest_hash_id} is not cryptographic (spec Section 9)"
            ));
        }
        manifest.push(FieldNode::leaf(
            "manifest_hash_algo_id",
            FieldValue::Enum {
                raw: manifest_hash_id as u64,
                name: manifest_hash_name.into(),
            },
            (13, 14),
        ));

        let flags = le_u16(data, 14).unwrap_or(0);
        if flags != 0 {
            warnings.push(format!("flags is {flags:#06x}; v1.0 readers require 0"));
        }
        manifest.push(FieldNode::leaf(
            "flags",
            FieldValue::U64(flags as u64),
            (14, 16),
        ));

        let signer_fp = data.get(16..16 + FINGERPRINT_SIZE).unwrap_or(&[]);
        manifest.push(FieldNode::leaf(
            "signer_key_fingerprint",
            FieldValue::Bytes(signer_fp.to_vec()),
            (16, 16 + FINGERPRINT_SIZE as u64),
        ));

        let signed_at = le_u64(data, 48).unwrap_or(0);
        manifest.push(FieldNode::leaf(
            "signed_at_unix_seconds",
            FieldValue::U64(signed_at),
            (48, 56),
        ));

        let signed_count = le_u32(data, 56).unwrap_or(0) as usize;
        if signed_count == 0 {
            warnings.push("signed_count is 0 (manifest must have at least 1 entry)".into());
        }
        manifest.push(FieldNode::leaf(
            "signed_count",
            FieldValue::U64(signed_count as u64),
            (56, 60),
        ));

        // ---- signed_entries[] -------------------------------------------------
        let mut entries_group = FieldNode::group("signed_entries");
        for i in 0..signed_count {
            let off = MANIFEST_PREFIX_SIZE + i * SIGNED_ENTRY_SIZE;
            if off + SIGNED_ENTRY_SIZE > data.len() {
                warnings.push(format!(
                    "signed_entry[{i}] runs past end of record (offset {off}, len {})",
                    data.len()
                ));
                break;
            }
            let mut entry = FieldNode::group(format!("entry[{i}]"));

            let uid = uid_at(data, off).unwrap_or([0; 16]);
            if uid == [0u8; 16] {
                warnings.push(format!("signed_entry[{i}].uid is NIL"));
            }
            entry.push(FieldNode::leaf(
                "uid",
                FieldValue::Uid(uid),
                (off as u64, off as u64 + 16),
            ));

            let ptype = le_u32(data, off + 16).unwrap_or(0);
            if ptype == 0 {
                warnings.push(format!("signed_entry[{i}].partition_type is 0 (reserved)"));
            }
            entry.push(FieldNode::leaf(
                "partition_type",
                FieldValue::U64(ptype as u64),
                (off as u64 + 16, off as u64 + 20),
            ));

            let label_bytes = data.get(off + 20..off + 52).unwrap_or(&[]);
            let label_end = label_bytes.iter().position(|&b| b == 0).unwrap_or(32);
            let label_str =
                String::from_utf8_lossy(&label_bytes[..label_end.min(label_bytes.len())])
                    .into_owned();
            entry.push(FieldNode::leaf(
                "label",
                FieldValue::Text(label_str),
                (off as u64 + 20, off as u64 + 52),
            ));

            let used_bytes = le_u64(data, off + 52).unwrap_or(0);
            entry.push(FieldNode::leaf(
                "used_bytes",
                FieldValue::U64(used_bytes),
                (off as u64 + 52, off as u64 + 60),
            ));

            let entry_hash_id = data.get(off + 60).copied().unwrap_or(0);
            let (entry_hash_name, entry_is_crypto) = match HashAlgo::from_id(entry_hash_id) {
                Ok(a) => (crate::model::algo_name(a), is_crypto_hash(a)),
                Err(_) => ("unknown", false),
            };
            if !entry_is_crypto {
                warnings.push(format!(
                    "signed_entry[{i}].data_hash_algo_id {entry_hash_id} is not cryptographic"
                ));
            }
            entry.push(FieldNode::leaf(
                "data_hash_algo_id",
                FieldValue::Enum {
                    raw: entry_hash_id as u64,
                    name: entry_hash_name.into(),
                },
                (off as u64 + 60, off as u64 + 61),
            ));

            let reserved1 = data.get(off + 61).copied().unwrap_or(0);
            if reserved1 != 0 {
                warnings.push(format!(
                    "signed_entry[{i}] reserved byte at offset 61 is {reserved1:#04x} (must be 0)"
                ));
            }
            entry.push(FieldNode::leaf(
                "reserved (1 B)",
                FieldValue::U64(reserved1 as u64),
                (off as u64 + 61, off as u64 + 62),
            ));

            let data_hash = data.get(off + 62..off + 126).unwrap_or(&[]);
            entry.push(FieldNode::leaf(
                "data_hash",
                FieldValue::Bytes(data_hash.to_vec()),
                (off as u64 + 62, off as u64 + 126),
            ));

            let reserved2 = data.get(off + 126..off + 218).unwrap_or(&[]);
            if reserved2.iter().any(|&b| b != 0) {
                warnings.push(format!(
                    "signed_entry[{i}] reserved tail (92 B at offset 126) must be all-zero"
                ));
            }
            entry.push(FieldNode::leaf(
                "reserved (92 B)",
                FieldValue::Bytes(reserved2.to_vec()),
                (off as u64 + 126, off as u64 + 218),
            ));

            entries_group.push(entry);
        }
        manifest.push(entries_group);
        fields.push(manifest);

        // ---- tail: sig_length || sig_bytes || trailer_length -----------------
        let manifest_len = MANIFEST_PREFIX_SIZE + signed_count * SIGNED_ENTRY_SIZE;
        if data.len() >= manifest_len + 4 {
            let sig_length = le_u32(data, manifest_len).unwrap_or(0) as usize;
            fields.push(FieldNode::leaf(
                "sig_length",
                FieldValue::U64(sig_length as u64),
                (manifest_len as u64, manifest_len as u64 + 4),
            ));

            let sig_start = manifest_len + 4;
            let sig_end = sig_start.saturating_add(sig_length);
            if sig_end > data.len() {
                warnings.push(format!(
                    "sig_bytes ({sig_length} bytes) runs past end of record"
                ));
            }
            let sig_bytes = data.get(sig_start..sig_end.min(data.len())).unwrap_or(&[]);
            fields.push(FieldNode::leaf(
                "sig_bytes",
                FieldValue::Bytes(sig_bytes.to_vec()),
                (sig_start as u64, sig_end as u64),
            ));

            if data.len() >= sig_end + 4 {
                let trailer_length = le_u32(data, sig_end).unwrap_or(0) as usize;
                if trailer_length != 0 {
                    warnings.push(format!(
                        "trailer_length is {trailer_length}; v1.0 readers require 0"
                    ));
                }
                fields.push(FieldNode::leaf(
                    "trailer_length",
                    FieldValue::U64(trailer_length as u64),
                    (sig_end as u64, sig_end as u64 + 4),
                ));
                if trailer_length > 0 {
                    let trailer_bytes = data
                        .get(sig_end + 4..(sig_end + 4 + trailer_length).min(data.len()))
                        .unwrap_or(&[]);
                    fields.push(FieldNode::leaf(
                        "trailer_bytes",
                        FieldValue::Bytes(trailer_bytes.to_vec()),
                        (sig_end as u64 + 4, (sig_end + 4 + trailer_length) as u64),
                    ));
                }
            } else {
                warnings.push("trailer_length field missing (record is truncated)".into());
            }
        } else {
            warnings.push("sig_length field missing (record is truncated)".into());
        }

        Decoded {
            format_name: "PCFSIG_SIG".into(),
            fields,
            warnings,
        }
    }
}
