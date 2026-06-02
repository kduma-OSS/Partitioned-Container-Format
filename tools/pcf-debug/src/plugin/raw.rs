//! The fallback decoder: works for any partition, used for `TYPE_RAW` blobs and
//! anything no other decoder claims.

use super::{Decoded, FieldNode, FieldValue, PartitionDecoder, PartitionMeta};

/// How many leading bytes to surface as a preview in the field tree. The full
/// hexdump is the job of the hexdump renderer, not this decoder.
const PREVIEW_BYTES: usize = 32;

pub struct RawDecoder;

impl PartitionDecoder for RawDecoder {
    fn name(&self) -> &'static str {
        "raw"
    }

    fn matches(&self, _meta: &PartitionMeta, _data: &[u8]) -> bool {
        // The unconditional final fallback.
        true
    }

    fn decode(&self, _meta: &PartitionMeta, data: &[u8]) -> Decoded {
        let printable = data.iter().filter(|&&b| (0x20..0x7f).contains(&b)).count();
        let ratio = if data.is_empty() {
            0.0
        } else {
            printable as f64 / data.len() as f64
        };

        let mut fields = vec![
            FieldNode::leaf(
                "size",
                FieldValue::U64(data.len() as u64),
                (0, data.len() as u64),
            ),
            FieldNode::leaf(
                "printable_ascii_ratio",
                FieldValue::Text(format!("{:.0}%", ratio * 100.0)),
                (0, data.len() as u64),
            ),
        ];

        let preview_len = data.len().min(PREVIEW_BYTES);
        fields.push(FieldNode::leaf(
            "preview",
            FieldValue::Bytes(data[..preview_len].to_vec()),
            (0, preview_len as u64),
        ));

        Decoded {
            format_name: "RAW".into(),
            fields,
            warnings: Vec::new(),
        }
    }
}
