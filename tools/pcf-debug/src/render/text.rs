//! The CLI/ASCII renderer: a layout map, a partition table, a block-chain tree,
//! decoded field trees, and a diagnostics footer — all driven by the shared
//! [`Report`].

use pcf::TYPE_RAW;

use super::color::Palette;
use super::{label_or, uid_hex, Report};
use crate::model::algo_name;
use crate::model::diag::Severity;
use crate::model::{LayoutMap, RegionKind};
use crate::plugin::{Decoded, FieldNode, FieldValue};

/// Width, in cells, of the proportional ASCII byte-map strip.
const STRIP_WIDTH: usize = 64;

/// Format a partition type, naming the two reserved values.
fn type_str(t: u32) -> String {
    match t {
        TYPE_RAW => format!("{t:#010x} (RAW)"),
        0 => format!("{t:#010x} (RESERVED)"),
        _ => format!("{t:#010x}"),
    }
}

fn verify_cell(ok: Option<bool>, pal: Palette) -> String {
    match ok {
        Some(true) => pal.green("OK"),
        Some(false) => pal.red("FAIL"),
        None => pal.dim("—"),
    }
}

/// The compact proportional strip: one glyph per `STRIP_WIDTH` slice of the file.
pub fn strip(layout: &LayoutMap, pal: Palette) -> String {
    if layout.file_len == 0 {
        return String::new();
    }
    let mut cells = vec!['.'; STRIP_WIDTH];
    for r in &layout.regions {
        if r.len == 0 {
            continue;
        }
        let start_cell = (r.start * STRIP_WIDTH as u64 / layout.file_len) as usize;
        let end_cell =
            ((r.end().saturating_sub(1)) * STRIP_WIDTH as u64 / layout.file_len) as usize;
        for cell in cells
            .iter_mut()
            .take(end_cell.min(STRIP_WIDTH - 1) + 1)
            .skip(start_cell)
        {
            *cell = r.kind.glyph();
        }
    }
    let bar: String = cells.into_iter().collect();
    format!(
        "{}\n[{}]\nlegend: H=header T=table-hdr E=entries D=data _=slack .=gap",
        pal.bold("byte map"),
        bar
    )
}

/// The region-by-region physical layout map.
pub fn layout(layout: &LayoutMap, pal: Palette) -> String {
    let mut out = String::new();
    out.push_str(&pal.bold("layout\n"));
    out.push_str(&format!("  file length: {} byte(s)\n", layout.file_len));
    for r in &layout.regions {
        let kind = match &r.kind {
            RegionKind::Gap => pal.yellow(r.kind.short()),
            RegionKind::Slack { .. } => pal.dim(r.kind.short()),
            _ => pal.cyan(r.kind.short()),
        };
        out.push_str(&format!(
            "  {:#010x}..{:#010x}  {:>8}  {:>11}  {}\n",
            r.start,
            r.end(),
            r.len,
            kind,
            r.label
        ));
    }
    out
}

/// The partition table.
pub fn table(layout: &LayoutMap, pal: Palette) -> String {
    let mut out = String::new();
    out.push_str(&pal.bold("partitions\n"));
    out.push_str(&pal.dim(
        "  type            uid        label             start       used/max (free)      algo     data\n",
    ));
    let mut any = false;
    for b in &layout.blocks {
        for ev in &b.entries {
            any = true;
            let e = &ev.entry;
            out.push_str(&format!(
                "  {:<14}  {:.8}…  {:<16}  {:>9}  {:>6}/{:<6} ({:>5})  {:<7}  {}\n",
                type_str(e.partition_type),
                uid_hex(&e.uid),
                label_or(e),
                e.start_offset,
                e.used_bytes,
                e.max_length,
                e.free_bytes(),
                algo_name(e.data_hash_algo),
                verify_cell(ev.data_hash_ok, pal),
            ));
        }
    }
    if !any {
        out.push_str(&pal.dim("  (no partitions)\n"));
    }
    out
}

/// The table-block chain as an indented tree.
pub fn chain(layout: &LayoutMap, pal: Palette) -> String {
    let mut out = String::new();
    out.push_str(&pal.bold("block chain\n"));
    if let Some(h) = layout.header {
        out.push_str(&format!(
            "  header: v{}.{}  first block @ {:#x}\n",
            h.version_major, h.version_minor, h.partition_table_offset
        ));
    }
    for b in &layout.blocks {
        let next = if b.next_offset == 0 {
            "end".to_string()
        } else {
            format!("{:#x}", b.next_offset)
        };
        let hash = match b.table_hash_ok {
            Some(true) => pal.green("hash OK"),
            Some(false) => pal.red("hash FAIL"),
            None => pal.dim("hash —"),
        };
        out.push_str(&format!(
            "  block {} @ {:#x}  count={}  next={}  {}  [{}]\n",
            b.index,
            b.offset,
            b.header.partition_count,
            next,
            hash,
            algo_name(b.header.table_hash_algo),
        ));
        for (i, ev) in b.entries.iter().enumerate() {
            let last = i + 1 == b.entries.len();
            let branch = if last { "└─" } else { "├─" };
            let valid = match &ev.validate_ok {
                Ok(()) => String::new(),
                Err(reason) => format!("  {}", pal.red(&format!("invalid: {reason}"))),
            };
            out.push_str(&format!(
                "    {branch} [{}] {} @ {:#x}{}\n",
                ev.slot,
                label_or(&ev.entry),
                ev.entry.start_offset,
                valid,
            ));
        }
    }
    out
}

/// Format a single field value as a one-line string.
fn value_str(v: &FieldValue) -> String {
    match v {
        FieldValue::None => String::new(),
        FieldValue::U64(n) => n.to_string(),
        FieldValue::Bytes(b) => {
            if b.is_empty() {
                "(empty)".into()
            } else {
                b.iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<Vec<_>>()
                    .join("")
            }
        }
        FieldValue::Text(s) => format!("\"{s}\""),
        FieldValue::Uid(u) => uid_hex(u),
        FieldValue::Enum { raw, name } => format!("{raw} ({name})"),
        FieldValue::Flags { raw, set } => {
            if set.is_empty() {
                format!("{raw:#x} (none)")
            } else {
                format!("{raw:#x} ({})", set.join("|"))
            }
        }
    }
}

fn field_tree(node: &FieldNode, prefix: &str, last: bool, out: &mut String, pal: Palette) {
    let branch = if last { "└─" } else { "├─" };
    let val = value_str(&node.value);
    let val_part = if val.is_empty() {
        String::new()
    } else {
        format!(" = {val}")
    };
    let range_part = match node.range {
        Some((a, b)) => pal.dim(&format!("  [{a}..{b}]")),
        None => String::new(),
    };
    let note_part = match &node.note {
        Some(n) => pal.dim(&format!("  // {n}")),
        None => String::new(),
    };
    out.push_str(&format!(
        "{prefix}{branch} {}{val_part}{range_part}{note_part}\n",
        pal.bold(&node.name)
    ));
    let child_prefix = format!("{prefix}{}", if last { "   " } else { "│  " });
    for (i, c) in node.children.iter().enumerate() {
        field_tree(c, &child_prefix, i + 1 == node.children.len(), out, pal);
    }
}

/// The decoded field trees for every partition (or a filtered subset).
pub fn decode(report: &Report, pal: Palette) -> String {
    let mut out = String::new();
    out.push_str(&pal.bold("decoded partitions\n"));
    if report.decoded.is_empty() {
        out.push_str(&pal.dim("  (nothing to decode)\n"));
        return out;
    }
    for (uid, dec) in &report.decoded {
        out.push_str(&format!(
            "  {} [{}]\n",
            pal.magenta(&format!("uid {}", &uid_hex(uid)[..16])),
            dec.format_name
        ));
        render_decoded_body(dec, "    ", &mut out, pal);
    }
    out
}

fn render_decoded_body(dec: &Decoded, prefix: &str, out: &mut String, pal: Palette) {
    for (i, f) in dec.fields.iter().enumerate() {
        field_tree(f, prefix, i + 1 == dec.fields.len(), out, pal);
    }
    for w in &dec.warnings {
        out.push_str(&format!("{prefix}{}\n", pal.yellow(&format!("⚠ {w}"))));
    }
}

/// The diagnostics footer.
pub fn diagnostics(layout: &LayoutMap, pal: Palette) -> String {
    let mut out = String::new();
    out.push_str(&pal.bold("diagnostics\n"));
    if layout.diagnostics.is_empty() {
        out.push_str(&pal.green("  no anomalies\n"));
        return out;
    }
    for d in &layout.diagnostics {
        let tag = match d.severity {
            Severity::Info => pal.dim(d.severity.tag()),
            Severity::Warning => pal.yellow(d.severity.tag()),
            Severity::Error => pal.red(d.severity.tag()),
        };
        out.push_str(&format!("  [{tag}] {}\n", d.message));
    }
    out
}

/// The default `inspect` view: strip, layout, table, chain, diagnostics.
pub fn inspect(report: &Report, pal: Palette) -> String {
    let l = &report.layout;
    let mut out = String::new();
    out.push_str(&strip(l, pal));
    out.push_str("\n\n");
    out.push_str(&layout(l, pal));
    out.push('\n');
    out.push_str(&table(l, pal));
    out.push('\n');
    out.push_str(&chain(l, pal));
    out.push('\n');
    out.push_str(&diagnostics(l, pal));
    out
}
