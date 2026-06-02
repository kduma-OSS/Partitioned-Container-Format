//! A self-contained HTML report: inline CSS, no JS framework, collapsible
//! sections via native `<details>`. Consumes the same [`Report`] as the text
//! renderer so the two never disagree.

use pcf::TYPE_RAW;

use super::{label_or, uid_hex, Report};
use crate::model::algo_name;
use crate::model::diag::Severity;
use crate::model::{LayoutMap, RegionKind};
use crate::plugin::{Decoded, FieldNode, FieldValue};

/// Escape the five characters that matter in HTML text/attribute context.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

const STYLE: &str = r#"
:root { color-scheme: light dark; }
body { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
       margin: 1.5rem; line-height: 1.4; }
h1 { font-size: 1.3rem; } h2 { font-size: 1.05rem; margin-top: 1.5rem; }
.bytemap { display: flex; width: 100%; height: 34px; border: 1px solid #8888;
           border-radius: 4px; overflow: hidden; margin: .5rem 0; }
.bytemap > div { min-width: 1px; }
.k-header { background: #4e79a7; } .k-tableheader { background: #59a14f; }
.k-entries { background: #76b7b2; } .k-data { background: #e15759; }
.k-slack { background: #bab0ac; } .k-gap {
    background: repeating-linear-gradient(45deg,#bbb,#bbb 4px,#ddd 4px,#ddd 8px); }
.legend span { display: inline-block; margin-right: .8rem; }
.legend i { display: inline-block; width: .8rem; height: .8rem; vertical-align: middle;
            margin-right: .25rem; border: 1px solid #8884; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0; }
th, td { border: 1px solid #8884; padding: .2rem .5rem; text-align: left;
         font-size: .85rem; }
th { background: #8881; }
.ok { color: #2a8; } .fail { color: #c33; font-weight: bold; } .muted { color: #999; }
details { margin: .3rem 0; } summary { cursor: pointer; }
ul.fields { list-style: none; padding-left: 1.1rem; border-left: 1px dotted #8886; }
.fname { font-weight: bold; } .frange { color: #999; font-size: .8rem; }
.fnote { color: #999; font-style: italic; }
.warn { color: #b80; } .diag-info { color: #888; } .diag-warn { color: #b80; }
.diag-error { color: #c33; }
"#;

fn kind_class(kind: &RegionKind) -> &'static str {
    match kind {
        RegionKind::FileHeader => "k-header",
        RegionKind::TableBlockHeader { .. } => "k-tableheader",
        RegionKind::EntryArray { .. } => "k-entries",
        RegionKind::PartitionData { .. } => "k-data",
        RegionKind::Slack { .. } => "k-slack",
        RegionKind::Gap => "k-gap",
    }
}

fn byte_map(l: &LayoutMap) -> String {
    let mut out = String::from("<div class=\"bytemap\">");
    if l.file_len > 0 {
        for r in &l.regions {
            if r.len == 0 {
                continue;
            }
            let pct = r.len as f64 / l.file_len as f64 * 100.0;
            out.push_str(&format!(
                "<div class=\"{}\" style=\"flex-grow:{:.4}\" title=\"{}\"></div>",
                kind_class(&r.kind),
                pct,
                esc(&format!(
                    "{:#x}..{:#x} ({} B) {}",
                    r.start,
                    r.end(),
                    r.len,
                    r.label
                ))
            ));
        }
    }
    out.push_str("</div>");
    out.push_str(
        "<div class=\"legend\">\
         <span><i class=\"k-header\"></i>header</span>\
         <span><i class=\"k-tableheader\"></i>table header</span>\
         <span><i class=\"k-entries\"></i>entries</span>\
         <span><i class=\"k-data\"></i>data</span>\
         <span><i class=\"k-slack\"></i>slack</span>\
         <span><i class=\"k-gap\"></i>gap</span>\
         </div>",
    );
    out
}

fn type_str(t: u32) -> String {
    match t {
        TYPE_RAW => format!("{t:#010x} (RAW)"),
        0 => format!("{t:#010x} (RESERVED)"),
        _ => format!("{t:#010x}"),
    }
}

fn partition_table(l: &LayoutMap) -> String {
    let mut out = String::from(
        "<table><tr><th>type</th><th>uid</th><th>label</th><th>start</th>\
         <th>used</th><th>max</th><th>free</th><th>algo</th><th>data</th></tr>",
    );
    for b in &l.blocks {
        for ev in &b.entries {
            let e = &ev.entry;
            let verify = match ev.data_hash_ok {
                Some(true) => "<span class=\"ok\">OK</span>",
                Some(false) => "<span class=\"fail\">FAIL</span>",
                None => "<span class=\"muted\">—</span>",
            };
            out.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
                 <td>{}</td><td>{}</td><td>{}</td><td>{verify}</td></tr>",
                esc(&type_str(e.partition_type)),
                esc(&uid_hex(&e.uid)),
                esc(&label_or(e)),
                e.start_offset,
                e.used_bytes,
                e.max_length,
                e.free_bytes(),
                algo_name(e.data_hash_algo),
            ));
        }
    }
    out.push_str("</table>");
    out
}

fn value_html(v: &FieldValue) -> String {
    match v {
        FieldValue::None => String::new(),
        FieldValue::U64(n) => n.to_string(),
        FieldValue::Bytes(b) => {
            if b.is_empty() {
                "(empty)".into()
            } else {
                b.iter().map(|x| format!("{x:02x}")).collect::<String>()
            }
        }
        FieldValue::Text(s) => format!("&quot;{}&quot;", esc(s)),
        FieldValue::Uid(u) => uid_hex(u),
        FieldValue::Enum { raw, name } => format!("{raw} ({})", esc(name)),
        FieldValue::Flags { raw, set } => {
            if set.is_empty() {
                format!("{raw:#x} (none)")
            } else {
                format!("{raw:#x} ({})", esc(&set.join("|")))
            }
        }
    }
}

fn field_node(node: &FieldNode, out: &mut String) {
    out.push_str("<li>");
    out.push_str(&format!("<span class=\"fname\">{}</span>", esc(&node.name)));
    let v = value_html(&node.value);
    if !v.is_empty() {
        out.push_str(&format!(" = {v}"));
    }
    if let Some((a, b)) = node.range {
        out.push_str(&format!(" <span class=\"frange\">[{a}..{b}]</span>"));
    }
    if let Some(n) = &node.note {
        out.push_str(&format!(" <span class=\"fnote\">// {}</span>", esc(n)));
    }
    if !node.children.is_empty() {
        out.push_str("<ul class=\"fields\">");
        for c in &node.children {
            field_node(c, out);
        }
        out.push_str("</ul>");
    }
    out.push_str("</li>");
}

fn decoded_section(uid: &[u8; 16], dec: &Decoded) -> String {
    let mut out = format!(
        "<details><summary>uid {} — {}</summary>",
        esc(&uid_hex(uid)),
        esc(&dec.format_name)
    );
    out.push_str("<ul class=\"fields\">");
    for f in &dec.fields {
        field_node(f, &mut out);
    }
    out.push_str("</ul>");
    for w in &dec.warnings {
        out.push_str(&format!("<div class=\"warn\">⚠ {}</div>", esc(w)));
    }
    out.push_str("</details>");
    out
}

fn diagnostics_section(l: &LayoutMap) -> String {
    if l.diagnostics.is_empty() {
        return "<p class=\"ok\">no anomalies</p>".into();
    }
    let mut out = String::from("<ul>");
    for d in &l.diagnostics {
        let cls = match d.severity {
            Severity::Info => "diag-info",
            Severity::Warning => "diag-warn",
            Severity::Error => "diag-error",
        };
        out.push_str(&format!(
            "<li class=\"{cls}\">[{}] {}</li>",
            d.severity.tag(),
            esc(&d.message)
        ));
    }
    out.push_str("</ul>");
    out
}

/// Render the whole report as a single self-contained HTML document.
pub fn render(report: &Report, title: &str) -> String {
    let l = &report.layout;
    let mut body = String::new();
    body.push_str(&format!("<h1>PCF report: {}</h1>", esc(title)));
    if let Some(h) = l.header {
        body.push_str(&format!(
            "<p>version {}.{} · first block @ {:#x} · file length {} B</p>",
            h.version_major, h.version_minor, h.partition_table_offset, l.file_len
        ));
    }

    body.push_str("<h2>byte map</h2>");
    body.push_str(&byte_map(l));

    body.push_str("<h2>partitions</h2>");
    body.push_str(&partition_table(l));

    body.push_str("<h2>decoded partitions</h2>");
    if report.decoded.is_empty() {
        body.push_str("<p class=\"muted\">(nothing to decode)</p>");
    } else {
        for (uid, dec) in &report.decoded {
            body.push_str(&decoded_section(uid, dec));
        }
    }

    body.push_str("<h2>diagnostics</h2>");
    body.push_str(&diagnostics_section(l));

    format!(
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{}</title><style>{STYLE}</style></head><body>{body}</body></html>\n",
        esc(title)
    )
}
