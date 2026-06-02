//! Structural smoke tests for the HTML report: it must be well-formed enough to
//! open, contain a byte-map cell per non-empty region, and embed the decoded
//! field trees.

mod common;

use pcf_debug::build_report;
use pcf_debug::plugin::DecoderRegistry;
use pcf_debug::render::html;

fn balanced(tag: &str, html: &str) -> bool {
    html.matches(&format!("<{tag}")).count() == html.matches(&format!("</{tag}>")).count()
}

#[test]
fn report_is_structurally_sound() {
    let data = common::canonical();
    let report = build_report(&data, true, &DecoderRegistry::with_builtins());
    let out = html::render(&report, "tv.pcf");

    assert!(out.starts_with("<!DOCTYPE html>"));
    assert!(out.contains("<title>tv.pcf</title>"));
    assert!(out.contains("class=\"bytemap\""));
    assert!(out.contains("PCF report"));
    // Both partitions appear in the table.
    assert!(out.contains("alpha"));
    assert!(out.contains("raw"));
    // Tags that must be balanced.
    for tag in [
        "html", "head", "body", "table", "details", "ul", "div", "style",
    ] {
        assert!(balanced(tag, &out), "unbalanced <{tag}> in HTML");
    }
}

#[test]
fn bytemap_has_one_cell_per_nonempty_region() {
    let data = common::canonical();
    let report = build_report(&data, true, &DecoderRegistry::with_builtins());
    let nonempty = report.layout.regions.iter().filter(|r| r.len > 0).count();
    let out = html::render(&report, "tv.pcf");
    // Each region cell carries a flex-grow style; the legend swatches do not.
    let cells = out.matches("flex-grow:").count();
    assert_eq!(
        cells, nonempty,
        "one byte-map cell expected per non-empty region"
    );
}

#[test]
fn pfs_records_render_field_trees() {
    let parts = vec![
        (
            0xAAAA_0001u32,
            [0xA1u8; 16],
            "node",
            common::pfs_node_direct("a.txt"),
        ),
        (
            0xAAAA_0002u32,
            [0xA2u8; 16],
            "sess",
            common::pfs_session("w"),
        ),
    ];
    let data = common::wrap(&parts);
    let report = build_report(&data, true, &DecoderRegistry::with_builtins());
    let out = html::render(&report, "pfs.pcf");
    assert!(out.contains("PFS_NODE"));
    assert!(out.contains("PFS_SESSION"));
    assert!(out.contains("content_kind"));
    assert!(out.contains("session_seq"));
}
