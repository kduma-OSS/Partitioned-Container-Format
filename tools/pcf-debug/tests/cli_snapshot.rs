//! Snapshot-style tests for the text renderer, run with colour disabled so the
//! output is a stable string.

mod common;

use pcf_debug::build_report;
use pcf_debug::plugin::DecoderRegistry;
use pcf_debug::render::color::Palette;
use pcf_debug::render::text;

fn report(data: &[u8]) -> pcf_debug::render::Report {
    build_report(data, true, &DecoderRegistry::with_builtins())
}

#[test]
fn layout_of_canonical_is_exact() {
    let data = common::canonical();
    assert_eq!(
        data.len(),
        395,
        "fixture must be the canonical 395-byte vector"
    );
    let r = report(&data);
    let out = text::layout(&r.layout, Palette::new(false));
    let expected = "\
layout
  file length: 395 byte(s)
  0x00000000..0x00000014        20       header  file header
  0x00000014..0x0000005e        74  tableheader  block 0 header
  0x0000005e..0x00000178       282      entries  block 0 entries (x2)
  0x00000178..0x00000183        11         data  data: alpha
  0x00000183..0x0000018b         8         data  data: raw
";
    assert_eq!(out, expected);
}

#[test]
fn strip_has_no_gaps_for_compacted_file() {
    let data = common::canonical();
    let r = report(&data);
    let out = text::strip(&r.layout, Palette::new(false));
    // A compacted file is fully covered: the bar contains no gap glyph.
    let bar = out.lines().nth(1).unwrap();
    assert!(bar.starts_with('['));
    assert!(
        !bar.contains('.'),
        "compacted file should have no gaps: {bar}"
    );
}

#[test]
fn table_lists_both_partitions_and_verifies() {
    let data = common::canonical();
    let r = report(&data);
    let out = text::table(&r.layout, Palette::new(false));
    assert!(out.contains("alpha"));
    assert!(out.contains("raw"));
    assert!(out.contains("sha256"));
    assert!(out.contains("crc32c"));
    assert!(out.contains("OK"));
    assert!(!out.contains("FAIL"));
}

#[test]
fn chain_shows_single_block_ending_chain() {
    let data = common::canonical();
    let r = report(&data);
    let out = text::chain(&r.layout, Palette::new(false));
    assert!(out.contains("block 0 @ 0x14"));
    assert!(out.contains("count=2"));
    assert!(out.contains("next=end"));
    assert!(out.contains("hash OK"));
}

#[test]
fn inspect_reports_no_anomalies() {
    let data = common::canonical();
    let r = report(&data);
    let out = text::inspect(&r, Palette::new(false));
    assert!(out.contains("no anomalies"));
}
