# `pcf-debug`

A read-only inspector and visualiser for **Partitioned Container Format (PCF)**
files. It walks a file's physical structure, renders the byte layout and
partition table as text or as a self-contained HTML report, and decodes
partition contents into field trees through a small plugin system.

It is built on the reference [`pcf`](../../reference/PCF-v1.0) crate and reuses
its byte parsers, so it never re-implements the format — but unlike
`pcf::Container`, it walks the table-block chain directly and tolerates corrupt
files, surfacing anomalies as diagnostics instead of erroring out.

## Build & run

From the repository root (a Cargo workspace ties the tool to the reference
crate):

```sh
# build
cargo build -p pcf-debug

# produce a sample file to look at
cargo run -p pcf --example gen_testvector -- /tmp/tv.pcf

# inspect it
cargo run -p pcf-debug -- /tmp/tv.pcf
```

## Usage

```text
pcf-debug <FILE> [SUBCOMMAND] [FLAGS]

SUBCOMMANDS:
  inspect   (default) byte map + layout + partition table + chain + diagnostics
  layout    physical region map only
  table     partition table only
  chain     table-block chain tree only
  hexdump   hexdump regions or an explicit byte range
  decode    run partition decoders and print field trees

GLOBAL FLAGS:
  --html <FILE>     also write a self-contained HTML report
  --no-color        disable ANSI colour (auto-off when stdout is not a TTY)
  --verify          compute and check hashes (default for inspect)
  --no-verify       skip hashing (fast path for large files)
  -h, --help        show help

HEXDUMP FLAGS:
  --region <NAME>   limit to regions matching a kind/label/uid substring
  --range <S[:L]>   hexdump bytes [S, S+L) (decimal or 0x-hex); L defaults to EOF
  --max-bytes <N>   cap bytes shown per region (default 512)

DECODE FLAGS:
  --uid <HEX>       decode only the partition whose UID starts with HEX
  --label <S>       decode only partitions whose label contains S
  --decoder <NAME>  force a decoder (e.g. pfs-node, pfs-session, raw)
```

### Examples

```sh
# graphical HTML report
pcf-debug archive.pcf --html report.html

# hexdump just the data regions
pcf-debug archive.pcf hexdump --region data

# decode a PFS-MS file system image into field trees
pcf-debug fs.pcf decode
```

## What it shows

- **Byte map** — a proportional strip (text) or coloured bar (HTML) of every
  physical region: header, table-block headers, entry arrays, partition data,
  reserved slack, and gaps.
- **Partition table** — type, UID, label, offsets, used/max/free, hash algorithm,
  and per-partition data-hash verification.
- **Block chain** — each table block's offset, entry count, chain link, and
  table-hash status, including backward links and chain end.
- **Diagnostics** — gaps, overlaps, truncated regions, chain cycles, and hash
  mismatches, by severity.
- **Decoded partitions** — field trees produced by the plugin decoders.
  *Container* decoders also decode what they contain: a `DCP_CONTAINER`
  (`0xAAAC0001`) reconstructs each inner partition's logical content and routes
  it back through the registry, nesting the result under a *decoded inner
  partitions* group (e.g. an inner `PFS_NODE` is shown as a full PFS field tree).

## Writing a decoder plugin

Decoders are registered statically (compiled in). A decoder turns a partition's
raw bytes into a renderer-agnostic [`FieldNode`] tree that both the text and HTML
renderers display.

1. Implement the [`PartitionDecoder`] trait in a new module under
   `src/plugin/`:

   ```rust
   use crate::plugin::{Decoded, FieldNode, FieldValue, PartitionDecoder, PartitionMeta};

   pub struct MyDecoder;

   impl PartitionDecoder for MyDecoder {
       fn name(&self) -> &'static str { "my-format" }

       fn matches(&self, meta: &PartitionMeta, data: &[u8]) -> bool {
           meta.partition_type == 0x1234_5678 || data.starts_with(b"MYFMT")
       }

       fn decode(&self, _meta: &PartitionMeta, data: &[u8]) -> Decoded {
           let mut warnings = Vec::new();
           let mut fields = Vec::new();
           // ... read fields defensively; never panic ...
           fields.push(FieldNode::leaf(
               "magic",
               FieldValue::Text("MYFMT".into()),
               (0, 5),
           ));
           Decoded { format_name: "MY_FORMAT".into(), fields, warnings }
       }
   }
   ```

2. Register it ahead of the raw fallback in
   `DecoderRegistry::with_builtins` (`src/plugin/mod.rs`), or at runtime with
   `registry.register(Box::new(MyDecoder))`.

The first decoder whose `matches` returns true wins; `raw` is always last and
matches everything. `decode` must be infallible — on malformed input, return the
fields you could read plus `warnings`.

A *container* decoder may also override the optional `children` method to return
the sub-partitions it holds (each as a `DecodedChild` carrying a reconstructed
content blob). The pipeline decodes those recursively and nests them under the
parent — see `dcp-container` (`src/plugin/dcp.rs`).

The built-in `pfs-node` and `pfs-session` decoders (`src/plugin/pfs.rs`) are a
complete worked example covering the PFS-MS record formats.

[`PartitionDecoder`]: src/plugin/mod.rs
[`FieldNode`]: src/plugin/mod.rs

## Tests

```sh
cargo test -p pcf-debug
```

Tests build the canonical 395-byte spec vector and hand-built PFS-MS records as
fixtures, then assert the text snapshots, HTML structure, decoder field trees,
and diagnostics for deliberately corrupted files.
