# pcf-dcp — PCF Dynamic Container Partition (reference implementation)

Reference reader/writer for **PCF-DCP v1.0**, an application-level profile that
adds *dynamic*, fragmentable, dedup-friendly sub-partitions to the
[Partitioned Container Format](../PCF-v1.0) without modifying the PCF byte
container.

This crate mirrors the written specification (`specs/PCF-DCP-spec-v1.0.txt`)
field-for-field and is intended as the *normative* implementation against which
language ports are checked. It favours auditability over performance.

## Model at a glance

PCF-DCP defines one new PCF partition type:

| Type         | Name            | Holds                                              |
|--------------|-----------------|----------------------------------------------------|
| `0xAAAC0001` | `DCP_CONTAINER` | An *arena*: a header, an inner partition table, fragment tables, and data extents |

A DCP container's bytes are an **arena** addressed by arena-relative offsets:

```
arena:
[ DCP Header (24 B) | data extents | Fragment Tables | Inner Table Block(s) ]
```

* **DCP Header** — `"PDCP"` magic, profile version, `inner_table_offset`,
  `arena_used` (a bump pointer).
* **Inner Table Block** — a chain of reused PCF Table Blocks (74 B header +
  141 B entries), byte-for-byte identical to the top-level table, listing the
  *inner* partitions. Two entry fields are reinterpreted: `start_offset` points
  at the partition's Fragment Table, and `max_length` equals `used_bytes`.
* **Fragment Table** — per inner partition, a chain of 9-byte block headers each
  followed by 18-byte **Fragment Entries**. Each entry names one extent
  `(offset, length, kind, flags)`. The logical content of an inner partition is
  the concatenation of its DATA extents.

A generic PCF reader sees a DCP file as **one opaque partition**; only a
DCP-aware reader looks inside. A DCP file is always a conforming PCF v1.0 file.

## Why a profile

PCF stores each partition as a contiguous, statically-reserved region. PCF-DCP
makes each *inner* partition grow, shrink, and be edited in the middle without
relocating its neighbours, by describing it as a list of extents rather than one
range. This buys:

* **Fragmentation / random edits** — append, insert, overwrite, delete, and
  truncate are edits of the Fragment Table (copy-on-write for shared bytes); no
  data is moved.
* **Deduplication** — two extents may name the same arena bytes; identical
  chunks are stored once. The per-extent `SHARED` flag makes safe in-place
  editing explicit.
* **Hash / signature stability** — an inner partition's `data_hash` covers its
  *logical content*, so fragmentation, dedup, compaction, and promotion all
  leave the hash (and any PCF-SIG signature over it) unchanged.

## Library example

```rust
use std::io::Cursor;
use pcf_dcp::{Arena, Chunker, DcpReader, DcpWriter, HashAlgo};

let mut arena = Arena::new();
arena.add_inner(0x10, [0xA1; 16], "A", b"Hello, World!", HashAlgo::Sha256, Chunker::Fixed(7))?;
arena.add_inner(0x10, [0xB2; 16], "B", b"World!", HashAlgo::Sha256, Chunker::Whole)?;

let mut w = DcpWriter::new();
w.add_container([0xDC; 16], "dcp", arena)?;
let image = w.to_image()?;

let mut r = DcpReader::open(Cursor::new(image))?;
r.verify()?;
assert_eq!(r.read_inner(&[0xB2; 16])?, b"World!");
# Ok::<(), pcf_dcp::Error>(())
```

## Promotion / demotion

`DcpWriter::promote` moves an inner partition out to a top-level PCF partition
(dynamic → fixed); `demote` moves a top-level partition into a container
(fixed → dynamic). Both preserve `uid`, `partition_type`, `label`,
`data_hash_algo_id`, and `data_hash` — the **promotion invariant**, identical to
the set of fields a PCF-SIG signature protects.

## Command-line tool

The `dcp` binary inspects and rewrites DCP files; every mutating command
re-verifies before writing:

```
dcp info    <file>
dcp dedup   <file> [--fixed N] [--trailer]
dcp defrag  <file> [--trailer]
dcp promote <file> <container-uid> <inner-uid> [--trailer]
dcp demote  <file> <part-uid> <container-uid> [--trailer]
```

UIDs are 32 hex digits, or `0xNN` for a uid of 16 identical bytes (e.g. `0xDC`).

## Build & test

```
cargo test -p pcf-dcp
cargo run -p pcf-dcp --example gen_testvector -- /tmp/dcp.bin   # the 700-byte vector
cargo run -p pcf-dcp --bin dcp -- info /tmp/dcp.bin
```

The example reproduces the byte-exact 700-byte test vector from Section 17 of
the specification.

## Relationship to `pcf`

This crate is layered strictly above [`pcf`](../PCF-v1.0): every container byte
operation goes through the reference PCF crate, and the arena reuses PCF's Table
Block, Partition Entry, and table-hash primitives directly.

## Licence

MIT OR Apache-2.0.
