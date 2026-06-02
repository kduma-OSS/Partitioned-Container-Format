# pcf — Partitioned Container Format (reference implementation)

Reference reader/writer for **PCF v1.0**, a language-agnostic binary container
that stores multiple independent byte regions ("partitions") in one file.

This crate mirrors the written specification (`PCF-spec-v1.0.txt`)
field-for-field and is intended as the *normative* implementation against which
ports (C#, then PHP and TypeScript) are checked. It favours auditability over
performance.

## Layout

```
[ 20-byte header ] [ table block(s) ] [ partition data regions ]
```

* **Header** (20 B): magic `0x89 K P R T 0x0D 0x0A 0x1A`, major/minor version,
  absolute offset of the first table block.
* **Table block**: 74-byte header (`partition_count`, `next_table_offset`,
  hash algo + 64-byte block hash) followed by `partition_count` entries.
  Blocks form a singly linked chain to hold more than 255 partitions.
* **Entry** (141 B): `type`, 16-byte UID, 32-byte ASCII label, `start_offset`,
  `max_length`, `used_bytes`, 1-byte data-hash algorithm, 64-byte data hash.

All integers are little-endian. Free space is `max_length - used_bytes`.

## Hash registry

| id | algorithm        | id | algorithm |
|----|------------------|----|-----------|
| 0  | none             | 5  | SHA-1     |
| 1  | CRC-32/ISO-HDLC  | 16 | SHA-256 (default) |
| 2  | CRC-32C          | 17 | SHA-512   |
| 3  | CRC-64/XZ        | 18 | BLAKE3    |
| 4  | MD5              |    |           |

## Usage

```rust
use std::io::Cursor;
use pcf::{Container, HashAlgo};

let mut c = Container::create(Cursor::new(Vec::new()))?;
c.add_partition(0x10, [1u8; 16], "notes", b"hello", 64, HashAlgo::Sha256)?;
c.verify()?;
# Ok::<(), pcf::Error>(())
```

`Container<S>` works with any `Read + Write + Seek` backing store
(`std::fs::File`, `std::io::Cursor<Vec<u8>>`, …).

## Tests

The crate is laid out as a standard Cargo project:

```
reference/PCF-v1.0/
├── Cargo.toml
├── src/                 # library sources
├── tests/
│   ├── roundtrip.rs     # end-to-end black-box tests
│   ├── coverage.rs      # targeted error-path / edge-case tests
│   └── spec_compliance.rs   # one test per normative MUST/SHALL in the spec
└── examples/
    └── gen_testvector.rs    # produces the canonical 395-byte spec test vector
```

Run from this directory:

```
cargo test                              # all unit + integration + doc tests
cargo run --example gen_testvector      # writes pcf_testvector.bin
cargo llvm-cov                          # line coverage (requires cargo-llvm-cov)
```

CI (`.github/workflows/ci.yml`) runs `cargo fmt --check`, `cargo clippy -D
warnings`, `cargo test` on Linux/macOS/Windows, the test-vector example, and
`cargo llvm-cov` with a 95% line / 100% function coverage floor.
