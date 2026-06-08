# pfs-ms — PFS-MS v1.0 (reference implementation)

Reference reader/writer for **PFS-MS v1.0** (PCF File System, Multi-Session
Profile): an append-only, multi-session tree of files and directories stored
inside a single **PCF v1.0** file.

This crate mirrors the written specification (`specs/PFS-MS-spec-v1.0.txt`)
field-for-field and builds entirely on the [`pcf`](../PCF-v1.0) reference crate.
It favours auditability over performance.

PFS-MS is layered *strictly above* PCF: **a PFS-MS file is a fully conforming
PCF file**. A generic PCF reader sees a valid flat set of partitions and
verifies every `table_hash`/`data_hash`; it simply does not reconstruct the
tree. PFS-MS adds no new container mechanics — it uses two application partition
types, the PCF RAW type, PCF's flexible `next_table_offset`, and the single
in-place header-pointer rewrite that PCF already permits.

## Model

* File **content** lives in PCF **RAW** partitions (`0xFFFFFFFF`): either the
  full bytes (DIRECT) or a VCDIFF patch (DELTA) against the previous version,
  in either case **optionally compressed** (see below).
* **Node** metadata lives in **PFS_NODE** partitions (`0xAAAA0001`): one
  declarative snapshot of a file/directory per session it changed in.
* **Session** metadata lives in **PFS_SESSION** partitions (`0xAAAA0002`): one
  per session, carrying the inter-session hash chain.

Each session appends new bytes and **backward-links** its Table Block(s) to the
previous session's HEAD block (newest → oldest). Committing a session writes all
data and blocks beyond the live chain, then atomically rewrites the 8-byte
`partition_table_offset` in the PCF header — the only in-place mutation
(Section 4.3). A reader walks the chain from the head, groups blocks into
sessions, and resolves the newest record per node (newest wins).

```
header.partition_table_offset --> HEAD(newest) --> ... --> HEAD(oldest) --> 0
```

## Partition types and magics

| value        | name        | data                                   |
|--------------|-------------|----------------------------------------|
| `0xAAAA0001` | PFS_NODE    | one Node Record  (magic `"PFSN"`)      |
| `0xAAAA0002` | PFS_SESSION | one Session Record (magic `"PFSS"`)    |
| `0xFFFFFFFF` | RAW         | file content: full bytes or a patch    |

## Compression (Section 9.5)

The bytes stored in a DIRECT content partition (the full content) or a DELTA
patch partition (the patch) may be compressed. The content section carries a
`compression_algo_id`; DIRECT is 91 bytes and DELTA is 165 bytes (one byte more
than the uncompressed-only draft). The writer DEFLATEs the bytes and stores the
compressed form only when it is smaller, else stores them verbatim.

| id | algorithm | notes |
|----|-----------|-------|
| 0  | none      | stored verbatim (required) |
| 1  | DEFLATE   | RFC 1951, the required default (pure-Rust `flate2`/miniz_oxide) |
| 2  | zstd      | reserved |
| 3  | brotli    | reserved |

Integrity layers cleanly: the PCF `data_hash` protects the **stored
(compressed)** bytes; `full_hash`/`full_size` protect the **decompressed**
content. An unknown `compression_algo_id` makes a file *unreadable* but not the
container *malformed* (the same rule as an unknown `patch_algo_id`).

> This revision changes the v1.0 content-section layout and is intentionally
> **not** compatible with files written by earlier drafts.

## Library usage

```rust
use std::io::Cursor;
use pcf::HashAlgo;
use pfs_ms::{FsReader, FsWriter};

let mut w = FsWriter::mkfs(Cursor::new(Vec::new()), HashAlgo::Sha256)?;
w.mkdir("docs")?;
w.put_file("docs/hello.txt", b"Hello\n")?;          // DIRECT
w.put_file("docs/hello.txt", b"Hello, world\n")?;   // DELTA (auto)
let bytes = w.into_storage().into_inner();

let mut r = FsReader::open(Cursor::new(bytes))?;
r.verify()?;                                         // incl. inter-session chain
assert_eq!(r.read_path("docs/hello.txt")?, b"Hello, world\n");
// History query "as of" an earlier session (Section 15):
assert_eq!(r.read_path_as_of("docs/hello.txt", Some(2))?, b"Hello\n");
# Ok::<(), pfs_ms::Error>(())
```

`FsReader<S>`/`FsWriter<S>` work with any `Read + Write + Seek` backing store
(`std::fs::File`, `std::io::Cursor<Vec<u8>>`, …). VCDIFF (RFC 3284) deltas are
provided by the pure-Rust [`oxidelta`](https://crates.io/crates/oxidelta) crate
and DEFLATE compression by [`flate2`](https://crates.io/crates/flate2)
(miniz_oxide backend); node/uid identities use UUIDv7.

## CLI

A small demo CLI (`pfs`) drives whole sessions end to end:

```
cargo run --bin pfs -- mkfs   fs.pfs
cargo run --bin pfs -- mkdir  fs.pfs docs
echo hi | cargo run --bin pfs -- put fs.pfs docs/hello.txt -
cargo run --bin pfs -- put    fs.pfs docs/hello.txt ./bigger.bin
cargo run --bin pfs -- put    fs.pfs docs/raw.bin ./data.bin --store  # no compression
cargo run --bin pfs -- mv     fs.pfs docs documents
cargo run --bin pfs -- rm     fs.pfs documents/hello.txt
cargo run --bin pfs -- ls     fs.pfs
cargo run --bin pfs -- log    fs.pfs
cargo run --bin pfs -- verify fs.pfs
```

### Directory commands

Whole-directory import/export. Each `create` and `update` is committed as a
**single session** (one "burn"), not one session per file.

```
# Create a new archive from a directory tree (fails if the archive exists).
cargo run --bin pfs -- create  backup.pfs ./project

# Update it from the directory: add new files, update changed ones. With
# --delete it mirrors (tombstones archive entries no longer in the source).
cargo run --bin pfs -- update  backup.pfs ./project
cargo run --bin pfs -- update  backup.pfs ./project --delete

# Extract the whole tree to a directory, optionally at a point in time.
cargo run --bin pfs -- extract backup.pfs ./restore
cargo run --bin pfs -- extract backup.pfs ./restore --at 2          # by session_seq
cargo run --bin pfs -- extract backup.pfs ./restore --at-time 1700000000000
```

### Compaction

`pfs compact` rebuilds a multi-session file into a single fresh session holding
the current tree, **discarding history** (Section 15): deleted nodes are gone,
superseded versions and delta chains collapse to the newest full content, and
abandoned tails are reclaimed. The output is a fully valid, verifiable PFS-MS
file. (Generic `pcf-compact` must *not* be used on a PFS-MS file — it would
corrupt the session chain.)

```
cargo run --bin pfs -- compact fs.pfs            # in place
cargo run --bin pfs -- compact fs.pfs out.pfs    # to a new file
```

POSIX permission bits and modification time are captured on import and restored
on extract; pass `--no-metadata` (on either side) to skip this, and `--store` to
disable compression. Symlinks and other non-regular files are skipped with a
warning.

### Signing (PCF-SIG)

`pfs` can sign archives with [PCF-SIG](../PCF-SIG-v1.0) (Ed25519). Because
PFS-MS is append-only with a backward-linked session chain, a signature is
**committed as its own PFS session** carrying the `PCFSIG_KEY` / `PCFSIG_SIG`
partitions — not appended out of band — so `verify` keeps working.

```
# Generate a keypair (delegates to the pcf-sig tool).
cargo run --bin pfs -- keygen id.key id.pub

# Sign content + node records not yet signed by this key (incremental).
cargo run --bin pfs -- sign       fs.pfs --key id.key          # no-op if nothing new
cargo run --bin pfs -- sign       fs.pfs --key id.key --resign # re-sign everything

# Verify embedded signatures (optionally assert a trusted public key).
cargo run --bin pfs -- verify-sig fs.pfs --key id.pub
```

Every mutating command (`mkfs`, `mkdir`, `put`, `mv`, `rm`, `create`, `update`)
also accepts `--key <priv>` to **auto-sign** right after its commit, so each
operation adds one signature covering just the partitions it introduced:

```
cargo run --bin pfs -- mkfs fs.pfs --key id.key
echo hi | cargo run --bin pfs -- put fs.pfs hello.txt - --key id.key
```

Signatures cover file content and node records; PFS-MS's own inter-session hash
chain (checked by `verify`) already makes session records tamper-evident.

## Layout

```
reference/PFS-MS-v1.0/
├── Cargo.toml
├── src/
│   ├── lib.rs       # crate root + re-exports
│   ├── consts.rs    # on-disk constants (Appendix B)
│   ├── node.rs      # PFS_NODE record + content sections (Section 7)
│   ├── session.rs   # PFS_SESSION record + hash-chain helpers (Section 8)
│   ├── delta.rs     # VCDIFF wrapper (Section 9.2)
│   ├── compress.rs  # DEFLATE wrapper + registry (Section 9.5)
│   ├── writer.rs    # append-only session writer (Sections 4, 6, 12)
│   ├── reader.rs    # backward-chain scan + node view (Sections 8, 10, 11)
│   ├── tree.rs      # liveness, tree, reconstruction (Sections 9.3, 10)
│   ├── fs.rs        # high-level FsReader
│   ├── dirsync.rs   # directory <-> archive tooling (create/update/extract)
│   ├── compact.rs   # single-session compaction (Section 15)
│   ├── vector.rs    # canonical Section 17 reference vector
│   └── bin/pfs.rs   # demo CLI
├── tests/
│   ├── roundtrip.rs       # end-to-end black-box tests
│   ├── coverage.rs        # targeted error-path / edge-case tests
│   ├── dirsync.rs         # directory create/update/extract round-trips
│   ├── compact.rs         # single-session compaction round-trips
│   └── spec_compliance.rs # one test per normative MUST (R1..R8, W2/W3)
└── examples/
    └── gen_testvector.rs  # writes pfs_ms_testvector.bin + hex dumps
```

## Tests

```
cargo test                          # unit + integration + doc tests
cargo run --example gen_testvector  # writes pfs_ms_testvector.bin (2986 bytes)
cargo llvm-cov --ignore-filename-regex 'bin/|examples/'   # library coverage
```

CI (`.github/workflows/ci-pfs.yml`) runs `cargo fmt --check`, `cargo clippy -D
warnings`, `cargo test` on Linux/macOS/Windows, the test-vector example, and
`cargo llvm-cov` with a library line/function floor (the `pfs` CLI is exercised
manually, so it is excluded from the coverage gate).

## Relationship to PCF

This crate uses only the **public** PCF primitives — `FileHeader`,
`TableBlockHeader`, `PartitionEntry`, `compute_table_hash`, `HashAlgo`,
`encode_label`, and `Container::read_block_at` (a read-only per-block walker).
It never uses PCF's in-place `Container` *writer*, because PFS-MS requires
backward-linked blocks and a single header-pointer rewrite at commit. The only
addition made to the PCF crate for this profile is the additive, read-only
`read_block_at`/`BlockView` API.
