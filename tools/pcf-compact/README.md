# `pcf-compact`

A compactor for **Partitioned Container Format (PCF)** files. It rebuilds a
container with all dead space removed and every partition's reservation
trimmed to its `used_bytes`, exactly as defined by spec section 11.5.

The tool is a thin wrapper around the reference [`pcf`](../../reference/PCF-v1.0)
crate's `Container::compacted_image` — the algorithm lives there. What this
crate adds is a CLI, safe atomic file replacement, and a savings report.

## Build & run

From the repository root:

```sh
# build
cargo build -p pcf-compact

# produce a sample file
cargo run -p pcf --example gen_testvector -- /tmp/tv.pcf

# compact it in place
cargo run -p pcf-compact -- /tmp/tv.pcf
```

## Usage

```text
pcf-compact <FILE> [FLAGS]

FLAGS:
    -o, --output <PATH>   write the compacted file to PATH instead of
                          overwriting <FILE> in place
        --no-verify       skip integrity verification before and after
                          compaction (default: verify both)
        --force           overwrite an existing --output path
    -q, --quiet           suppress the savings report on stderr
    -h, --help            show help
```

### Examples

```sh
# In-place, with verification before and after (default).
pcf-compact container.pcf

# Write the compacted copy to a new path, leave the original alone.
pcf-compact container.pcf --output container.compact.pcf

# Overwrite an existing output file.
pcf-compact container.pcf -o out.pcf --force

# Skip verification (fast path for known-good inputs).
pcf-compact container.pcf --no-verify
```

## Atomic write guarantees

In-place mode (and `--output` to a fresh path) writes via a sibling temp file
named `<target>.pcf-compact.tmp.<pid>.<nanos>`, fsyncs the data, then issues an
atomic `rename(2)`. On crash either the original file is intact, or the new
file is fully durable. Stray `*.pcf-compact.tmp.*` files left after a crash
are safe to delete.

Cross-filesystem `--output` (where the temp file and target would land on
different mount points) is rejected rather than silently falling back to a
non-atomic copy — pick an `--output` path on the same filesystem.

## What it does *not* do

- Edit individual partitions (`pcf-debug` is for inspection).
- Change the table-hash algorithm beyond normalising every table block to
  the algorithm used by the first block in the source chain.
- Stream: the whole file is loaded into memory.

## Tests

```sh
cargo test -p pcf-compact
```
