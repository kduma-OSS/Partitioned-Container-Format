# @kduma-oss/pcf-dcp — PCF Dynamic Container Partition (TypeScript)

TypeScript reader/writer for **PCF-DCP v1.0**, an application-level profile that
adds *dynamic*, fragmentable, dedup-friendly sub-partitions to the
[Partitioned Container Format](../pcf) without modifying the PCF byte container.

This package mirrors the written specification (`PCF-DCP-spec-v1.0.txt`) and the
Rust reference implementation field-for-field, and ships the same byte-exact
700-byte canonical test vector as every other port.

## Model at a glance

One new PCF partition type is defined:

| Type         | Name            | Holds                                              |
|--------------|-----------------|----------------------------------------------------|
| `0xAAAC0001` | `DCP_CONTAINER` | An *arena*: a header, an inner partition table, fragment tables, and data extents |

```
arena:
[ DCP Header (24 B) | data extents | Fragment Tables | Inner Table Block(s) ]
```

Each inner partition's logical content is the concatenation of its DATA extents;
its `dataHash` covers that logical content, so fragmentation, deduplication,
compaction, and promotion all leave the hash (and any PCF-SIG signature over it)
unchanged. A generic PCF reader sees a DCP file as **one opaque partition**; only
a DCP-aware reader looks inside.

## Example

```ts
import { Arena, Chunker, DcpReader, DcpWriter, HashAlgo } from "@kduma-oss/pcf-dcp";
import { MemoryStorage } from "@kduma-oss/pcf";

const arena = new Arena();
arena.addInner(0x10, new Uint8Array(16).fill(0xa1), "A",
  new TextEncoder().encode("Hello, World!"), HashAlgo.Sha256, Chunker.fixed(7));
arena.addInner(0x10, new Uint8Array(16).fill(0xb2), "B",
  new TextEncoder().encode("World!"), HashAlgo.Sha256, Chunker.whole());

const w = new DcpWriter();
w.addContainer(new Uint8Array(16).fill(0xdc), "dcp", arena);
const image = w.toImage();

const r = DcpReader.open(new MemoryStorage(image));
r.verify();
new TextDecoder().decode(r.readInner(new Uint8Array(16).fill(0xb2))); // "World!"
```

## Operations

`Arena` supports content-defined deduplication, copy-on-write edits
(`append` / `insert` / `overwrite` / `delete` / `truncate`), and
sharing-preserving `compact`. `DcpWriter` adds **promotion** (`promote`,
dynamic → fixed) and **demotion** (`demote`, fixed → dynamic), each preserving
`uid`, `partitionType`, `label`, `dataHashAlgo`, and `dataHash` — the promotion
invariant, identical to the fields a PCF-SIG signature protects.

## Build & test

```
npm run build -w @kduma-oss/pcf      # build the dependency first
npm test -w @kduma-oss/pcf-dcp
npm run gen-testvector -w @kduma-oss/pcf-dcp -- out.bin   # the 700-byte vector
```

## Licence

MIT OR Apache-2.0.
