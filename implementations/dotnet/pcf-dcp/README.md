# KDuma.Pcf.Dcp — PCF Dynamic Container Partition (.NET)

.NET reader/writer for **PCF-DCP v1.0**, an application-level profile that adds
*dynamic*, fragmentable, dedup-friendly sub-partitions to the
[Partitioned Container Format](../pcf) without modifying the PCF byte container.

This package mirrors the written specification (`PCF-DCP-spec-v1.0.txt`) and the
Rust reference implementation field-for-field, and ships the same byte-exact
700-byte canonical test vector as every other port. It has no cryptographic
dependency — data/table hashing comes from the base `KDuma.Pcf` package.

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
its data hash covers that logical content, so fragmentation, deduplication,
compaction, and promotion all leave the hash (and any PCF-SIG signature over it)
unchanged. A generic PCF reader sees a DCP file as **one opaque partition**; only
a DCP-aware reader looks inside.

## Example

```csharp
using System.IO;
using Pcf;
using Pcf.Dcp;

var arena = new Arena();
arena.AddInner(0x10, Uid(0xA1), "A", Bytes("Hello, World!"), HashAlgo.Sha256, Chunker.Fixed(7));
arena.AddInner(0x10, Uid(0xB2), "B", Bytes("World!"), HashAlgo.Sha256, Chunker.Whole());

var w = new DcpWriter();
w.AddContainer(Uid(0xDC), "dcp", arena);
byte[] image = w.ToImage();

var r = DcpReader.Open(new MemoryStream(image));
r.Verify();
// System.Text.Encoding.UTF8.GetString(r.ReadInner(Uid(0xB2))) == "World!"
```

## Operations

`Arena` supports content-defined deduplication, copy-on-write edits
(`Append` / `Insert` / `Overwrite` / `Delete` / `Truncate`), and
sharing-preserving `Compact`. `DcpWriter` adds **promotion** (`Promote`,
dynamic → fixed) and **demotion** (`Demote`, fixed → dynamic), each preserving
`uid`, `PartitionType`, `Label`, `DataHashAlgo`, and `DataHash` — the promotion
invariant, identical to the fields a PCF-SIG signature protects.

## Licence

MIT OR Apache-2.0.
