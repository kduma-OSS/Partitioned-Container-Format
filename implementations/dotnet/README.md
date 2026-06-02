# Pcf — Partitioned Container Format (C# / .NET implementation)

A C# reader/writer for **PCF v1.0**, a language-agnostic binary container that
stores multiple independent byte regions ("partitions") in one file.

This is the first port of the Rust [reference implementation](../../reference/PCF-v1.0)
and tracks the written specification ([`PCF-spec-v1.0.txt`](../../specs/PCF-spec-v1.0.txt))
field-for-field. It is verified byte-for-byte against the spec's canonical
395-byte test vector (section 15) and, like the reference, favours auditability
over performance.

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

SHA-1/2 and MD5 use `System.Security.Cryptography`; the three CRCs are
self-contained reflected-CRC routines (`Crc.cs`); BLAKE3 uses the
[`Blake3`](https://www.nuget.org/packages/Blake3) NuGet package.

## Usage

```csharp
using System.IO;
using System.Text;
using Pcf;

var c = Container.Create(new MemoryStream());
c.AddPartition(
    partitionType: 0x10,
    uid: new byte[16] { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 },
    label: "notes",
    data: Encoding.ASCII.GetBytes("hello"),
    extraReserve: 64,
    dataHashAlgo: HashAlgo.Sha256);

c.Verify();

foreach (PartitionEntry e in c.Entries())
{
    byte[] data = c.ReadPartitionData(e);
    // ...
}

// Reclaim unused reservations and produce the canonical, tightly packed form:
byte[] image = c.CompactedImage();
```

`Container` is backed by any readable/writable/seekable `System.IO.Stream`
(both `MemoryStream` and `FileStream` work) — the C# analogue of the
reference's `Read + Write + Seek` store. Operations raise `PcfException`, whose
`Kind` (`PcfError`) identifies the exact failure.

## Project structure

```
implementations/dotnet/
├── Pcf.sln
├── src/Pcf/                 # the library (targets netstandard2.0)
│   ├── Constants.cs         # on-disk constants (spec Appendix A)
│   ├── PcfError.cs          # PcfError + PcfException
│   ├── LittleEndian.cs      # explicit little-endian helpers
│   ├── Crc.cs               # CRC-32 / CRC-32C / CRC-64
│   ├── HashAlgo.cs          # hash-algorithm registry (spec 8)
│   ├── FileHeader.cs        # 20-byte header (spec 4)
│   ├── PartitionEntry.cs    # 141-byte entry + labels (spec 5.2, 10)
│   ├── TableBlockHeader.cs  # 74-byte block header + table hash (spec 5.1, 8.4)
│   └── Container.cs         # high-level reader/writer
└── tests/Pcf.Tests/         # xUnit suite (targets net8.0)
    ├── SpecComplianceTests.cs  # one assertion per normative MUST/SHALL
    ├── RoundtripTests.cs       # end-to-end create/read/verify/update/remove/compact
    └── CoverageTests.cs        # error paths, every hash algo, label edge cases
```

The library targets `netstandard2.0` for broad reach; the test project targets
`net8.0`. BLAKE3 is provided by `Blake3` 0.6.1 — the last release that ships a
`netstandard2.0` assembly together with native runtimes for linux/macOS/windows
(x64 + arm64).

## Building and testing

```sh
cd implementations/dotnet
dotnet build -c Release
dotnet test  -c Release
```

The section-15 test (`S15_canonical_vector_is_byte_exact`) proves this
implementation emits the spec's exact 395-byte file.
