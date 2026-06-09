# kduma/pcf-dcp — PCF Dynamic Container Partition (PHP)

PHP reader/writer for **PCF-DCP v1.0**, an application-level profile that adds
*dynamic*, fragmentable, dedup-friendly sub-partitions to the
[Partitioned Container Format](https://github.com/kduma-OSS/Partitioned-Container-Format)
(`kduma/pcf`) without modifying the PCF byte container.

This package mirrors the written specification (`PCF-DCP-spec-v1.0.txt`) and the
Rust reference implementation field-for-field, and ships the same byte-exact
700-byte canonical test vector as every other port. It has no cryptographic
dependency — data/table hashing comes from `kduma/pcf` (`ext-hash`).

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

```php
use Kduma\PCF\HashAlgo;
use Kduma\PCF\Storage\MemoryStorage;
use Kduma\PCFDCP\Arena;
use Kduma\PCFDCP\Chunker;
use Kduma\PCFDCP\DcpReader;
use Kduma\PCFDCP\DcpWriter;

$arena = new Arena();
$arena->addInner(0x10, str_repeat("\xA1", 16), 'A', 'Hello, World!', HashAlgo::Sha256, Chunker::fixed(7));
$arena->addInner(0x10, str_repeat("\xB2", 16), 'B', 'World!', HashAlgo::Sha256, Chunker::whole());

$w = new DcpWriter();
$w->addContainer(str_repeat("\xDC", 16), 'dcp', $arena);
$image = $w->toImage();

$r = DcpReader::open(new MemoryStorage($image));
$r->verify();
echo $r->readInner(str_repeat("\xB2", 16)); // "World!"
```

## Operations

`Arena` supports content-defined deduplication, copy-on-write edits
(`append` / `insert` / `overwrite` / `delete` / `truncate`), and
sharing-preserving `compact`. `DcpWriter` adds **promotion** (`promote`,
dynamic → fixed) and **demotion** (`demote`, fixed → dynamic), each preserving
`uid`, `partitionType`, `label`, `dataHashAlgo`, and `dataHash` — the promotion
invariant, identical to the fields a PCF-SIG signature protects.

## Licence

MIT.
