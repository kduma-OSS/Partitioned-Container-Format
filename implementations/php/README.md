# pcf — Partitioned Container Format (PHP implementation)

PHP reader/writer for **PCF v1.0**, a language-agnostic binary container that
stores multiple independent byte regions ("partitions") in one file.

This is the first PHP port of the format. It mirrors the written specification
(`specs/PCF-spec-v1.0.txt`) and the Rust reference (`reference/PCF-v1.0/`)
field-for-field, and it reproduces the canonical 395-byte test vector from spec
section 15 **byte-for-byte**. It favours auditability over performance.

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

Most algorithms come from PHP's bundled `ext-hash`. The two it does not provide
are shipped pure-PHP and validated against canonical vectors:

* **CRC-64/XZ** — `Kduma\PCF\Crc64` (check value `0x995DC9BBDF1939FA`).
* **BLAKE3** — `Kduma\PCF\Blake3`, a port of the official reference
  implementation covering the full chunk tree (validated against all 35 official
  BLAKE3 test vectors).

The library therefore has **no runtime Composer dependencies** beyond `ext-hash`.

## Requirements

* PHP >= 8.1 with `ext-hash` (bundled by default).

## Installation

```bash
composer require kduma-oss/pcf
```

## Usage

```php
use Kduma\PCF\Container;
use Kduma\PCF\HashAlgo;
use Kduma\PCF\Storage\MemoryStorage;
use Kduma\PCF\Storage\StreamStorage;

// In-memory container.
$c = Container::create(new MemoryStorage());
$uid = str_repeat("\x01", 16);
$c->addPartition(0x10, $uid, 'notes', 'hello world', 64, HashAlgo::Sha256);

$c->verify();
$entries = $c->entries();
echo $c->readPartitionData($entries[0]); // "hello world"

// File-backed container.
$f = Container::create(StreamStorage::fromFile('container.pcf', 'c+'));
$f->addPartition(0xFFFFFFFF, str_repeat("\x02", 16), 'blob', "\x00\x01\x02", 0, HashAlgo::Crc32c);
$f->verify();

// Reclaim dead space into the canonical compacted layout.
$image = $c->compactedImage();
file_put_contents('compacted.pcf', $image);
```

`Container` works over any `Kduma\PCF\Storage\StorageInterface`:

* `MemoryStorage` — an in-memory string buffer (analogue of the reference's
  `Cursor<Vec<u8>>`).
* `StreamStorage` — any seekable PHP stream / file (analogue of `std::fs::File`).

### Operations

| Method                       | Purpose |
|------------------------------|---------|
| `Container::create()` / `createWith()` | Start an empty container. |
| `Container::open()`          | Open an existing one (validates magic + major version). |
| `addPartition()`             | Append a partition (unique non-NIL UID, non-reserved type). |
| `updatePartitionData()`      | Replace data in place; maintains the hash cascade. |
| `removePartition()`          | Remove a partition (data region becomes dead space). |
| `entries()` / `readPartitionData()` | Read metadata and data. |
| `verify()`                   | Verify every table-block and partition hash + conformance checks. |
| `compactedImage()` / `compactInto()` | Produce the tightly packed canonical form. |

Errors are reported as `Kduma\PCF\PcfException`; the precise cause is available
as `$e->kind` (a `Kduma\PCF\ErrorKind`).

## Tests

```bash
composer install
composer test                       # or: vendor/bin/phpunit
php examples/gen_testvector.php out.bin   # writes the canonical 395-byte file
```

The suite mirrors the Rust reference:

```
implementations/php/
├── composer.json
├── src/                      # library sources
├── examples/
│   └── gen_testvector.php    # produces the canonical spec test vector
└── tests/
    ├── HashTest.php          # hash registry + CRC/BLAKE3 vectors
    ├── HeaderTest.php        # 20-byte file header
    ├── EntryTest.php         # 141-byte entry + labels
    ├── TableTest.php         # 74-byte table block + table hash
    ├── RoundtripTest.php     # end-to-end create/open/update/remove/compact
    └── SpecComplianceTest.php# one test per normative MUST/SHALL + byte-exact vector
```
