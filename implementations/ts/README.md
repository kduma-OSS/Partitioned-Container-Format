# pcf — Partitioned Container Format (TypeScript implementation)

A TypeScript reader/writer for **PCF v1.0**, a language-agnostic binary
container that stores multiple independent byte regions ("partitions") in one
file.

This package is a faithful port of the Rust reference implementation
(`reference/PCF-v1.0/`) and mirrors the written specification
(`specs/PCF-spec-v1.0.txt`) field-for-field. It favours auditability over
performance and produces the **byte-exact** canonical test vector from spec
section 15.

## Layout

```
[ 20-byte header ] [ table block(s) ] [ partition data regions ]
```

- **Header** (20 B): magic `0x89 K P R T 0x0D 0x0A 0x1A`, major/minor version,
  absolute offset of the first table block.
- **Table block**: 74-byte header (`partitionCount`, `nextTableOffset`,
  hash algo + 64-byte block hash) followed by `partitionCount` entries. Blocks
  form a singly linked chain to hold more than 255 partitions.
- **Entry** (141 B): `type`, 16-byte UID, 32-byte ASCII label, `startOffset`,
  `maxLength`, `usedBytes`, 1-byte data-hash algorithm, 64-byte data hash.

All integers are little-endian. `u64` fields are modelled as `bigint` to
preserve full 64-bit fidelity; free space is `maxLength - usedBytes`.

## Hash registry

| id | algorithm        | id | algorithm |
|----|------------------|----|-----------|
| 0  | none             | 5  | SHA-1     |
| 1  | CRC-32/ISO-HDLC  | 16 | SHA-256 (default) |
| 2  | CRC-32C          | 17 | SHA-512   |
| 3  | CRC-64/XZ        | 18 | BLAKE3    |
| 4  | MD5              |    |           |

Digests are provided by the audited [`@noble/hashes`](https://github.com/paulmillr/noble-hashes)
package; the three CRC variants are implemented in pure TypeScript
(`src/crc.ts`).

## Usage

```ts
import { Container, HashAlgo } from "pcf";

const c = Container.create();
const uid = new Uint8Array(16).fill(1);
c.addPartition(
  0x10,
  uid,
  "notes",
  new TextEncoder().encode("hello world"),
  64,
  HashAlgo.Sha256,
);

c.verify();
const entries = c.entries();
const data = c.readPartitionData(entries[0]);
console.log(new TextDecoder().decode(data)); // "hello world"
```

A `Container` is backed by any `Storage`. Two implementations ship with the
package:

- `MemoryStorage` — an in-memory growable buffer (the default for
  `Container.create()`).
- `NodeFileStorage` — backed by a Node file descriptor:

```ts
import { Container, NodeFileStorage, HashAlgo } from "pcf";

const store = NodeFileStorage.open("container.pcf", /* truncate */ true);
const c = Container.create(store);
// … add partitions …
store.close();
```

## Project layout

```
implementations/ts/
├── package.json
├── tsconfig.json
├── vitest.config.ts
├── src/                       # library sources
│   ├── consts.ts  errors.ts  crc.ts  hash.ts
│   ├── header.ts  entry.ts   table.ts
│   ├── storage.ts node-storage.ts container.ts
│   └── index.ts               # public re-exports
├── test/
│   ├── roundtrip.test.ts      # end-to-end black-box tests
│   ├── coverage.test.ts       # targeted error-path / edge-case tests
│   └── spec-compliance.test.ts  # one test per normative MUST/SHALL
└── examples/
    └── gen-testvector.ts      # produces the canonical 395-byte spec vector
```

## Scripts

Run from this directory:

```
npm install            # install dependencies
npm run build          # type-check and emit dist/ (tsc, strict)
npm test               # run the full vitest suite
npm run coverage       # vitest + v8 coverage (95% line / 100% function floor)
npm run gen-testvector # writes pcf_testvector.bin (the 395-byte spec vector)
```

CI (`.github/workflows/ts-ci.yml`) runs the type-check/build, the test suite on
Linux/macOS/Windows, regenerates and size-checks the spec test vector, and
enforces the coverage floor.
