# @kduma-oss/pcf-sig

TypeScript implementation of **PCF-SIG v1.0**, the PCF Cryptographic Signatures
profile. Mirrors the [normative specification][spec] and the [Rust reference
implementation][rust] field-for-field.

[spec]: ../../../specs/PCF-SIG-spec-v1.0.txt
[rust]: ../../../reference/PCF-SIG-v1.0/

## Install

```sh
npm install @kduma-oss/pcf @kduma-oss/pcf-sig
```

## What it adds

Two new PCF partition types layered on top of the [`@kduma-oss/pcf`](../pcf/)
container, without changing the PCF byte format:

| Type         | Name         | Holds                                                |
|--------------|--------------|------------------------------------------------------|
| `0xAAAB0001` | `PCFSIG_KEY` | One signer's public key, identified by SHA-256 fingerprint of the key bytes |
| `0xAAAB0002` | `PCFSIG_SIG` | One Manifest enumerating signed partitions + the signature over the Manifest |

A **Manifest** binds the *protected fields* of each covered partition:
`uid`, `partitionType`, `label`, `usedBytes`, `dataHashAlgo`, `dataHash`. It
does NOT bind `startOffset` or `maxLength`, so PCF compaction and other
relocations preserve signature validity as long as partition bytes do not
change.

## Algorithm support

| `sig_algo_id` | Algorithm           | This release |
|---------------|---------------------|--------------|
| 1             | Ed25519 (RFC 8032)  | implemented (MUST) |
| 2, 4, 5, 7    | RSA-PSS / PKCS1v15  | registry only |
| 16, 18        | ECDSA P-256 / P-521 | registry only |
| 32            | X.509 chain         | registry only |

Algorithms marked *registry only* are recognised at parse time and reported as
`ManifestVerdict.Unverifiable` (with `UnverifiableReason.UnsupportedSigAlgo`)
rather than `Malformed`. Adding a full implementation for any of them is a
pure addition that does not touch the on-disk format.

Hash algorithm constraint: signed partitions MUST use a cryptographic
`dataHashAlgo` (SHA-256, SHA-512, BLAKE3). The Writer refuses to sign
weakly-hashed partitions; the Verifier rejects them per entry.

## Usage

```ts
import { Container, HashAlgo, MemoryStorage } from "@kduma-oss/pcf";
import {
  signPartitions,
  verifyAllWithRecheck,
  ManifestVerdict,
  SigningMaterial,
} from "@kduma-oss/pcf-sig";

const c = Container.create();
const alpha = new Uint8Array(16).fill(0x11);
c.addPartition(0x10, alpha, "alpha",
  new TextEncoder().encode("Hello, PCF-SIG!"), 0, HashAlgo.Sha256);

const signer = SigningMaterial.ed25519FromSeed(new Uint8Array(32).fill(0x42));
signPartitions(c, signer, {
  targetUids: [alpha],
  sigPartitionUid: new Uint8Array(16).fill(0x33),
  keyPartitionUid: new Uint8Array(16).fill(0x22),
  signedAtUnixSeconds: 0n,
  sigLabel: "pcfsig",
  keyLabel: "pcfkey",
});

for (const report of verifyAllWithRecheck(c)) {
  if (report.verdict === ManifestVerdict.Valid) {
    console.log("signature is valid; entries:", report.entries);
  }
}
```

## Cross-port test vector parity

The shipped `testdata/canonical.bin` is byte-identical to the canonical vector
produced by the Rust reference (`reference/PCF-SIG-v1.0/testdata/canonical.bin`).
SHA-256: `b158e2f5b160d72cea3226af2041f8d18aa75b3db6cb85faeca5df7879871307`.

The `gen-testvector` script regenerates this exact file from the deterministic
seed `0x00..0x1F`:

```sh
npm run gen-testvector -- /tmp/ts.bin
```

The test suite asserts byte-exact equality on every CI run.

## Dependencies

- `@kduma-oss/pcf` — the PCF base container library (peer dependency, same version).
- `@noble/ed25519` — audited pure-JavaScript Ed25519 (Paul Miller).
- `@noble/hashes` — audited pure-JavaScript SHA-256/SHA-512 (Paul Miller).

No native modules; the package runs unchanged in Node, Deno, Bun and modern
browsers.
