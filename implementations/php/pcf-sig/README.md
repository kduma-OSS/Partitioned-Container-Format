# kduma/pcf-sig

PHP implementation of **PCF-SIG v1.0**, the PCF Cryptographic Signatures
profile. Mirrors the [normative specification][spec] and the [Rust reference
implementation][rust] field-for-field.

[spec]: ../../../specs/PCF-SIG-spec-v1.0.txt
[rust]: ../../../reference/PCF-SIG-v1.0/

## Install

```sh
composer require kduma/pcf kduma/pcf-sig
```

## What it adds

Two new PCF partition types layered on top of the [`kduma/pcf`](../pcf/)
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
`ManifestVerdict::Unverifiable` (with `UnverifiableReason::UnsupportedSigAlgo`)
rather than `Malformed`. Adding a full implementation for any of them is a
pure addition that does not touch the on-disk format.

Hash algorithm constraint: signed partitions MUST use a cryptographic
`dataHashAlgo` (SHA-256, SHA-512, BLAKE3). The Writer refuses to sign
weakly-hashed partitions; the Verifier rejects them per entry.

## Usage

```php
use Kduma\PCF\Container;
use Kduma\PCF\HashAlgo;
use Kduma\PCFSIG\ManifestVerdict;
use Kduma\PCFSIG\SignPartitions;
use Kduma\PCFSIG\SigningMaterial;
use Kduma\PCFSIG\Verify;

$c = Container::create();
$alpha = str_repeat("\x11", 16);
$c->addPartition(0x10, $alpha, 'alpha', 'Hello, PCF-SIG!', 0, HashAlgo::Sha256);

$signer = SigningMaterial::ed25519FromSeed(str_repeat("\x42", 32));
SignPartitions::run(
    $c, $signer, [$alpha],
    str_repeat("\x33", 16),
    str_repeat("\x22", 16),
    0, 'pcfsig', 'pcfkey',
);

foreach (Verify::allWithRecheck($c) as $report) {
    if ($report->verdict === ManifestVerdict::Valid) {
        printf("signature valid; %d entries covered\n", count($report->entries));
    }
}
```

## Cross-port test vector parity

The shipped `testdata/canonical.bin` is byte-identical to the canonical vector
produced by the Rust reference and the TypeScript port. SHA-256:
`b158e2f5b160d72cea3226af2041f8d18aa75b3db6cb85faeca5df7879871307`.

```sh
composer gen-testvector -- /tmp/php.bin
```

The test suite asserts byte-exact equality on every CI run.

## Dependencies

- `kduma/pcf` — the PCF base container library (same version as pcf-sig).
- `ext-sodium` — PHP's bundled libsodium, used for Ed25519 sign/verify
  (`sodium_crypto_sign_detached` / `sodium_crypto_sign_verify_detached`).
  Available in PHP 7.2+ without external dependencies.
- `ext-hash` — PHP's bundled hash extension, used for SHA-256 fingerprints.

No Composer crypto dependencies; all signing/hashing runs through built-in
PHP extensions.
