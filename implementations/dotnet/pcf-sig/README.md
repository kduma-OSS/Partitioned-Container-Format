# KDuma.Pcf.Sig

.NET implementation of **PCF-SIG v1.0**, the PCF Cryptographic Signatures
profile. Mirrors the [normative specification][spec] and the [Rust reference
implementation][rust] field-for-field.

[spec]: ../../../specs/PCF-SIG-spec-v1.0.txt
[rust]: ../../../reference/PCF-SIG-v1.0/

## Install

```sh
dotnet add package KDuma.Pcf
dotnet add package KDuma.Pcf.Sig
```

## What it adds

Two new PCF partition types layered on top of the [`KDuma.Pcf`](../pcf/)
container, without changing the PCF byte format:

| Type         | Name         | Holds                                                |
|--------------|--------------|------------------------------------------------------|
| `0xAAAB0001` | `PCFSIG_KEY` | One signer's public key, identified by SHA-256 fingerprint of the key bytes |
| `0xAAAB0002` | `PCFSIG_SIG` | One Manifest enumerating signed partitions + the signature over the Manifest |

A **Manifest** binds the *protected fields* of each covered partition:
`Uid`, `PartitionType`, `Label`, `UsedBytes`, `DataHashAlgo`, `DataHash`. It
does NOT bind `StartOffset` or `MaxLength`, so PCF compaction and other
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
`DataHashAlgo` (SHA-256, SHA-512, BLAKE3). The Writer refuses to sign
weakly-hashed partitions; the Verifier rejects them per entry.

## Usage

```csharp
using Pcf;
using Pcf.Sig;
using System.IO;

var c = Container.Create(new MemoryStream());
var alpha = new byte[16] { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                           0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
c.AddPartition(0x10, alpha, "alpha",
    System.Text.Encoding.UTF8.GetBytes("Hello, PCF-SIG!"), 0, HashAlgo.Sha256);

var seed = new byte[32]; for (int i = 0; i < 32; i++) seed[i] = 0x42;
var signer = SigningMaterial.Ed25519FromSeed(seed);
SignPartitions.Run(
    c, signer, new[] { alpha },
    /* sigPartitionUid: */ new byte[16] { 0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33, 0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33 },
    /* keyPartitionUid: */ new byte[16] { 0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22, 0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22 },
    signedAtUnixSeconds: 0,
    sigLabel: "pcfsig",
    keyLabel: "pcfkey");

foreach (var report in Verify.AllWithRecheck(c))
{
    if (report.Verdict == ManifestVerdict.Valid)
    {
        System.Console.WriteLine(
            $"signature valid; {report.Entries.Count} entries covered");
    }
}
```

## Cross-port test vector parity

The shipped `testdata/canonical.bin` is byte-identical to the canonical vector
produced by the Rust reference, the TypeScript port and the PHP port. SHA-256:
`b158e2f5b160d72cea3226af2041f8d18aa75b3db6cb85faeca5df7879871307`.

## Dependencies

- `KDuma.Pcf` — the PCF base container library (same version as pcf-sig).
- `BouncyCastle.Cryptography` v2.4+ — actively maintained main BouncyCastle
  fork; ships RFC 8032 Ed25519 (`Org.BouncyCastle.Math.EC.Rfc8032.Ed25519`)
  and targets `netstandard2.0`.
- `System.Security.Cryptography` (BCL) — SHA-256 for fingerprints.

The library targets `netstandard2.0` to match the PCF base; tests target
`net8.0`.
