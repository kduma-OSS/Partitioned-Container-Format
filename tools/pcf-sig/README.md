# `pcf-sig`

A command-line tool to **sign** and **verify** Partitioned Container Format
(PCF) files using the [PCF-SIG v1.0](../../reference/PCF-SIG-v1.0) cryptographic
signature profile (Ed25519).

It is a thin CLI over the reference [`pcf-sig`](../../reference/PCF-SIG-v1.0)
crate. The orchestration (key generation, partition selection, incremental
signing, report formatting) lives in this crate's library half (`pcf_sig_cli`),
which the [`pfs`](../../reference/PFS-MS-v1.0) CLI reuses for its own `keygen`
and `verify-sig` subcommands.

## Build & run

From the repository root:

```sh
cargo build -p pcf-sig-cli

# generate a keypair (32-byte raw Ed25519 seed + public key)
cargo run -p pcf-sig-cli --bin pcf-sig -- keygen id.key id.pub

# produce a sample PCF file
cargo run -p pcf --example gen_testvector -- /tmp/tv.pcf

# sign every partition, then verify
cargo run -p pcf-sig-cli --bin pcf-sig -- sign   /tmp/tv.pcf --key id.key
cargo run -p pcf-sig-cli --bin pcf-sig -- verify /tmp/tv.pcf --key id.pub
```

## Usage

```text
pcf-sig keygen <priv_out> <pub_out>
pcf-sig sign   <file.pcf> --key <priv> [--uid <hex16>]... [--resign] [--sig-label <s>] [--key-label <s>]
pcf-sig verify <file.pcf> [--key <trusted_pub>] [--no-recheck]
pcf-sig keys   <file.pcf>
pcf-sig help | -h | --help
```

- **`keygen`** writes a 32-byte raw Ed25519 secret seed to `<priv_out>` (mode
  `0600` on Unix) and the 32-byte raw public key to `<pub_out>`. It refuses to
  overwrite existing files.
- **`sign`** adds a `PCFSIG_SIG` partition (and, if needed, a `PCFSIG_KEY`).
  By default it covers every partition except existing PCF-SIG ones, and is
  **incremental**: partitions already covered by a valid signature from the
  same key are skipped, so re-signing an unchanged file is a no-op. `--resign`
  forces all selected partitions to be signed afresh. `--uid` (repeatable)
  restricts coverage to specific partition uids.
- **`verify`** reports, per signature, whether it is cryptographically valid
  and whether each covered partition still matches. `--key` additionally
  checks that a *trusted* public key matched a valid signature. The exit code
  is non-zero if any signature is not fully valid (or a supplied trusted key
  did not match). `--no-recheck` skips the independent data re-hash.
- **`keys`** lists the `PCFSIG_KEY` fingerprints embedded in the file.

## Key files

| File         | Contents                                  |
|--------------|-------------------------------------------|
| private key  | 32 raw bytes — the Ed25519 secret seed    |
| public key   | 32 raw bytes — the raw Ed25519 public key |

`verify` usually needs no public-key file: the signer's key is embedded in the
file's `PCFSIG_KEY` partition. Pass `--key <pub>` only to assert *trust* in a
specific key out of band (fingerprint match).

## PFS-MS files

A PFS-MS archive is a PCF file, so `verify` and `keys` work on it directly.
**`sign` refuses PFS-MS files**, however: appending partitions would corrupt
their backward-linked session chain. Sign PFS-MS files with
[`pfs sign`](../../reference/PFS-MS-v1.0), which commits the signature as a
dedicated PFS session.

## What it does *not* do

- Implement algorithms other than Ed25519 (the PCF-SIG v1.0 MUST-support
  baseline; other algorithm ids are registered but not implemented).
- Manage trust policy: it reports per-signature, per-partition facts, not an
  aggregate "the file is trusted" verdict.

## Tests

```sh
cargo test -p pcf-sig-cli
```
