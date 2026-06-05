# pcf-sig — PCF Cryptographic Signatures (reference implementation)

Reference reader/writer for **PCF-SIG v1.0**, an application-level profile
that adds digital signatures to the [Partitioned Container Format](../PCF-v1.0)
without modifying the PCF byte container.

This crate mirrors the written specification (`specs/PCF-SIG-spec-v1.0.txt`)
field-for-field and is intended as the *normative* implementation against
which language ports are checked. It favours auditability over performance.

## Model at a glance

PCF-SIG defines two new PCF partition types:

| Type         | Name         | Holds                                                    |
|--------------|--------------|----------------------------------------------------------|
| `0xAAAB0001` | `PCFSIG_KEY` | One signer's public key or X.509 cert, identified by a 32-byte SHA-256 fingerprint of the key bytes |
| `0xAAAB0002` | `PCFSIG_SIG` | One Manifest enumerating signed partitions + the signature over the Manifest |

A **Manifest** binds the *protected fields* of each covered partition:
`uid`, `partition_type`, `label`, `used_bytes`, `data_hash_algo_id`,
`data_hash`. It does NOT bind `start_offset` or `max_length`, so PCF
compaction and other relocations preserve signature validity as long as
partition bytes do not change.

```
PCFSIG_SIG partition data:
[ Manifest (60 + 218 * N bytes) | u32 sig_len | sig_bytes | u32 trailer_len=0 ]
```

## Algorithm support

| `sig_algo_id` | Algorithm           | This crate v1.0 |
|---------------|---------------------|------------------|
| 1             | Ed25519 (RFC 8032)  | implemented (MUST) |
| 2, 4, 5, 7    | RSA-PSS / PKCS1v15  | registry only    |
| 16, 18        | ECDSA P-256 / P-521 | registry only    |
| 32            | X.509 chain         | registry only    |

Algorithms in *registry only* are recognised at parse time and reported as
`Unverifiable` rather than `Malformed`. Adding a full implementation for any
of them is a pure addition that does not touch the on-disk format.

Hash algorithm constraint: signed partitions MUST use a cryptographic
`data_hash_algo_id` (16 SHA-256, 17 SHA-512, 18 BLAKE3). The Writer refuses
to sign weakly-hashed partitions; the Verifier rejects them per entry.

## Usage

```rust
use std::io::Cursor;
use pcf::{Container, HashAlgo};
use pcf_sig::{sign_partitions, verify_all_with_recheck, ManifestVerdict, SigningMaterial};

let mut c = Container::create(Cursor::new(Vec::new()))?;
let alpha = [0x11u8; 16];
c.add_partition(0x10, alpha, "alpha", b"Hello, PCF-SIG!", 0, HashAlgo::Sha256)?;

let signer = SigningMaterial::ed25519_from_seed(&[0x42u8; 32]);
sign_partitions(
    &mut c, &signer,
    &[alpha],
    [0x33u8; 16],  // PCFSIG_SIG uid
    [0x22u8; 16],  // PCFSIG_KEY uid (reused if a key with the same fingerprint already exists)
    0,             // signed_at_unix_seconds (0 = unspecified)
    "pcfsig", "pcfkey",
)?;

for report in verify_all_with_recheck(&mut c)? {
    assert!(matches!(report.verdict, ManifestVerdict::Valid));
    for entry in &report.entries {
        println!("covered uid {:?} verdict {:?}", entry.uid, entry.verdict);
    }
}
# Ok::<(), pcf_sig::Error>(())
```

## Trust patterns

The profile defines two non-X.509 ways for an application to express trust;
both are described in spec Section 12.

**Pattern A — self-binding key attestations.** Carry a JWT, SCITT statement,
or custom signed envelope as an application-private TLV entry (tag range
`0x8000..0xFFFF`) inside the `PCFSIG_KEY` partition (Section 6.4). The
attestation MUST internally commit to the key's SHA-256 fingerprint (e.g.
JWT `cnf.jkt`); otherwise the binding is meaningless because the fingerprint
covers only `key_data`, not the TLV. The application verifies the
attestation independently of PCF-SIG.

**Pattern B — key endorsement via countersignature.** A "CA" emits a
`PCFSIG_SIG` partition whose manifest covers the leaf signer's `PCFSIG_KEY`
partition by uid. Verifiers report it like any other signature; the
application checks whether any trusted CA fingerprint endorses the leaf key.

```rust
use pcf_sig::{key_endorsements, verify_all_with_recheck};

let reports = verify_all_with_recheck(&mut container)?;
let endorsers = key_endorsements(&mut container, &reports, &leaf_fingerprint)?;
let trusted = endorsers.iter().any(|fp| my_trusted_ca_set.contains(fp));
# Ok::<(), pcf_sig::Error>(())
```

For Pattern B the CA does NOT need the leaf's PCF file. The stateless
workflow (spec 12.2.1 W2): the client sends only the leaf key bytes plus the
planned partition identity; the CA returns a self-contained response that
the client embeds locally.

```rust
use pcf_sig::{embed_endorsement, issue_endorsement, EndorsementRequest, KeyFormat};
use pcf::HashAlgo;

// CA side (stateless; no I/O, no file):
let request = EndorsementRequest {
    key_format: KeyFormat::Ed25519Raw,
    key_data: leaf_public_key_bytes,
    intended_uid: agreed_uid,           // stable across leaf and CA
    intended_label: agreed_label,
    data_hash_algo: HashAlgo::Sha256,
};
let response = issue_endorsement(&ca_signer, &request, signed_at)?;

// Client side: embed into the local container:
embed_endorsement(&mut container, &response, ca_key_uid, ca_sig_uid, "ca-key", "ca-sig")?;
# Ok::<(), pcf_sig::Error>(())
```

Because the response commits to the leaf `PCFSIG_KEY` bytes (not to any file
location), a client may also cache and re-use the same response across many
PCF files in which the leaf KEY partition is reproduced byte-identical
(workflow W3, license pattern).

## Relocation stability

The central property: a PCFSIG_SIG signature remains valid across any
operation that touches only the unprotected fields. `tests/relocation.rs`
exercises this end-to-end:

- PCF compaction (full rewrite, every `start_offset` and `max_length`
  changes) — signature still verifies.
- Table Block chain growth (extra blocks inserted, chain re-linked) —
  signature still verifies.
- In-place update of a sibling UNSIGNED partition — signature still verifies.

## Tests

```
reference/PCF-SIG-v1.0/
├── Cargo.toml
├── README.md
├── src/                       # library sources
│   ├── lib.rs
│   ├── consts.rs              # magics, type ids, byte-layout constants
│   ├── algo.rs                # SigAlgo + KeyFormat registries
│   ├── error.rs
│   ├── key.rs                 # PCFSIG_KEY record (Key Record + TLV metadata)
│   ├── manifest.rs            # Manifest + SignedEntry layout
│   ├── sig.rs                 # PCFSIG_SIG payload framing (manifest|sig|trailer)
│   ├── sign.rs                # high-level Writer API
│   └── verify.rs              # high-level Verifier API
├── tests/
│   ├── roundtrip.rs           # sign → write → reopen → verify
│   ├── relocation.rs          # compaction + chain growth + sibling update
│   ├── multi_signer.rs        # independent signatures, key deduplication
│   ├── tamper.rs              # protected-field changes invalidate signatures
│   └── spec_compliance.rs     # one test per normative MUST/SHALL clause
├── examples/
│   └── gen_testvector.rs      # produces a deterministic byte-exact vector
└── testdata/
    └── canonical.bin          # 966-byte canonical PCF-SIG container
```

Run from this directory:

```
cargo test
cargo run --example gen_testvector       # writes pcfsig_testvector.bin
```

The canonical test vector is 966 bytes; its SHA-256 is printed on stderr
when the example runs. Ports are expected to reproduce the same bytes.
