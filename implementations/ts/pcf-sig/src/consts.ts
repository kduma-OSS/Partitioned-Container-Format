/**
 * On-disk constants defined by PCF-SIG v1.0.
 *
 * Every value here is normative and corresponds directly to a figure in the
 * specification (`specs/PCF-SIG-spec-v1.0.txt`, Appendix A).
 */

/** PCF partition type carrying one Key Record (spec Section 5). */
export const TYPE_PCFSIG_KEY = 0xaaab_0001;

/** PCF partition type carrying one Signature Partition (spec Section 5). */
export const TYPE_PCFSIG_SIG = 0xaaab_0002;

/** 8-byte magic at the start of a Key Record (spec Section 6.1). */
export const KEY_MAGIC: Uint8Array = new Uint8Array([
  0x50, 0x43, 0x46, 0x4b, 0x45, 0x59, 0x00, 0x00,
]); // "PCFKEY\0\0"

/** 8-byte magic at the start of a Signature Partition Manifest (spec Section 7.1). */
export const SIG_MAGIC: Uint8Array = new Uint8Array([
  0x50, 0x43, 0x46, 0x53, 0x49, 0x47, 0x00, 0x00,
]); // "PCFSIG\0\0"

/** Profile version implemented by this library (major). */
export const PROFILE_VERSION_MAJOR = 1;

/** Profile version implemented by this library (minor). */
export const PROFILE_VERSION_MINOR = 0;

/** Length of the Key Record fixed prefix that precedes `key_data` (spec 6.1). */
export const KEY_PREFIX_SIZE = 52;

/** Length of the Manifest fixed prefix that precedes `signed_entries` (spec 7.1). */
export const MANIFEST_PREFIX_SIZE = 60;

/** Length of one Signed Entry (spec Section 7.2). */
export const SIGNED_ENTRY_SIZE = 218;

/** Length of a SHA-256 key fingerprint (spec Section 6.3). */
export const FINGERPRINT_SIZE = 32;

/** Length of the Ed25519 raw public key (spec Section 6.2, key_format_id = 1). */
export const ED25519_PUBLIC_KEY_LEN = 32;

/** Length of an Ed25519 signature (spec Section 8, sig_algo_id = 1). */
export const ED25519_SIGNATURE_LEN = 64;
