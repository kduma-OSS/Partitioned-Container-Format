<?php

declare(strict_types=1);

namespace Kduma\PCFSIG;

/**
 * On-disk constants defined by PCF-SIG v1.0.
 *
 * Every value here is normative and corresponds directly to a figure in the
 * specification (`specs/PCF-SIG-spec-v1.0.txt`, Appendix A).
 */
final class Consts
{
    /** PCF partition type carrying one Key Record (spec Section 5). */
    public const TYPE_PCFSIG_KEY = 0xAAAB_0001;

    /** PCF partition type carrying one Signature Partition (spec Section 5). */
    public const TYPE_PCFSIG_SIG = 0xAAAB_0002;

    /** 8-byte magic at the start of a Key Record (spec Section 6.1). */
    public const KEY_MAGIC = "PCFKEY\x00\x00";

    /** 8-byte magic at the start of a Signature Partition Manifest (spec Section 7.1). */
    public const SIG_MAGIC = "PCFSIG\x00\x00";

    /** Profile version implemented by this library (major). */
    public const PROFILE_VERSION_MAJOR = 1;

    /** Profile version implemented by this library (minor). */
    public const PROFILE_VERSION_MINOR = 0;

    /** Length of the Key Record fixed prefix that precedes key_data (spec 6.1). */
    public const KEY_PREFIX_SIZE = 52;

    /** Length of the Manifest fixed prefix that precedes signed_entries (spec 7.1). */
    public const MANIFEST_PREFIX_SIZE = 60;

    /** Length of one Signed Entry (spec Section 7.2). */
    public const SIGNED_ENTRY_SIZE = 218;

    /** Length of a SHA-256 key fingerprint (spec Section 6.3). */
    public const FINGERPRINT_SIZE = 32;

    /** Length of the Ed25519 raw public key (spec Section 6.2, key_format_id = 1). */
    public const ED25519_PUBLIC_KEY_LEN = 32;

    /** Length of an Ed25519 signature (spec Section 8, sig_algo_id = 1). */
    public const ED25519_SIGNATURE_LEN = 64;

    private function __construct()
    {
    }
}
