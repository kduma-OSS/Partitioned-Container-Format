namespace Pcf.Sig;

/// <summary>
/// On-disk constants defined by PCF-SIG v1.0. Every value here is normative
/// and corresponds directly to a figure in the specification
/// (`specs/PCF-SIG-spec-v1.0.txt`, Appendix A).
/// </summary>
public static class Constants
{
    /// <summary>PCF partition type carrying one Key Record (spec Section 5).</summary>
    public const uint TypePcfsigKey = 0xAAAB_0001;

    /// <summary>PCF partition type carrying one Signature Partition (spec Section 5).</summary>
    public const uint TypePcfsigSig = 0xAAAB_0002;

    /// <summary>8-byte magic at the start of a Key Record (spec Section 6.1).</summary>
    public static readonly byte[] KeyMagic =
        { (byte)'P', (byte)'C', (byte)'F', (byte)'K', (byte)'E', (byte)'Y', 0x00, 0x00 };

    /// <summary>8-byte magic at the start of a Signature Partition Manifest (spec Section 7.1).</summary>
    public static readonly byte[] SigMagic =
        { (byte)'P', (byte)'C', (byte)'F', (byte)'S', (byte)'I', (byte)'G', 0x00, 0x00 };

    /// <summary>Profile version implemented by this library (major).</summary>
    public const ushort ProfileVersionMajor = 1;

    /// <summary>Profile version implemented by this library (minor).</summary>
    public const ushort ProfileVersionMinor = 0;

    /// <summary>Length of the Key Record fixed prefix that precedes key_data (spec 6.1).</summary>
    public const int KeyPrefixSize = 52;

    /// <summary>Length of the Manifest fixed prefix that precedes signed_entries (spec 7.1).</summary>
    public const int ManifestPrefixSize = 60;

    /// <summary>Length of one Signed Entry (spec Section 7.2).</summary>
    public const int SignedEntrySize = 218;

    /// <summary>Length of a SHA-256 key fingerprint (spec Section 6.3).</summary>
    public const int FingerprintSize = 32;

    /// <summary>Length of the Ed25519 raw public key (spec Section 6.2, key_format_id = 1).</summary>
    public const int Ed25519PublicKeyLen = 32;

    /// <summary>Length of an Ed25519 signature (spec Section 8, sig_algo_id = 1).</summary>
    public const int Ed25519SignatureLen = 64;
}
