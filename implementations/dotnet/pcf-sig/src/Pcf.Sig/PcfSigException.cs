using System;

namespace Pcf.Sig;

/// <summary>Discriminant identifying which kind of <see cref="PcfSigException"/> occurred.</summary>
public enum PcfSigErrorKind
{
    /// <summary>A Key Record did not begin with <c>"PCFKEY\0\0"</c>.</summary>
    BadKeyMagic,
    /// <summary>A Manifest did not begin with <c>"PCFSIG\0\0"</c>.</summary>
    BadManifestMagic,
    /// <summary>A record's profile major version is not implemented by this library.</summary>
    UnsupportedMajor,
    /// <summary>A Key Record's <c>key_format_id</c> is unknown or reserved (0).</summary>
    UnknownKeyFormat,
    /// <summary>A Key Record's <c>key_data_length</c> is zero.</summary>
    EmptyKeyData,
    /// <summary>A Key Record's reserved bytes are non-zero in v1.0.</summary>
    NonZeroKeyReserved,
    /// <summary><c>fingerprint</c> does not equal <c>SHA-256(key_data)</c>.</summary>
    FingerprintMismatch,
    /// <summary>A Manifest's <c>sig_algo_id</c> is reserved (0) or unknown.</summary>
    UnknownSigAlgo,
    /// <summary>A Manifest's <c>manifest_hash_algo_id</c> is not cryptographic.</summary>
    NonCryptoManifestHash,
    /// <summary><c>manifest_hash_algo_id</c> does not match the binding required by <c>sig_algo_id</c>.</summary>
    HashAlgoBindingMismatch,
    /// <summary><c>flags</c> carries bits not defined in v1.0.</summary>
    NonZeroFlags,
    /// <summary><c>signed_count</c> is 0.</summary>
    EmptyManifest,
    /// <summary><c>trailer_length</c> is non-zero (reserved in v1.0).</summary>
    NonZeroTrailer,
    /// <summary>A SignedEntry's reserved span is non-zero.</summary>
    NonZeroEntryReserved,
    /// <summary>A SignedEntry's <c>data_hash_algo_id</c> is not cryptographic (spec Section 9).</summary>
    NonCryptoEntryHash,
    /// <summary>A SignedEntry references the PCF NIL UID.</summary>
    EntryNilUid,
    /// <summary>A SignedEntry uses PCF reserved type <c>0x00000000</c>.</summary>
    EntryReservedType,
    /// <summary>Two SignedEntry records share the same uid.</summary>
    DuplicateSignedUid,
    /// <summary>A SignedEntry references the enclosing PCFSIG_SIG partition's own uid.</summary>
    SelfSignedEntry,
    /// <summary>A truncation, short read, or length-field mismatch in the partition payload.</summary>
    MalformedSignaturePartition,
    /// <summary>Length of <c>sig_bytes</c> does not match the algorithm's natural size.</summary>
    SignatureLengthMismatch,
    /// <summary>The Writer was asked to sign a partition whose <c>data_hash_algo_id</c> is not cryptographic.</summary>
    NonCryptoTargetHash,
    /// <summary>The Writer was asked to sign a partition that does not exist in the supplied container.</summary>
    TargetPartitionMissing,
}

/// <summary>All ways a PCF-SIG operation can fail.</summary>
public sealed class PcfSigException : Exception
{
    /// <summary>The kind of failure.</summary>
    public PcfSigErrorKind Kind { get; }

    /// <summary>Construct an exception of the given kind with the given message.</summary>
    public PcfSigException(PcfSigErrorKind kind, string message)
        : base(message)
    {
        Kind = kind;
    }

    /// <summary>Construct a <see cref="PcfSigErrorKind.BadKeyMagic"/> exception.</summary>
    public static PcfSigException BadKeyMagic() =>
        new(PcfSigErrorKind.BadKeyMagic, "bad PCFSIG_KEY magic");

    /// <summary>Construct a <see cref="PcfSigErrorKind.BadManifestMagic"/> exception.</summary>
    public static PcfSigException BadManifestMagic() =>
        new(PcfSigErrorKind.BadManifestMagic, "bad PCFSIG_SIG manifest magic");

    /// <summary>Construct an <see cref="PcfSigErrorKind.UnsupportedMajor"/> exception.</summary>
    public static PcfSigException UnsupportedMajor(int v) =>
        new(PcfSigErrorKind.UnsupportedMajor, $"unsupported PCF-SIG major version {v}");

    /// <summary>Construct an <see cref="PcfSigErrorKind.UnknownKeyFormat"/> exception.</summary>
    public static PcfSigException UnknownKeyFormat(int id) =>
        new(PcfSigErrorKind.UnknownKeyFormat, $"unknown key_format_id {id}");

    /// <summary>Construct an <see cref="PcfSigErrorKind.EmptyKeyData"/> exception.</summary>
    public static PcfSigException EmptyKeyData() =>
        new(PcfSigErrorKind.EmptyKeyData, "key_data_length is zero");

    /// <summary>Construct a <see cref="PcfSigErrorKind.NonZeroKeyReserved"/> exception.</summary>
    public static PcfSigException NonZeroKeyReserved() =>
        new(PcfSigErrorKind.NonZeroKeyReserved, "key record reserved bytes are non-zero");

    /// <summary>Construct a <see cref="PcfSigErrorKind.FingerprintMismatch"/> exception.</summary>
    public static PcfSigException FingerprintMismatch() =>
        new(PcfSigErrorKind.FingerprintMismatch,
            "stored key fingerprint does not match SHA-256(key_data)");

    /// <summary>Construct an <see cref="PcfSigErrorKind.UnknownSigAlgo"/> exception.</summary>
    public static PcfSigException UnknownSigAlgo(int id) =>
        new(PcfSigErrorKind.UnknownSigAlgo, $"unknown or reserved sig_algo_id {id}");

    /// <summary>Construct a <see cref="PcfSigErrorKind.NonCryptoManifestHash"/> exception.</summary>
    public static PcfSigException NonCryptoManifestHash(int id) =>
        new(PcfSigErrorKind.NonCryptoManifestHash,
            $"manifest_hash_algo_id {id} is not cryptographic");

    /// <summary>Construct a <see cref="PcfSigErrorKind.HashAlgoBindingMismatch"/> exception.</summary>
    public static PcfSigException HashAlgoBindingMismatch() =>
        new(PcfSigErrorKind.HashAlgoBindingMismatch,
            "manifest_hash_algo_id does not match the binding required by sig_algo_id");

    /// <summary>Construct a <see cref="PcfSigErrorKind.NonZeroFlags"/> exception.</summary>
    public static PcfSigException NonZeroFlags() =>
        new(PcfSigErrorKind.NonZeroFlags, "manifest flags are non-zero in v1.0");

    /// <summary>Construct an <see cref="PcfSigErrorKind.EmptyManifest"/> exception.</summary>
    public static PcfSigException EmptyManifest() =>
        new(PcfSigErrorKind.EmptyManifest, "manifest signed_count is 0");

    /// <summary>Construct a <see cref="PcfSigErrorKind.NonZeroTrailer"/> exception.</summary>
    public static PcfSigException NonZeroTrailer() =>
        new(PcfSigErrorKind.NonZeroTrailer, "trailer_length is non-zero in v1.0");

    /// <summary>Construct a <see cref="PcfSigErrorKind.NonZeroEntryReserved"/> exception.</summary>
    public static PcfSigException NonZeroEntryReserved() =>
        new(PcfSigErrorKind.NonZeroEntryReserved,
            "SignedEntry reserved span contains non-zero bytes");

    /// <summary>Construct a <see cref="PcfSigErrorKind.NonCryptoEntryHash"/> exception.</summary>
    public static PcfSigException NonCryptoEntryHash(int id) =>
        new(PcfSigErrorKind.NonCryptoEntryHash,
            $"SignedEntry data_hash_algo_id {id} is not cryptographic");

    /// <summary>Construct an <see cref="PcfSigErrorKind.EntryNilUid"/> exception.</summary>
    public static PcfSigException EntryNilUid() =>
        new(PcfSigErrorKind.EntryNilUid, "SignedEntry uses the NIL UID");

    /// <summary>Construct an <see cref="PcfSigErrorKind.EntryReservedType"/> exception.</summary>
    public static PcfSigException EntryReservedType() =>
        new(PcfSigErrorKind.EntryReservedType,
            "SignedEntry uses PCF reserved type 0x00000000");

    /// <summary>Construct a <see cref="PcfSigErrorKind.DuplicateSignedUid"/> exception.</summary>
    public static PcfSigException DuplicateSignedUid() =>
        new(PcfSigErrorKind.DuplicateSignedUid, "duplicate uid in manifest");

    /// <summary>Construct a <see cref="PcfSigErrorKind.SelfSignedEntry"/> exception.</summary>
    public static PcfSigException SelfSignedEntry() =>
        new(PcfSigErrorKind.SelfSignedEntry,
            "SignedEntry references the PCFSIG_SIG partition itself");

    /// <summary>Construct a <see cref="PcfSigErrorKind.MalformedSignaturePartition"/> exception.</summary>
    public static PcfSigException MalformedSignaturePartition() =>
        new(PcfSigErrorKind.MalformedSignaturePartition,
            "PCFSIG_SIG partition layout is malformed");

    /// <summary>Construct a <see cref="PcfSigErrorKind.SignatureLengthMismatch"/> exception.</summary>
    public static PcfSigException SignatureLengthMismatch() =>
        new(PcfSigErrorKind.SignatureLengthMismatch,
            "sig_bytes length does not match the algorithm");

    /// <summary>Construct a <see cref="PcfSigErrorKind.NonCryptoTargetHash"/> exception.</summary>
    public static PcfSigException NonCryptoTargetHash() =>
        new(PcfSigErrorKind.NonCryptoTargetHash,
            "cannot sign a partition whose data_hash_algo_id is not cryptographic");

    /// <summary>Construct a <see cref="PcfSigErrorKind.TargetPartitionMissing"/> exception.</summary>
    public static PcfSigException TargetPartitionMissing() =>
        new(PcfSigErrorKind.TargetPartitionMissing,
            "partition to sign is not present in the container");
}
