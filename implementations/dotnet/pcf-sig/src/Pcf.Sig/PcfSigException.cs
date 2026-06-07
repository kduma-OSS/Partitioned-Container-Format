using System;

namespace Pcf.Sig;

/// <summary>Discriminant identifying which kind of <see cref="PcfSigException"/> occurred.</summary>
public enum PcfSigErrorKind
{
    BadKeyMagic,
    BadManifestMagic,
    UnsupportedMajor,
    UnknownKeyFormat,
    EmptyKeyData,
    NonZeroKeyReserved,
    FingerprintMismatch,
    UnknownSigAlgo,
    NonCryptoManifestHash,
    HashAlgoBindingMismatch,
    NonZeroFlags,
    EmptyManifest,
    NonZeroTrailer,
    NonZeroEntryReserved,
    NonCryptoEntryHash,
    EntryNilUid,
    EntryReservedType,
    DuplicateSignedUid,
    SelfSignedEntry,
    MalformedSignaturePartition,
    SignatureLengthMismatch,
    NonCryptoTargetHash,
    TargetPartitionMissing,
}

/// <summary>All ways a PCF-SIG operation can fail.</summary>
public sealed class PcfSigException : Exception
{
    public PcfSigErrorKind Kind { get; }

    public PcfSigException(PcfSigErrorKind kind, string message)
        : base(message)
    {
        Kind = kind;
    }

    public static PcfSigException BadKeyMagic() =>
        new(PcfSigErrorKind.BadKeyMagic, "bad PCFSIG_KEY magic");

    public static PcfSigException BadManifestMagic() =>
        new(PcfSigErrorKind.BadManifestMagic, "bad PCFSIG_SIG manifest magic");

    public static PcfSigException UnsupportedMajor(int v) =>
        new(PcfSigErrorKind.UnsupportedMajor, $"unsupported PCF-SIG major version {v}");

    public static PcfSigException UnknownKeyFormat(int id) =>
        new(PcfSigErrorKind.UnknownKeyFormat, $"unknown key_format_id {id}");

    public static PcfSigException EmptyKeyData() =>
        new(PcfSigErrorKind.EmptyKeyData, "key_data_length is zero");

    public static PcfSigException NonZeroKeyReserved() =>
        new(PcfSigErrorKind.NonZeroKeyReserved, "key record reserved bytes are non-zero");

    public static PcfSigException FingerprintMismatch() =>
        new(PcfSigErrorKind.FingerprintMismatch,
            "stored key fingerprint does not match SHA-256(key_data)");

    public static PcfSigException UnknownSigAlgo(int id) =>
        new(PcfSigErrorKind.UnknownSigAlgo, $"unknown or reserved sig_algo_id {id}");

    public static PcfSigException NonCryptoManifestHash(int id) =>
        new(PcfSigErrorKind.NonCryptoManifestHash,
            $"manifest_hash_algo_id {id} is not cryptographic");

    public static PcfSigException HashAlgoBindingMismatch() =>
        new(PcfSigErrorKind.HashAlgoBindingMismatch,
            "manifest_hash_algo_id does not match the binding required by sig_algo_id");

    public static PcfSigException NonZeroFlags() =>
        new(PcfSigErrorKind.NonZeroFlags, "manifest flags are non-zero in v1.0");

    public static PcfSigException EmptyManifest() =>
        new(PcfSigErrorKind.EmptyManifest, "manifest signed_count is 0");

    public static PcfSigException NonZeroTrailer() =>
        new(PcfSigErrorKind.NonZeroTrailer, "trailer_length is non-zero in v1.0");

    public static PcfSigException NonZeroEntryReserved() =>
        new(PcfSigErrorKind.NonZeroEntryReserved,
            "SignedEntry reserved span contains non-zero bytes");

    public static PcfSigException NonCryptoEntryHash(int id) =>
        new(PcfSigErrorKind.NonCryptoEntryHash,
            $"SignedEntry data_hash_algo_id {id} is not cryptographic");

    public static PcfSigException EntryNilUid() =>
        new(PcfSigErrorKind.EntryNilUid, "SignedEntry uses the NIL UID");

    public static PcfSigException EntryReservedType() =>
        new(PcfSigErrorKind.EntryReservedType,
            "SignedEntry uses PCF reserved type 0x00000000");

    public static PcfSigException DuplicateSignedUid() =>
        new(PcfSigErrorKind.DuplicateSignedUid, "duplicate uid in manifest");

    public static PcfSigException SelfSignedEntry() =>
        new(PcfSigErrorKind.SelfSignedEntry,
            "SignedEntry references the PCFSIG_SIG partition itself");

    public static PcfSigException MalformedSignaturePartition() =>
        new(PcfSigErrorKind.MalformedSignaturePartition,
            "PCFSIG_SIG partition layout is malformed");

    public static PcfSigException SignatureLengthMismatch() =>
        new(PcfSigErrorKind.SignatureLengthMismatch,
            "sig_bytes length does not match the algorithm");

    public static PcfSigException NonCryptoTargetHash() =>
        new(PcfSigErrorKind.NonCryptoTargetHash,
            "cannot sign a partition whose data_hash_algo_id is not cryptographic");

    public static PcfSigException TargetPartitionMissing() =>
        new(PcfSigErrorKind.TargetPartitionMissing,
            "partition to sign is not present in the container");
}
