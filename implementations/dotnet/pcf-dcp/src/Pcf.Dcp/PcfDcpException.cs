using System;

namespace Pcf.Dcp;

/// <summary>Discriminant identifying which kind of <see cref="PcfDcpException"/> occurred.</summary>
public enum PcfDcpErrorKind
{
    /// <summary>The arena did not begin with the <c>"PDCP"</c> magic.</summary>
    BadDcpMagic,
    /// <summary>The arena's profile major version is not implemented.</summary>
    UnsupportedProfileMajor,
    /// <summary>A Fragment Entry carried an unsupported kind (HOLE/REF/unknown).</summary>
    BadFragmentKind,
    /// <summary>An extent range escapes <c>[0, arena_used)</c>.</summary>
    OffsetOutOfRange,
    /// <summary>Reconstructed length did not match <c>used_bytes</c>, or a hash failed.</summary>
    LengthMismatch,
    /// <summary>A stored hash (inner table_hash or data_hash) did not verify.</summary>
    HashMismatch,
    /// <summary>No inner (or top-level) partition with the requested uid.</summary>
    NotFound,
    /// <summary>A uid is used by more than one partition file-wide.</summary>
    DuplicateUid,
    /// <summary>An inner partition is itself a DCP container (nesting forbidden).</summary>
    NestedContainer,
    /// <summary>A partition uid is the PCF NIL uid.</summary>
    NilUid,
    /// <summary>A partition type is the PCF reserved type <c>0x00000000</c>.</summary>
    ReservedType,
    /// <summary>A top-level partition expected to be a DCP container is not one.</summary>
    NotADcpContainer,
    /// <summary>A logical edit addressed a position beyond the partition's content.</summary>
    PositionOutOfRange,
}

/// <summary>All ways a PCF-DCP operation can fail.</summary>
public sealed class PcfDcpException : Exception
{
    /// <summary>The kind of failure.</summary>
    public PcfDcpErrorKind Kind { get; }

    private PcfDcpException(PcfDcpErrorKind kind, string message) : base(message)
    {
        Kind = kind;
    }

    internal static PcfDcpException BadDcpMagic() =>
        new PcfDcpException(PcfDcpErrorKind.BadDcpMagic, "arena does not begin with \"PDCP\" magic");

    internal static PcfDcpException UnsupportedProfileMajor(int v) =>
        new PcfDcpException(PcfDcpErrorKind.UnsupportedProfileMajor,
            $"unsupported PCF-DCP profile major version {v}");

    internal static PcfDcpException BadFragmentKind(int k) =>
        new PcfDcpException(PcfDcpErrorKind.BadFragmentKind, $"unsupported fragment kind {k}");

    internal static PcfDcpException OffsetOutOfRange() =>
        new PcfDcpException(PcfDcpErrorKind.OffsetOutOfRange, "extent range escapes the arena");

    internal static PcfDcpException LengthMismatch(long expected, long got) =>
        new PcfDcpException(PcfDcpErrorKind.LengthMismatch,
            $"logical length mismatch: expected {expected}, got {got}");

    internal static PcfDcpException HashMismatch() =>
        new PcfDcpException(PcfDcpErrorKind.HashMismatch, "stored hash does not verify");

    internal static PcfDcpException NotFound() =>
        new PcfDcpException(PcfDcpErrorKind.NotFound, "no partition with that uid");

    internal static PcfDcpException DuplicateUid() =>
        new PcfDcpException(PcfDcpErrorKind.DuplicateUid, "uid is not unique file-wide");

    internal static PcfDcpException NestedContainer() =>
        new PcfDcpException(PcfDcpErrorKind.NestedContainer,
            "an inner partition may not be a DCP container");

    internal static PcfDcpException NilUid() =>
        new PcfDcpException(PcfDcpErrorKind.NilUid, "uid is the NIL uid");

    internal static PcfDcpException ReservedType() =>
        new PcfDcpException(PcfDcpErrorKind.ReservedType,
            "partition type is the reserved type 0x00000000");

    internal static PcfDcpException NotADcpContainer() =>
        new PcfDcpException(PcfDcpErrorKind.NotADcpContainer, "partition is not a DCP container");

    internal static PcfDcpException PositionOutOfRange() =>
        new PcfDcpException(PcfDcpErrorKind.PositionOutOfRange,
            "logical position is past end of content");
}
