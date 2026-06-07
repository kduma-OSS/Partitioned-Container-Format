using System;

namespace Pcf;

/// <summary>
/// The kind of a <see cref="PcfException"/>. Mirrors the variants of the
/// reference implementation's error enum so callers can branch on the exact
/// failure mode.
/// </summary>
public enum PcfError
{
    /// <summary>The file does not begin with the PCF magic.</summary>
    BadMagic,

    /// <summary>The file's major version is not implemented by this library.</summary>
    UnsupportedMajor,

    /// <summary>A hash-algorithm identifier is not in the registry.</summary>
    UnknownHashAlgo,

    /// <summary>A live entry used the reserved type <c>0x00000000</c>.</summary>
    ReservedType,

    /// <summary>A live entry used the NIL UID.</summary>
    NilUid,

    /// <summary><c>used_bytes</c> exceeded <c>max_length</c> for an entry.</summary>
    UsedExceedsMax,

    /// <summary>A label byte was outside the permitted range (>= 0x80), or too long.</summary>
    InvalidLabel,

    /// <summary>A table block failed hash verification.</summary>
    TableHashMismatch,

    /// <summary>A partition's data failed hash verification.</summary>
    DataHashMismatch,

    /// <summary>An in-place update supplied more data than the partition's reservation.</summary>
    DataTooLarge,

    /// <summary>No partition with the requested UID exists.</summary>
    NotFound,

    /// <summary>An attempt was made to add a partition whose UID already exists.</summary>
    DuplicateUid,

    /// <summary>The header requested trailer-based location but no valid trailer exists.</summary>
    BadTrailer,
}

/// <summary>An error raised by a PCF reader or writer operation.</summary>
public sealed class PcfException : Exception
{
    /// <summary>The category of failure.</summary>
    public PcfError Kind { get; }

    /// <summary>Create a new <see cref="PcfException"/>.</summary>
    public PcfException(PcfError kind, string message) : base(message)
    {
        Kind = kind;
    }

    internal static PcfException BadMagic() =>
        new(PcfError.BadMagic, "bad magic: not a PCF file");

    internal static PcfException UnsupportedMajor(ushort v) =>
        new(PcfError.UnsupportedMajor, $"unsupported major version {v}");

    internal static PcfException UnknownHashAlgo(byte id) =>
        new(PcfError.UnknownHashAlgo, $"unknown hash algorithm id {id}");

    internal static PcfException ReservedType() =>
        new(PcfError.ReservedType, "reserved partition type used for a live entry");

    internal static PcfException NilUid() =>
        new(PcfError.NilUid, "NIL UID used for a live entry");

    internal static PcfException UsedExceedsMax() =>
        new(PcfError.UsedExceedsMax, "used_bytes exceeds max_length");

    internal static PcfException InvalidLabel() =>
        new(PcfError.InvalidLabel, "invalid label");

    internal static PcfException TableHashMismatch() =>
        new(PcfError.TableHashMismatch, "table block hash mismatch");

    internal static PcfException DataHashMismatch() =>
        new(PcfError.DataHashMismatch, "partition data hash mismatch");

    internal static PcfException DataTooLarge() =>
        new(PcfError.DataTooLarge, "data larger than partition reservation");

    internal static PcfException NotFound() =>
        new(PcfError.NotFound, "partition not found");

    internal static PcfException DuplicateUid() =>
        new(PcfError.DuplicateUid, "duplicate UID");

    internal static PcfException BadTrailer() =>
        new(PcfError.BadTrailer, "missing or invalid file trailer");
}
