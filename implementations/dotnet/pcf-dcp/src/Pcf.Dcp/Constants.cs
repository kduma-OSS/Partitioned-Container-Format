namespace Pcf.Dcp;

/// <summary>
/// On-disk constants defined by PCF-DCP v1.0 (spec Appendix A and B). Every
/// value here is normative.
/// </summary>
public static class Constants
{
    /// <summary>PCF partition type carrying one DCP arena.</summary>
    public const uint DcpContainerType = 0xAAAC_0001;

    /// <summary>First value reserved by this profile for future types.</summary>
    public const uint DcpTypeReservedLo = 0xAAAC_0000;

    /// <summary>Last value reserved by this profile.</summary>
    public const uint DcpTypeReservedHi = 0xAAAC_00FF;

    /// <summary>4-byte magic at the start of a DCP arena: <c>"PDCP"</c>.</summary>
    public static readonly byte[] DcpMagic = { 0x50, 0x44, 0x43, 0x50 };

    /// <summary>PCF-DCP profile version implemented by this library (major).</summary>
    public const byte ProfileVersionMajor = 1;

    /// <summary>PCF-DCP profile version implemented by this library (minor).</summary>
    public const byte ProfileVersionMinor = 0;

    /// <summary>Fixed size of the DCP Header, in bytes (spec Section 6).</summary>
    public const int DcpHeaderSize = 24;

    /// <summary>Fixed size of a Fragment Table block header, in bytes.</summary>
    public const int FragTableHeaderSize = 9;

    /// <summary>Fixed size of one Fragment Entry, in bytes.</summary>
    public const int FragmentEntrySize = 18;

    /// <summary>Fragment Entry kind: RESERVED / INVALID guard.</summary>
    public const byte KindInvalid = 0;

    /// <summary>Fragment Entry kind: DATA — literal content (only kind in v1.0).</summary>
    public const byte KindData = 1;

    /// <summary>Fragment Entry kind: HOLE (RESERVED).</summary>
    public const byte KindHole = 2;

    /// <summary>Fragment Entry kind: REF (RESERVED).</summary>
    public const byte KindRef = 3;

    /// <summary>Fragment Entry <c>flags</c> bit 0: SHARED (copy-on-write required).</summary>
    public const byte FlagShared = 0x01;

    /// <summary>The arena-relative offset value reserved as "none" / terminator.</summary>
    public const ulong ArenaNone = 0;

    /// <summary>Max entries per (inner) Table Block and extents per Fragment block.</summary>
    public const int MaxEntriesPerBlock = 255;
}
