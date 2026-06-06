namespace Pcf;

/// <summary>
/// On-disk constants defined by PCF v1.0. Every value here is normative and
/// corresponds directly to a figure in the specification (Appendix A,
/// "Field Layout Summary").
/// </summary>
public static class Constants
{
    /// <summary>File signature, 8 bytes: <c>0x89 'K' 'P' 'R' 'T' 0x0D 0x0A 0x1A</c>.</summary>
    public static readonly byte[] Magic =
        { 0x89, (byte)'K', (byte)'P', (byte)'R', (byte)'T', 0x0D, 0x0A, 0x1A };

    /// <summary>Major format version implemented by this library.</summary>
    public const ushort VersionMajor = 1;

    /// <summary>Minor format version implemented by this library.</summary>
    public const ushort VersionMinor = 0;

    /// <summary>Fixed size of the file header, in bytes.</summary>
    public const long HeaderSize = 20;

    /// <summary>Fixed size of a table-block header, in bytes.</summary>
    public const long TableHeaderSize = 74;

    /// <summary>Fixed size of a single partition entry, in bytes.</summary>
    public const long EntrySize = 141;

    /// <summary>Size of every hash field, in bytes (large enough for the widest digest).</summary>
    public const int HashFieldSize = 64;

    /// <summary>Size of the partition label field, in bytes.</summary>
    public const int LabelSize = 32;

    /// <summary>Size of the partition UID field, in bytes.</summary>
    public const int UidSize = 16;

    /// <summary>Reserved partition type: invalid / uninitialised. MUST NOT label a live partition.</summary>
    public const uint TypeReserved = 0x0000_0000;

    /// <summary>Reserved partition type: raw / blob, interpreted entirely by the application.</summary>
    public const uint TypeRaw = 0xFFFF_FFFF;

    /// <summary>
    /// Maximum number of entries a single table block can hold
    /// (<c>partition_count</c> is a <c>u8</c>).
    /// </summary>
    public const uint MaxEntriesPerBlock = 255;

    /// <summary>The NIL UID (all zero). MUST NOT label a live partition.</summary>
    public static readonly byte[] NilUid = new byte[UidSize];

    /// <summary>
    /// Sentinel value of <c>partition_table_offset</c> (header offset 12) meaning
    /// the partition-table head is recorded in the file <see cref="Trailer"/> at
    /// the end of the file rather than in the header (spec section 4, "File
    /// Trailer"). The all-ones u64 can never be a real offset, so it is
    /// unambiguous.
    /// </summary>
    public const ulong PtOffsetTrailer = 0xFFFF_FFFF_FFFF_FFFF;

    /// <summary>Fixed size of the optional file trailer, in bytes.</summary>
    public const long TrailerSize = 20;

    /// <summary>
    /// Trailer signature, 8 bytes: the file <see cref="Magic"/> reversed
    /// (<c>0x1A 0x0A 0x0D 'T' 'R' 'P' 'K' 0x89</c>). Placed as the final 8 bytes
    /// of the file so a reader can detect and validate the trailer at the end.
    /// </summary>
    public static readonly byte[] TrailerMagic =
        { 0x1A, 0x0A, 0x0D, (byte)'T', (byte)'R', (byte)'P', (byte)'K', 0x89 };

    /// <summary>Chain-direction flag: forward chain, head = first block.</summary>
    public const byte ChainForward = 0;

    /// <summary>Chain-direction flag: backward chain, head = last/newest block.</summary>
    public const byte ChainBackward = 1;
}
