namespace Pcf.Dcp;

/// <summary>One Fragment Entry: a single extent of an inner partition (spec 8.2).</summary>
public sealed class FragmentEntry
{
    /// <summary>Arena-relative start of the extent's bytes.</summary>
    public ulong ExtentOffset { get; set; }

    /// <summary>Length of the extent in bytes.</summary>
    public ulong ExtentLength { get; set; }

    /// <summary>Extent kind (<c>1</c> = DATA; <c>0</c> invalid; <c>2</c>/<c>3</c> reserved).</summary>
    public byte Kind { get; set; }

    /// <summary><c>flags</c> byte (bit 0 = SHARED; others reserved 0).</summary>
    public byte Flags { get; set; }

    /// <summary>Serialise to the on-disk 18-byte layout.</summary>
    public byte[] ToBytes()
    {
        var b = new byte[Constants.FragmentEntrySize];
        LittleEndian.WriteU64(b, 0, ExtentOffset);
        LittleEndian.WriteU64(b, 8, ExtentLength);
        b[16] = Kind;
        b[17] = Flags;
        return b;
    }

    /// <summary>Parse from the on-disk 18-byte layout.</summary>
    public static FragmentEntry FromBytes(byte[] b, int offset = 0)
    {
        return new FragmentEntry
        {
            ExtentOffset = LittleEndian.ReadU64(b, offset + 0),
            ExtentLength = LittleEndian.ReadU64(b, offset + 8),
            Kind = b[offset + 16],
            Flags = b[offset + 17],
        };
    }

    /// <summary>Whether this entry's <c>kind</c> is DATA.</summary>
    public bool IsData() => Kind == Constants.KindData;

    /// <summary>Whether the SHARED flag (bit 0) is set.</summary>
    public bool IsShared() => (Flags & Constants.FlagShared) != 0;
}
