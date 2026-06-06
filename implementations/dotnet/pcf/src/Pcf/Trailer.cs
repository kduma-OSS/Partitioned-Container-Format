using System;

namespace Pcf;

/// <summary>
/// The optional fixed 20-byte file trailer (spec section 4, "File Trailer").
///
/// <para>A trailer is present only when the file header's
/// <c>partition_table_offset</c> holds the <see cref="Constants.PtOffsetTrailer"/>
/// sentinel. It occupies the final <see cref="Constants.TrailerSize"/> bytes of
/// the file and records the real offset of the partition-table head together
/// with the chain direction. Because every append places a fresh trailer at the
/// new end of file, the file's last bytes always point at the newest table —
/// enabling append-only writers with no in-place header rewrite.</para>
/// </summary>
public sealed class Trailer
{
    /// <summary>Absolute offset of the partition-table head (0 = empty container).</summary>
    public ulong PartitionTableOffset { get; set; }

    /// <summary>Chain-direction flags; bit 0 selects forward (0) or backward (1).</summary>
    public byte ChainFlags { get; set; }

    /// <summary>Serialise to the on-disk 20-byte layout (reserved bytes 9..12 are zero).</summary>
    public byte[] ToBytes()
    {
        var b = new byte[20];
        LittleEndian.WriteU64(b, 0, PartitionTableOffset);
        b[8] = ChainFlags;
        Buffer.BlockCopy(Constants.TrailerMagic, 0, b, 12, 8);
        return b;
    }

    /// <summary>
    /// Parse from the on-disk 20-byte layout, validating the trailer magic.
    /// Throws <see cref="PcfException"/> (BadTrailer) if the magic does not match.
    /// </summary>
    public static Trailer FromBytes(byte[] b)
    {
        if (b.Length < Constants.TrailerSize)
        {
            throw PcfException.BadTrailer();
        }
        for (int i = 0; i < 8; i++)
        {
            if (b[12 + i] != Constants.TrailerMagic[i])
            {
                throw PcfException.BadTrailer();
            }
        }
        return new Trailer
        {
            PartitionTableOffset = LittleEndian.ReadU64(b, 0),
            ChainFlags = b[8],
        };
    }
}
