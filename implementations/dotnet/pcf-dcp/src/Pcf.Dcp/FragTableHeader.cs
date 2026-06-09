using System;
using System.Collections.Generic;

namespace Pcf.Dcp;

/// <summary>The 9-byte header that begins each Fragment Table block (spec 8.1).</summary>
public sealed class FragTableHeader
{
    /// <summary>Arena-relative offset of the next block of this partition, or 0.</summary>
    public ulong NextFragtableOffset { get; set; }

    /// <summary>Number of Fragment Entries packed immediately after this header.</summary>
    public byte FragmentCount { get; set; }

    /// <summary>Serialise to the on-disk 9-byte layout.</summary>
    public byte[] ToBytes()
    {
        var b = new byte[Constants.FragTableHeaderSize];
        LittleEndian.WriteU64(b, 0, NextFragtableOffset);
        b[8] = FragmentCount;
        return b;
    }

    /// <summary>Parse from the on-disk 9-byte layout.</summary>
    public static FragTableHeader FromBytes(byte[] b, int offset = 0)
    {
        return new FragTableHeader
        {
            NextFragtableOffset = LittleEndian.ReadU64(b, offset + 0),
            FragmentCount = b[offset + 8],
        };
    }
}

/// <summary>Static helpers for walking and reconstructing Fragment Tables.</summary>
public static class FragmentTable
{
    /// <summary>
    /// Walk an inner partition's Fragment Table chain starting at arena-relative
    /// <paramref name="firstOff"/>, returning its entries in logical order.
    /// </summary>
    public static List<FragmentEntry> Walk(byte[] arena, ulong firstOff)
    {
        var outList = new List<FragmentEntry>();
        ulong off = firstOff;
        int budget = arena.Length / Constants.FragTableHeaderSize + 1;
        while (off != Constants.ArenaNone)
        {
            if (budget == 0)
            {
                throw PcfDcpException.OffsetOutOfRange();
            }
            budget -= 1;
            int baseOff = checked((int)off);
            if (baseOff + Constants.FragTableHeaderSize > arena.Length)
            {
                throw PcfDcpException.OffsetOutOfRange();
            }
            var h = FragTableHeader.FromBytes(arena, baseOff);
            int eo = baseOff + Constants.FragTableHeaderSize;
            for (int i = 0; i < h.FragmentCount; i++)
            {
                if (eo + Constants.FragmentEntrySize > arena.Length)
                {
                    throw PcfDcpException.OffsetOutOfRange();
                }
                outList.Add(FragmentEntry.FromBytes(arena, eo));
                eo += Constants.FragmentEntrySize;
            }
            off = h.NextFragtableOffset;
        }
        return outList;
    }

    /// <summary>
    /// Reconstruct the logical content from Fragment Entries (spec Section 8.3):
    /// concatenate the bytes of the DATA extents in order.
    /// </summary>
    public static byte[] Reconstruct(byte[] arena, IReadOnlyList<FragmentEntry> frags, ulong arenaUsed)
    {
        long total = 0;
        foreach (var f in frags)
        {
            if (!f.IsData())
            {
                throw PcfDcpException.BadFragmentKind(f.Kind);
            }
            ulong end = f.ExtentOffset + f.ExtentLength;
            if (end > arenaUsed || end > (ulong)arena.Length)
            {
                throw PcfDcpException.OffsetOutOfRange();
            }
            total += (long)f.ExtentLength;
        }
        var outBytes = new byte[total];
        int p = 0;
        foreach (var f in frags)
        {
            Buffer.BlockCopy(arena, (int)f.ExtentOffset, outBytes, p, (int)f.ExtentLength);
            p += (int)f.ExtentLength;
        }
        return outBytes;
    }
}
