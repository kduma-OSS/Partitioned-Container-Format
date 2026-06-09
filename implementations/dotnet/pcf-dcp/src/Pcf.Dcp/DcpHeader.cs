using System;

namespace Pcf.Dcp;

/// <summary>The fixed 24-byte DCP Header at arena offset 0 (spec Section 6).</summary>
public sealed class DcpHeader
{
    /// <summary>PCF-DCP profile major version.</summary>
    public byte ProfileVersionMajor { get; set; }

    /// <summary>PCF-DCP profile minor version.</summary>
    public byte ProfileVersionMinor { get; set; }

    /// <summary>Reserved; MUST be 0 in v1.0.</summary>
    public ushort Flags { get; set; }

    /// <summary>Arena-relative offset of the first Inner Table Block (0 = none).</summary>
    public ulong InnerTableOffset { get; set; }

    /// <summary>Bump pointer: arena-relative offset of the first free byte.</summary>
    public ulong ArenaUsed { get; set; }

    /// <summary>Serialise to the on-disk 24-byte layout.</summary>
    public byte[] ToBytes()
    {
        var b = new byte[Constants.DcpHeaderSize];
        Buffer.BlockCopy(Constants.DcpMagic, 0, b, 0, 4);
        b[4] = ProfileVersionMajor;
        b[5] = ProfileVersionMinor;
        LittleEndian.WriteU16(b, 6, Flags);
        LittleEndian.WriteU64(b, 8, InnerTableOffset);
        LittleEndian.WriteU64(b, 16, ArenaUsed);
        return b;
    }

    /// <summary>Parse from the on-disk 24-byte layout, validating the magic.</summary>
    public static DcpHeader FromBytes(byte[] b)
    {
        for (int i = 0; i < 4; i++)
        {
            if (b[i] != Constants.DcpMagic[i])
            {
                throw PcfDcpException.BadDcpMagic();
            }
        }
        return new DcpHeader
        {
            ProfileVersionMajor = b[4],
            ProfileVersionMinor = b[5],
            Flags = LittleEndian.ReadU16(b, 6),
            InnerTableOffset = LittleEndian.ReadU64(b, 8),
            ArenaUsed = LittleEndian.ReadU64(b, 16),
        };
    }

    /// <summary>Read a DCP Header from the start of an arena byte array.</summary>
    public static DcpHeader Read(byte[] arena)
    {
        if (arena.Length < Constants.DcpHeaderSize)
        {
            throw PcfDcpException.BadDcpMagic();
        }
        var fixedBytes = new byte[Constants.DcpHeaderSize];
        Buffer.BlockCopy(arena, 0, fixedBytes, 0, Constants.DcpHeaderSize);
        return FromBytes(fixedBytes);
    }
}
