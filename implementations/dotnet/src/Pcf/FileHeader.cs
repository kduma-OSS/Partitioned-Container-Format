using System;

namespace Pcf;

/// <summary>The fixed 20-byte file header (spec section 4).</summary>
public sealed class FileHeader
{
    /// <summary>Major format version.</summary>
    public ushort VersionMajor { get; set; }

    /// <summary>Minor format version.</summary>
    public ushort VersionMinor { get; set; }

    /// <summary>Absolute offset of the first table block.</summary>
    public ulong PartitionTableOffset { get; set; }

    /// <summary>Serialise to the on-disk 20-byte layout.</summary>
    public byte[] ToBytes()
    {
        var b = new byte[20];
        Buffer.BlockCopy(Constants.Magic, 0, b, 0, 8);
        LittleEndian.WriteU16(b, 8, VersionMajor);
        LittleEndian.WriteU16(b, 10, VersionMinor);
        LittleEndian.WriteU64(b, 12, PartitionTableOffset);
        return b;
    }

    /// <summary>
    /// Parse from the on-disk 20-byte layout, validating magic and major
    /// version (spec conformance checks C1, C2).
    /// </summary>
    public static FileHeader FromBytes(byte[] b)
    {
        for (int i = 0; i < 8; i++)
        {
            if (b[i] != Constants.Magic[i])
            {
                throw PcfException.BadMagic();
            }
        }
        ushort major = LittleEndian.ReadU16(b, 8);
        if (major != Constants.VersionMajor)
        {
            throw PcfException.UnsupportedMajor(major);
        }
        return new FileHeader
        {
            VersionMajor = major,
            VersionMinor = LittleEndian.ReadU16(b, 10),
            PartitionTableOffset = LittleEndian.ReadU64(b, 12),
        };
    }
}
