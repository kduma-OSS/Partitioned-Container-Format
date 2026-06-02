using System;
using System.Collections.Generic;

namespace Pcf;

/// <summary>
/// The 74-byte table-block header (spec sections 5.1, 8.4). The block's
/// partition entries follow it on disk.
/// </summary>
public sealed class TableBlockHeader
{
    /// <summary>Number of entries stored in this block (0..255).</summary>
    public byte PartitionCount { get; set; }

    /// <summary>Absolute offset of the next block, or 0 for end-of-chain.</summary>
    public ulong NextTableOffset { get; set; }

    /// <summary>Algorithm used for <see cref="TableHash"/>.</summary>
    public HashAlgo TableHashAlgo { get; set; }

    /// <summary>64-byte table-hash field.</summary>
    public byte[] TableHash { get; set; } = new byte[Constants.HashFieldSize];

    /// <summary>Serialise to the on-disk 74-byte layout.</summary>
    public byte[] ToBytes()
    {
        var b = new byte[74];
        b[0] = PartitionCount;
        LittleEndian.WriteU64(b, 1, NextTableOffset);
        b[9] = TableHashAlgo.Id();
        Buffer.BlockCopy(TableHash, 0, b, 10, Constants.HashFieldSize);
        return b;
    }

    /// <summary>Parse from the on-disk 74-byte layout.</summary>
    public static TableBlockHeader FromBytes(byte[] b)
    {
        var h = new TableBlockHeader
        {
            PartitionCount = b[0],
            NextTableOffset = LittleEndian.ReadU64(b, 1),
            TableHashAlgo = HashAlgoExtensions.FromId(b[9]),
        };
        Buffer.BlockCopy(b, 10, h.TableHash, 0, Constants.HashFieldSize);
        return h;
    }

    /// <summary>
    /// Compute the table hash over <c>[header-with-zeroed-hash || entries]</c>
    /// (spec section 8.4). The <c>table_hash_algo</c> byte is included; the
    /// 64-byte hash field is treated as zero; trailing reserved space is excluded.
    /// </summary>
    public static byte[] ComputeTableHash(
        HashAlgo algo, ulong nextTableOffset, IReadOnlyList<PartitionEntry> entries)
    {
        var header = new TableBlockHeader
        {
            PartitionCount = (byte)entries.Count,
            NextTableOffset = nextTableOffset,
            TableHashAlgo = algo,
            TableHash = new byte[Constants.HashFieldSize], // zeroed for the computation
        };
        var image = new byte[74 + entries.Count * 141];
        Buffer.BlockCopy(header.ToBytes(), 0, image, 0, 74);
        int off = 74;
        for (int i = 0; i < entries.Count; i++)
        {
            Buffer.BlockCopy(entries[i].ToBytes(), 0, image, off, 141);
            off += 141;
        }
        return algo.Compute(image);
    }
}
