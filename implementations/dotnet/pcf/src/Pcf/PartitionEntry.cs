using System;
using System.Text;

namespace Pcf;

/// <summary>One partition's metadata: the fixed 141-byte entry (spec section 5.2).</summary>
public sealed class PartitionEntry
{
    /// <summary>Application-defined type (<c>0</c> and <c>0xFFFFFFFF</c> are reserved).</summary>
    public uint PartitionType { get; set; }

    /// <summary>16-byte unique identifier.</summary>
    public byte[] Uid { get; set; } = new byte[Constants.UidSize];

    /// <summary>32-byte ASCII label, NUL-padded.</summary>
    public byte[] Label { get; set; } = new byte[Constants.LabelSize];

    /// <summary>Absolute offset of the partition's data region.</summary>
    public ulong StartOffset { get; set; }

    /// <summary>Bytes reserved for the partition.</summary>
    public ulong MaxLength { get; set; }

    /// <summary>Bytes currently used (a contiguous prefix of the reservation).</summary>
    public ulong UsedBytes { get; set; }

    /// <summary>Algorithm used for <see cref="DataHash"/>.</summary>
    public HashAlgo DataHashAlgo { get; set; }

    /// <summary>64-byte data-hash field.</summary>
    public byte[] DataHash { get; set; } = new byte[Constants.HashFieldSize];

    /// <summary>Serialise to the on-disk 141-byte layout.</summary>
    public byte[] ToBytes()
    {
        var b = new byte[141];
        LittleEndian.WriteU32(b, 0, PartitionType);
        Buffer.BlockCopy(Uid, 0, b, 4, Constants.UidSize);
        Buffer.BlockCopy(Label, 0, b, 20, Constants.LabelSize);
        LittleEndian.WriteU64(b, 52, StartOffset);
        LittleEndian.WriteU64(b, 60, MaxLength);
        LittleEndian.WriteU64(b, 68, UsedBytes);
        b[76] = DataHashAlgo.Id();
        Buffer.BlockCopy(DataHash, 0, b, 77, Constants.HashFieldSize);
        return b;
    }

    /// <summary>Parse from the on-disk 141-byte layout.</summary>
    public static PartitionEntry FromBytes(byte[] b)
    {
        var e = new PartitionEntry
        {
            PartitionType = LittleEndian.ReadU32(b, 0),
            StartOffset = LittleEndian.ReadU64(b, 52),
            MaxLength = LittleEndian.ReadU64(b, 60),
            UsedBytes = LittleEndian.ReadU64(b, 68),
            DataHashAlgo = HashAlgoExtensions.FromId(b[76]),
        };
        Buffer.BlockCopy(b, 4, e.Uid, 0, Constants.UidSize);
        Buffer.BlockCopy(b, 20, e.Label, 0, Constants.LabelSize);
        Buffer.BlockCopy(b, 77, e.DataHash, 0, Constants.HashFieldSize);
        return e;
    }

    /// <summary>
    /// Apply the conformance checks a reader must run on a live entry
    /// (spec C5, C6, C7).
    /// </summary>
    public void Validate()
    {
        if (PartitionType == Constants.TypeReserved)
        {
            throw PcfException.ReservedType();
        }
        if (IsNilUid(Uid))
        {
            throw PcfException.NilUid();
        }
        if (UsedBytes > MaxLength)
        {
            throw PcfException.UsedExceedsMax();
        }
        DecodeLabel(Label); // validates label bytes
    }

    /// <summary>Decode the label as a string (reads up to the first NUL).</summary>
    public string LabelString() => DecodeLabel(Label);

    /// <summary>Free bytes remaining in the partition (<c>max_length - used_bytes</c>).</summary>
    public ulong FreeBytes() => MaxLength >= UsedBytes ? MaxLength - UsedBytes : 0;

    /// <summary>Whether <paramref name="uid"/> is the all-zero NIL UID.</summary>
    internal static bool IsNilUid(byte[] uid)
    {
        foreach (byte x in uid)
        {
            if (x != 0)
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>Build a 32-byte label field from a string (spec section 10).</summary>
    public static byte[] EncodeLabel(string s)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(s ?? string.Empty);
        if (bytes.Length > Constants.LabelSize)
        {
            throw PcfException.InvalidLabel();
        }
        foreach (byte c in bytes)
        {
            if (c == 0 || c >= 0x80)
            {
                throw PcfException.InvalidLabel();
            }
        }
        var l = new byte[Constants.LabelSize];
        Buffer.BlockCopy(bytes, 0, l, 0, bytes.Length);
        return l;
    }

    /// <summary>
    /// Decode a 32-byte label field: read until the first NUL or 32 bytes,
    /// rejecting any byte >= 0x80 (spec section 10).
    /// </summary>
    public static string DecodeLabel(byte[] label)
    {
        int end = Constants.LabelSize;
        for (int i = 0; i < label.Length; i++)
        {
            if (label[i] == 0)
            {
                end = i;
                break;
            }
            if (label[i] >= 0x80)
            {
                throw PcfException.InvalidLabel();
            }
        }
        return Encoding.ASCII.GetString(label, 0, end);
    }
}
