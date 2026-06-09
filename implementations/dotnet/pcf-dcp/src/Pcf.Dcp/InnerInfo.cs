using System.Collections.Generic;
using Pcf;

namespace Pcf.Dcp;

/// <summary>A read-only view of one extent, for tooling and tests.</summary>
public sealed class ExtentInfo
{
    /// <summary>Arena/pool-relative offset of the extent.</summary>
    public ulong ExtentOffset { get; set; }

    /// <summary>Length of the extent in bytes.</summary>
    public ulong ExtentLength { get; set; }

    /// <summary>Extent kind (<c>1</c> = DATA).</summary>
    public byte Kind { get; set; }

    /// <summary>Whether the SHARED flag is set.</summary>
    public bool Shared { get; set; }
}

/// <summary>A read-only view of one inner partition.</summary>
public sealed class InnerInfo
{
    /// <summary>Application partition type.</summary>
    public uint PartitionType { get; set; }

    /// <summary>16-byte uid (unique file-wide).</summary>
    public byte[] Uid { get; set; }

    /// <summary>Decoded label.</summary>
    public string Label { get; set; }

    /// <summary>Logical content length (= <c>used_bytes</c>).</summary>
    public ulong UsedBytes { get; set; }

    /// <summary>Hash algorithm protecting the logical content.</summary>
    public HashAlgo DataHashAlgo { get; set; }

    /// <summary>The 64-byte data-hash field over the logical content.</summary>
    public byte[] DataHash { get; set; }

    /// <summary>The partition's extents in logical order.</summary>
    public List<ExtentInfo> Extents { get; set; }
}
