using System.Collections.Generic;

namespace Pcf;

/// <summary>
/// One table block read from disk: its absolute <see cref="Offset"/>, its parsed
/// <see cref="TableBlockHeader"/> (including <c>table_hash</c> and
/// <c>next_table_offset</c>), and its <see cref="PartitionEntry"/> list.
/// </summary>
/// <remarks>
/// This is a read-only view returned by <see cref="Container.ReadBlockAt"/>. It
/// exists so that profiles layered on PCF (which must group blocks, inspect each
/// block's <c>table_hash</c>, and follow non-default <c>next_table_offset</c>
/// chains) can reuse PCF's block parsing rather than re-decoding raw bytes. It
/// plays no part in the writer's in-memory bookkeeping.
/// </remarks>
public sealed class BlockView
{
    /// <summary>Absolute file offset of the table block.</summary>
    public ulong Offset { get; }

    /// <summary>Parsed 74-byte block header.</summary>
    public TableBlockHeader Header { get; }

    /// <summary>The block's entries, in stored order.</summary>
    public IReadOnlyList<PartitionEntry> Entries { get; }

    /// <summary>Create a block view.</summary>
    public BlockView(ulong offset, TableBlockHeader header, IReadOnlyList<PartitionEntry> entries)
    {
        Offset = offset;
        Header = header;
        Entries = entries;
    }
}
