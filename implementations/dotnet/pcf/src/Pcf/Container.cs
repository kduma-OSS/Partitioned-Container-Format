using System;
using System.Collections.Generic;
using System.IO;

namespace Pcf;

/// <summary>
/// A PCF container backed by a seekable <see cref="Stream"/> (the C# analogue
/// of the reference implementation's <c>Read + Write + Seek</c> store; both
/// <see cref="MemoryStream"/> and <see cref="FileStream"/> work).
///
/// <para>The reader side (<see cref="Open"/>, <see cref="Entries"/>,
/// <see cref="ReadPartitionData"/>, <see cref="Verify"/>) is fully general and
/// accepts any conforming file, including arbitrary region placement and
/// overflow-block chains.</para>
///
/// <para>The writer side implements one documented placement strategy (the
/// format deliberately leaves layout to the writer, spec section 12 / A7, A9):
/// the first table block sits immediately after the header with reserved
/// capacity; partition data is appended at a growing end-of-data cursor; when
/// every known block is full a new overflow block is appended and linked. Block
/// capacity is not stored on disk (spec A9): after <see cref="Open"/> blocks are
/// treated as having no spare capacity, so subsequent additions go into fresh
/// overflow blocks. <see cref="CompactedImage"/> rebuilds a tightly packed file.</para>
/// </summary>
public sealed class Container
{
    /// <summary>In-memory bookkeeping for one table block (not stored on disk).</summary>
    private sealed class BlockInfo
    {
        public ulong Offset;
        public uint Capacity;
        public byte Count;
        public HashAlgo Algo;
        public ulong Next;
    }

    private readonly Stream _storage;
    private FileHeader _header;
    private List<BlockInfo> _blocks;
    private ulong _dataEof;
    private uint _defaultCapacity;
    private HashAlgo _tableHashAlgo;

    /// <summary>
    /// Resolved absolute offset of the partition-table head: the header pointer
    /// for a classic file, or the offset from the file <see cref="Trailer"/>
    /// when the header holds <see cref="Constants.PtOffsetTrailer"/>. 0 denotes
    /// an empty table.
    /// </summary>
    private ulong _tableHead;

    /// <summary>Chain-direction flags resolved at open time (see <see cref="Trailer"/>).</summary>
    private byte _chainFlags;

    private Container(Stream storage)
    {
        _storage = storage;
    }

    // ---- construction ----------------------------------------------------

    /// <summary>
    /// Create an empty container with sensible defaults (first block capacity
    /// 16, table hashing with SHA-256).
    /// </summary>
    public static Container Create(Stream storage) =>
        CreateWith(storage, 16, HashAlgo.Sha256);

    /// <summary>
    /// Create an empty container, choosing the first block's reserved capacity
    /// and the table-hash algorithm.
    /// </summary>
    public static Container CreateWith(Stream storage, uint firstBlockCapacity, HashAlgo tableHashAlgo)
    {
        uint cap = Clamp(firstBlockCapacity, 1, Constants.MaxEntriesPerBlock);
        var header = new FileHeader
        {
            VersionMajor = Constants.VersionMajor,
            VersionMinor = Constants.VersionMinor,
            PartitionTableOffset = (ulong)Constants.HeaderSize,
        };

        var c = new Container(storage) { _header = header };
        byte[] hb = header.ToBytes();
        c.WriteAt(0, hb, hb.Length);

        byte[] th = TableBlockHeader.ComputeTableHash(tableHashAlgo, 0, Array.Empty<PartitionEntry>());
        var bh = new TableBlockHeader
        {
            PartitionCount = 0,
            NextTableOffset = 0,
            TableHashAlgo = tableHashAlgo,
            TableHash = th,
        };
        byte[] bhb = bh.ToBytes();
        c.WriteAt((ulong)Constants.HeaderSize, bhb, bhb.Length);

        c._dataEof = (ulong)(Constants.HeaderSize + Constants.TableHeaderSize)
                     + (ulong)cap * (ulong)Constants.EntrySize;
        c._blocks = new List<BlockInfo>
        {
            new BlockInfo
            {
                Offset = (ulong)Constants.HeaderSize,
                Capacity = cap,
                Count = 0,
                Algo = tableHashAlgo,
                Next = 0,
            },
        };
        c._defaultCapacity = cap;
        c._tableHashAlgo = tableHashAlgo;
        c._tableHead = (ulong)Constants.HeaderSize;
        c._chainFlags = Constants.ChainForward;
        return c;
    }

    /// <summary>
    /// Open an existing container, validating the header (spec C1, C2).
    ///
    /// <para>When the header's <c>partition_table_offset</c> is the
    /// <see cref="Constants.PtOffsetTrailer"/> sentinel, the partition-table head
    /// and chain direction are read from the file <see cref="Trailer"/> (located
    /// by scanning backward from the end of the file). Chain traversal is
    /// identical in both directions (follow <c>next_table_offset</c> until 0);
    /// the direction only conveys which end is newest, exposed via
    /// <see cref="ChainIsBackward"/>.</para>
    /// </summary>
    public static Container Open(Stream storage)
    {
        var c = new Container(storage)
        {
            _blocks = new List<BlockInfo>(),
            _defaultCapacity = 16,
            _tableHashAlgo = HashAlgo.Sha256,
        };

        var hb = new byte[20];
        c.ReadAt(0, hb, 20);
        c._header = FileHeader.FromBytes(hb);

        if (c._header.PartitionTableOffset == Constants.PtOffsetTrailer)
        {
            (c._tableHead, c._chainFlags) = c.LocateTrailer();
        }
        else
        {
            c._tableHead = c._header.PartitionTableOffset;
            c._chainFlags = Constants.ChainForward;
        }

        var blocks = new List<BlockInfo>();
        ulong off = c._tableHead;
        while (off != 0)
        {
            (TableBlockHeader h, _) = c.ReadBlock(off);
            blocks.Add(new BlockInfo
            {
                Offset = off,
                Capacity = h.PartitionCount, // no known spare after open
                Count = h.PartitionCount,
                Algo = h.TableHashAlgo,
                Next = h.NextTableOffset,
            });
            off = h.NextTableOffset;
        }
        if (blocks.Count > 0)
        {
            c._tableHashAlgo = blocks[0].Algo;
        }
        c._blocks = blocks;
        c._dataEof = (ulong)c._storage.Seek(0, SeekOrigin.End);
        return c;
    }

    /// <summary>The backing store.</summary>
    public Stream Storage => _storage;

    /// <summary>
    /// The parsed file header. In trailer mode its <c>PartitionTableOffset</c>
    /// holds the <see cref="Constants.PtOffsetTrailer"/> sentinel; use
    /// <see cref="TableHead"/> for the resolved head.
    /// </summary>
    public FileHeader Header => _header;

    /// <summary>
    /// The resolved absolute offset of the partition-table head (0 if empty).
    /// This is the value to follow regardless of header-pointer vs trailer mode.
    /// </summary>
    public ulong TableHead => _tableHead;

    /// <summary>
    /// Whether the chain is backward-linked (head = newest block,
    /// <c>next_table_offset</c> points at the previous/older block). Classic
    /// header-pointer files are always forward.
    /// </summary>
    public bool ChainIsBackward => (_chainFlags & 1) != 0;

    /// <summary>
    /// Locate the most recent valid file trailer by scanning backward from the
    /// end of the file for the last 20-byte window ending in
    /// <see cref="Constants.TrailerMagic"/> whose recorded head is empty (0) or
    /// references a parseable table block. Bytes after that trailer — an
    /// incomplete or aborted append — are ignored, which gives append-only
    /// writers crash recovery for free. In the clean case the trailer is the
    /// final <see cref="Constants.TrailerSize"/> bytes.
    /// </summary>
    private (ulong, byte) LocateTrailer()
    {
        long fileLen = _storage.Seek(0, SeekOrigin.End);
        var tb = new byte[20];
        long end = fileLen;
        while (end >= Constants.TrailerSize)
        {
            long start = end - Constants.TrailerSize;
            ReadAt((ulong)start, tb, 20);
            bool magicOk = true;
            for (int i = 0; i < 8; i++)
            {
                if (tb[12 + i] != Constants.TrailerMagic[i])
                {
                    magicOk = false;
                    break;
                }
            }
            if (magicOk)
            {
                Trailer t = Trailer.FromBytes(tb);
                if (t.PartitionTableOffset == 0)
                {
                    return (0, t.ChainFlags);
                }
                // Guard against the magic appearing inside an aborted tail: the
                // recorded head must precede this trailer and parse as a block.
                if (start >= Constants.TableHeaderSize
                    && t.PartitionTableOffset <= (ulong)(start - Constants.TableHeaderSize))
                {
                    try
                    {
                        var bhb = new byte[74];
                        ReadAt(t.PartitionTableOffset, bhb, 74);
                        TableBlockHeader.FromBytes(bhb);
                        return (t.PartitionTableOffset, t.ChainFlags);
                    }
                    catch (PcfException)
                    {
                        // Spurious magic in an aborted tail; keep scanning.
                    }
                }
            }
            end -= 1;
        }
        throw PcfException.BadTrailer();
    }

    // ---- low-level I/O ----------------------------------------------------

    private void ReadAt(ulong off, byte[] buf, int len)
    {
        _storage.Seek((long)off, SeekOrigin.Begin);
        ReadExact(_storage, buf, len);
    }

    private void WriteAt(ulong off, byte[] buf, int len)
    {
        _storage.Seek((long)off, SeekOrigin.Begin);
        _storage.Write(buf, 0, len);
    }

    private static void ReadExact(Stream s, byte[] buf, int len)
    {
        int total = 0;
        while (total < len)
        {
            int n = s.Read(buf, total, len - total);
            if (n == 0)
            {
                throw new EndOfStreamException("unexpected end of PCF stream");
            }
            total += n;
        }
    }

    private (TableBlockHeader, List<PartitionEntry>) ReadBlock(ulong off)
    {
        var hb = new byte[74];
        ReadAt(off, hb, 74);
        TableBlockHeader h = TableBlockHeader.FromBytes(hb);
        var entries = new List<PartitionEntry>(h.PartitionCount);
        var eb = new byte[141];
        for (ulong i = 0; i < h.PartitionCount; i++)
        {
            ReadAt(off + (ulong)Constants.TableHeaderSize + i * (ulong)Constants.EntrySize, eb, 141);
            entries.Add(PartitionEntry.FromBytes(eb));
        }
        return (h, entries);
    }

    private void WriteBlock(ulong off, ulong next, HashAlgo algo, IReadOnlyList<PartitionEntry> entries)
    {
        byte[] hash = TableBlockHeader.ComputeTableHash(algo, next, entries);
        var header = new TableBlockHeader
        {
            PartitionCount = (byte)entries.Count,
            NextTableOffset = next,
            TableHashAlgo = algo,
            TableHash = hash,
        };
        byte[] hb = header.ToBytes();
        WriteAt(off, hb, hb.Length);

        var buf = new byte[entries.Count * 141];
        for (int i = 0; i < entries.Count; i++)
        {
            Buffer.BlockCopy(entries[i].ToBytes(), 0, buf, i * 141, 141);
        }
        WriteAt(off + (ulong)Constants.TableHeaderSize, buf, buf.Length);
    }

    // ---- reading ----------------------------------------------------------

    /// <summary>All live partition entries, in chain order.</summary>
    public List<PartitionEntry> Entries()
    {
        var outp = new List<PartitionEntry>();
        ulong off = _tableHead;
        while (off != 0)
        {
            (TableBlockHeader h, List<PartitionEntry> entries) = ReadBlock(off);
            outp.AddRange(entries);
            off = h.NextTableOffset;
        }
        return outp;
    }

    /// <summary>
    /// Read a single table block at an absolute <paramref name="offset"/>,
    /// returning its parsed header (including <c>table_hash</c>) and entries.
    /// Unlike <see cref="Entries"/>, which flattens the whole chain, this exposes
    /// one block at a time so a caller can follow an arbitrary
    /// <c>next_table_offset</c> chain and inspect each block's <c>table_hash</c>.
    /// It is a read-only operation and does not alter the container.
    /// </summary>
    public BlockView ReadBlockAt(ulong offset)
    {
        (TableBlockHeader h, List<PartitionEntry> entries) = ReadBlock(offset);
        return new BlockView(offset, h, entries);
    }

    /// <summary>Read a partition's used data.</summary>
    public byte[] ReadPartitionData(PartitionEntry entry)
    {
        var buf = new byte[checked((int)entry.UsedBytes)];
        if (buf.Length > 0)
        {
            ReadAt(entry.StartOffset, buf, buf.Length);
        }
        return buf;
    }

    private (ulong, int, PartitionEntry) Locate(byte[] uid)
    {
        ulong off = _tableHead;
        while (off != 0)
        {
            (TableBlockHeader h, List<PartitionEntry> entries) = ReadBlock(off);
            for (int i = 0; i < entries.Count; i++)
            {
                if (UidEquals(entries[i].Uid, uid))
                {
                    return (off, i, entries[i]);
                }
            }
            off = h.NextTableOffset;
        }
        throw PcfException.NotFound();
    }

    private int BlockIndex(ulong offset)
    {
        for (int i = 0; i < _blocks.Count; i++)
        {
            if (_blocks[i].Offset == offset)
            {
                return i;
            }
        }
        throw new InvalidOperationException("block offset must be tracked");
    }

    // ---- writing ----------------------------------------------------------

    /// <summary>
    /// Add a new partition. The data is appended at the end-of-data cursor and
    /// reserves <paramref name="extraReserve"/> spare bytes for later in-place
    /// growth.
    /// </summary>
    public void AddPartition(
        uint partitionType, byte[] uid, string label, byte[] data,
        ulong extraReserve, HashAlgo dataHashAlgo)
    {
        if (partitionType == Constants.TypeReserved)
        {
            throw PcfException.ReservedType();
        }
        if (PartitionEntry.IsNilUid(uid))
        {
            throw PcfException.NilUid();
        }
        foreach (PartitionEntry e in Entries())
        {
            if (UidEquals(e.Uid, uid))
            {
                throw PcfException.DuplicateUid();
            }
        }

        byte[] labelBytes = PartitionEntry.EncodeLabel(label);
        ulong used = (ulong)data.Length;
        ulong max = used + extraReserve;
        ulong start = _dataEof;
        if (used > 0)
        {
            WriteAt(start, data, data.Length);
        }
        _dataEof += max;
        byte[] dataHash = dataHashAlgo.Compute(data);

        var entry = new PartitionEntry
        {
            PartitionType = partitionType,
            Uid = (byte[])uid.Clone(),
            Label = labelBytes,
            StartOffset = start,
            MaxLength = max,
            UsedBytes = used,
            DataHashAlgo = dataHashAlgo,
            DataHash = dataHash,
        };

        // Find an existing block with reserved room.
        int target = -1;
        for (int i = 0; i < _blocks.Count; i++)
        {
            if (_blocks[i].Count < _blocks[i].Capacity && _blocks[i].Count < Constants.MaxEntriesPerBlock)
            {
                target = i;
                break;
            }
        }

        if (target >= 0)
        {
            ulong boff = _blocks[target].Offset;
            (_, List<PartitionEntry> entries) = ReadBlock(boff);
            entries.Add(entry);
            WriteBlock(boff, _blocks[target].Next, _blocks[target].Algo, entries);
            _blocks[target].Count += 1;
        }
        else
        {
            // Allocate a new overflow block at the end-of-data cursor.
            ulong newOff = _dataEof;
            uint cap = Clamp(_defaultCapacity, 1, Constants.MaxEntriesPerBlock);
            _dataEof = newOff + (ulong)Constants.TableHeaderSize + (ulong)cap * (ulong)Constants.EntrySize;
            HashAlgo algo = _tableHashAlgo;
            WriteBlock(newOff, 0, algo, new List<PartitionEntry> { entry });

            // Re-link the previous tail block to point at the new block.
            BlockInfo tail = _blocks[_blocks.Count - 1];
            (_, List<PartitionEntry> tentries) = ReadBlock(tail.Offset);
            WriteBlock(tail.Offset, newOff, tail.Algo, tentries);
            _blocks[_blocks.Count - 1].Next = newOff;
            _blocks.Add(new BlockInfo
            {
                Offset = newOff,
                Capacity = cap,
                Count = 1,
                Algo = algo,
                Next = 0,
            });
        }
    }

    /// <summary>
    /// Replace a partition's data in place (spec section 8.5, hash cascade).
    /// Fails if <paramref name="newData"/> exceeds the partition's reservation.
    /// </summary>
    public void UpdatePartitionData(byte[] uid, byte[] newData)
    {
        (ulong boff, int slot, PartitionEntry entry) = Locate(uid);
        if ((ulong)newData.Length > entry.MaxLength)
        {
            throw PcfException.DataTooLarge();
        }
        if (newData.Length > 0)
        {
            WriteAt(entry.StartOffset, newData, newData.Length);
        }
        entry.UsedBytes = (ulong)newData.Length;
        entry.DataHash = entry.DataHashAlgo.Compute(newData);

        (_, List<PartitionEntry> entries) = ReadBlock(boff);
        entries[slot] = entry;
        int bi = BlockIndex(boff);
        WriteBlock(boff, _blocks[bi].Next, _blocks[bi].Algo, entries);
    }

    /// <summary>
    /// Remove a partition. Entries after it in the same block shift down; the
    /// freed data region becomes dead space until <see cref="CompactedImage"/>
    /// reclaims it (spec section 11.4).
    /// </summary>
    public void RemovePartition(byte[] uid)
    {
        (ulong boff, int slot, _) = Locate(uid);
        (_, List<PartitionEntry> entries) = ReadBlock(boff);
        entries.RemoveAt(slot);
        int bi = BlockIndex(boff);
        WriteBlock(boff, _blocks[bi].Next, _blocks[bi].Algo, entries);
        _blocks[bi].Count -= 1;
    }

    // ---- integrity --------------------------------------------------------

    /// <summary>
    /// Verify every table block and every partition's data against its stored
    /// hash, and run the per-entry conformance checks (spec section 12).
    /// </summary>
    public void Verify()
    {
        ulong off = _tableHead;
        while (off != 0)
        {
            (TableBlockHeader h, List<PartitionEntry> entries) = ReadBlock(off);
            if (h.TableHashAlgo.Verifies())
            {
                byte[] computed = TableBlockHeader.ComputeTableHash(h.TableHashAlgo, h.NextTableOffset, entries);
                int n = h.TableHashAlgo.DigestLen();
                for (int i = 0; i < n; i++)
                {
                    if (computed[i] != h.TableHash[i])
                    {
                        throw PcfException.TableHashMismatch();
                    }
                }
            }
            foreach (PartitionEntry e in entries)
            {
                e.Validate();
                byte[] data = ReadPartitionData(e);
                if (!e.DataHashAlgo.Verify(data, e.DataHash))
                {
                    throw PcfException.DataHashMismatch();
                }
            }
            off = h.NextTableOffset;
        }
    }

    // ---- compaction -------------------------------------------------------

    /// <summary>
    /// Build a freshly compacted image: all dead space removed, every
    /// <c>max_length</c> trimmed to <c>used_bytes</c>, partitions placed
    /// contiguously after a tightly packed table (spec section 11.5). The
    /// current handle is left unchanged; write the bytes to a new stream and
    /// re-open it.
    /// </summary>
    public byte[] CompactedImage()
    {
        // Gather live entries and their data, in chain order.
        var live = new List<KeyValuePair<PartitionEntry, byte[]>>();
        ulong off = _tableHead;
        while (off != 0)
        {
            (TableBlockHeader h, List<PartitionEntry> entries) = ReadBlock(off);
            foreach (PartitionEntry e in entries)
            {
                live.Add(new KeyValuePair<PartitionEntry, byte[]>(e, ReadPartitionData(e)));
            }
            off = h.NextTableOffset;
        }

        HashAlgo algo = _tableHashAlgo;
        int n = live.Count;
        int numBlocks = n == 0 ? 1 : (n + 254) / 255;

        var counts = new List<int>(numBlocks);
        int rem = n;
        for (int i = 0; i < numBlocks; i++)
        {
            int c = Math.Min(rem, 255);
            counts.Add(c);
            rem -= c;
        }

        var blockOffsets = new List<ulong>(numBlocks);
        ulong o = (ulong)Constants.HeaderSize;
        foreach (int c in counts)
        {
            blockOffsets.Add(o);
            o += (ulong)Constants.TableHeaderSize + (ulong)c * (ulong)Constants.EntrySize;
        }
        ulong dataStart = o;

        // Assign contiguous data offsets; trim reservations to used size.
        ulong d = dataStart;
        foreach (KeyValuePair<PartitionEntry, byte[]> kv in live)
        {
            PartitionEntry e = kv.Key;
            e.StartOffset = d;
            e.UsedBytes = (ulong)kv.Value.Length;
            e.MaxLength = (ulong)kv.Value.Length;
            // data_hash is unchanged because the content is unchanged.
            d += (ulong)kv.Value.Length;
        }

        // Serialise.
        using var image = new MemoryStream();
        var header = new FileHeader
        {
            VersionMajor = Constants.VersionMajor,
            VersionMinor = Constants.VersionMinor,
            PartitionTableOffset = (ulong)Constants.HeaderSize,
        };
        byte[] hb = header.ToBytes();
        image.Write(hb, 0, hb.Length);

        int idx = 0;
        for (int bi = 0; bi < counts.Count; bi++)
        {
            int c = counts[bi];
            ulong next = bi + 1 < numBlocks ? blockOffsets[bi + 1] : 0;
            var slice = new List<PartitionEntry>(c);
            for (int j = 0; j < c; j++)
            {
                slice.Add(live[idx + j].Key);
            }
            byte[] th = TableBlockHeader.ComputeTableHash(algo, next, slice);
            var blockHeader = new TableBlockHeader
            {
                PartitionCount = (byte)c,
                NextTableOffset = next,
                TableHashAlgo = algo,
                TableHash = th,
            };
            byte[] bhb = blockHeader.ToBytes();
            image.Write(bhb, 0, bhb.Length);
            foreach (PartitionEntry e in slice)
            {
                byte[] eb = e.ToBytes();
                image.Write(eb, 0, eb.Length);
            }
            idx += c;
        }

        foreach (KeyValuePair<PartitionEntry, byte[]> kv in live)
        {
            image.Write(kv.Value, 0, kv.Value.Length);
        }
        return image.ToArray();
    }

    /// <summary>Write a compacted copy of the container to <paramref name="output"/>.</summary>
    public void CompactInto(Stream output)
    {
        byte[] img = CompactedImage();
        output.Write(img, 0, img.Length);
    }

    // ---- trailer mode -----------------------------------------------------

    /// <summary>
    /// Convert the file to trailer mode: append a fixed <see cref="Trailer"/> at
    /// the end of the file recording the current partition-table head, then
    /// overwrite the header's <c>partition_table_offset</c> with the
    /// <see cref="Constants.PtOffsetTrailer"/> sentinel so the head is located
    /// via that trailer. The chain built by this writer is forward-linked, so the
    /// trailer records <see cref="Constants.ChainForward"/>.
    /// </summary>
    public void FinalizeWithTrailer()
    {
        var trailer = new Trailer
        {
            PartitionTableOffset = _tableHead,
            ChainFlags = Constants.ChainForward,
        };
        long pos = _storage.Seek(0, SeekOrigin.End);
        byte[] tb = trailer.ToBytes();
        WriteAt((ulong)pos, tb, tb.Length);
        _header.PartitionTableOffset = Constants.PtOffsetTrailer;
        byte[] hb = _header.ToBytes();
        WriteAt(0, hb, hb.Length);
        _chainFlags = Constants.ChainForward;
        _dataEof = (ulong)pos + (ulong)Constants.TrailerSize;
    }

    // ---- helpers ----------------------------------------------------------

    private static uint Clamp(uint v, uint lo, uint hi) => v < lo ? lo : (v > hi ? hi : v);

    internal static bool UidEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
        {
            return false;
        }
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }
        return true;
    }
}
