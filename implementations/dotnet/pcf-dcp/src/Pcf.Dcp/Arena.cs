using System;
using System.Collections.Generic;
using Pcf;

namespace Pcf.Dcp;

/// <summary>
/// The DCP arena: the in-memory model of one DCP container and its canonical
/// byte serialisation.
///
/// An <see cref="Arena"/> holds a byte pool plus a list of inner partitions,
/// each owning a list of fragments. A fragment addresses a byte range in the
/// pool; two fragments addressing the same range share that extent
/// (deduplication, spec Section 10.2). Edits work on the fragment list and
/// append new bytes to the pool, never overwriting bytes a SHARED extent still
/// names (copy-on-write, spec Section 10.1). <see cref="ToBytes"/> always emits
/// the canonical layout of the spec's Section 17 test vector.
/// </summary>
public sealed class Arena
{
    private sealed class Frag
    {
        public int Offset;
        public int Length;
        public byte Kind;
        public bool Shared;
    }

    private sealed class Inner
    {
        public uint PartitionType;
        public byte[] Uid;
        public byte[] Label;
        public HashAlgo DataHashAlgo;
        public List<Frag> Frags;
    }

    private byte ProfileVersionMajor = Constants.ProfileVersionMajor;
    private byte ProfileVersionMinor = Constants.ProfileVersionMinor;
    private ushort Flags;
    private HashAlgo _innerTableAlgo = HashAlgo.Sha256;
    private byte[] _blob = Array.Empty<byte>();
    private int _blobLen;
    private readonly List<Inner> _inners = new List<Inner>();

    /// <summary>Choose the hash algorithm used for inner Table Blocks (default SHA-256).</summary>
    public Arena WithInnerTableAlgo(HashAlgo algo)
    {
        _innerTableAlgo = algo;
        return this;
    }

    // ---- byte pool ---------------------------------------------------------

    private int AppendBlob(byte[] data)
    {
        int start = _blobLen;
        int end = start + data.Length;
        if (end > _blob.Length)
        {
            int cap = _blob.Length == 0 ? 64 : _blob.Length;
            while (cap < end)
            {
                cap *= 2;
            }
            var next = new byte[cap];
            Buffer.BlockCopy(_blob, 0, next, 0, _blobLen);
            _blob = next;
        }
        Buffer.BlockCopy(data, 0, _blob, start, data.Length);
        _blobLen = end;
        return start;
    }

    private bool BlobEquals(int off, int len, byte[] chunk)
    {
        if (len != chunk.Length)
        {
            return false;
        }
        for (int i = 0; i < len; i++)
        {
            if (_blob[off + i] != chunk[i])
            {
                return false;
            }
        }
        return true;
    }

    // ---- parsing -----------------------------------------------------------

    /// <summary>Parse an arena from its on-disk bytes (spec Sections 6–8).</summary>
    public static Arena Parse(byte[] bytes)
    {
        DcpHeader header = DcpHeader.Read(bytes);
        if (header.ProfileVersionMajor != Constants.ProfileVersionMajor)
        {
            throw PcfDcpException.UnsupportedProfileMajor(header.ProfileVersionMajor);
        }
        ulong arenaUsed = header.ArenaUsed;

        var arena = new Arena
        {
            ProfileVersionMajor = header.ProfileVersionMajor,
            ProfileVersionMinor = header.ProfileVersionMinor,
            Flags = header.Flags,
            _blob = (byte[])bytes.Clone(),
            _blobLen = bytes.Length,
        };

        bool firstBlock = true;
        ulong off = header.InnerTableOffset;
        int budget = bytes.Length / (int)Pcf.Constants.TableHeaderSize + 1;
        while (off != Constants.ArenaNone)
        {
            if (budget == 0)
            {
                throw PcfDcpException.OffsetOutOfRange();
            }
            budget -= 1;
            int baseOff = checked((int)off);
            if (baseOff + (int)Pcf.Constants.TableHeaderSize > bytes.Length)
            {
                throw PcfDcpException.OffsetOutOfRange();
            }
            var hb = new byte[(int)Pcf.Constants.TableHeaderSize];
            Buffer.BlockCopy(bytes, baseOff, hb, 0, hb.Length);
            var h = TableBlockHeader.FromBytes(hb);
            if (firstBlock)
            {
                arena._innerTableAlgo = h.TableHashAlgo;
                firstBlock = false;
            }
            for (int i = 0; i < h.PartitionCount; i++)
            {
                int eo = baseOff + (int)Pcf.Constants.TableHeaderSize + i * (int)Pcf.Constants.EntrySize;
                if (eo + (int)Pcf.Constants.EntrySize > bytes.Length)
                {
                    throw PcfDcpException.OffsetOutOfRange();
                }
                var eb = new byte[(int)Pcf.Constants.EntrySize];
                Buffer.BlockCopy(bytes, eo, eb, 0, eb.Length);
                var entry = PartitionEntry.FromBytes(eb);
                var onDisk = FragmentTable.Walk(bytes, entry.StartOffset);
                var frags = new List<Frag>(onDisk.Count);
                foreach (var fe in onDisk)
                {
                    frags.Add(new Frag
                    {
                        Offset = checked((int)fe.ExtentOffset),
                        Length = checked((int)fe.ExtentLength),
                        Kind = fe.Kind,
                        Shared = fe.IsShared(),
                    });
                }
                arena._inners.Add(new Inner
                {
                    PartitionType = entry.PartitionType,
                    Uid = entry.Uid,
                    Label = entry.Label,
                    DataHashAlgo = entry.DataHashAlgo,
                    Frags = frags,
                });
            }
            off = h.NextTableOffset;
        }

        foreach (var inner in arena._inners)
        {
            foreach (var f in inner.Frags)
            {
                if ((ulong)(f.Offset + f.Length) > arenaUsed)
                {
                    throw PcfDcpException.OffsetOutOfRange();
                }
            }
        }
        return arena;
    }

    // ---- read-only views ---------------------------------------------------

    /// <summary>Number of inner partitions.</summary>
    public int Count => _inners.Count;

    /// <summary>Whether the arena has no inner partitions.</summary>
    public bool IsEmpty => _inners.Count == 0;

    /// <summary>The uids of all inner partitions, in stored order.</summary>
    public List<byte[]> Uids()
    {
        var outList = new List<byte[]>(_inners.Count);
        foreach (var i in _inners)
        {
            outList.Add((byte[])i.Uid.Clone());
        }
        return outList;
    }

    private int IndexOf(byte[] uid)
    {
        for (int i = 0; i < _inners.Count; i++)
        {
            if (BytesEqual(_inners[i].Uid, uid))
            {
                return i;
            }
        }
        throw PcfDcpException.NotFound();
    }

    private int InnerLogicalLen(Inner inner)
    {
        int total = 0;
        foreach (var f in inner.Frags)
        {
            if (f.Kind == Constants.KindData)
            {
                total += f.Length;
            }
        }
        return total;
    }

    private byte[] InnerContent(Inner inner)
    {
        var outBytes = new byte[InnerLogicalLen(inner)];
        int p = 0;
        foreach (var f in inner.Frags)
        {
            if (f.Kind == Constants.KindData)
            {
                Buffer.BlockCopy(_blob, f.Offset, outBytes, p, f.Length);
                p += f.Length;
            }
        }
        return outBytes;
    }

    private byte[] InnerDataHash(Inner inner) =>
        inner.DataHashAlgo.Compute(InnerContent(inner));

    private InnerInfo View(Inner inner)
    {
        var extents = new List<ExtentInfo>(inner.Frags.Count);
        foreach (var f in inner.Frags)
        {
            extents.Add(new ExtentInfo
            {
                ExtentOffset = (ulong)f.Offset,
                ExtentLength = (ulong)f.Length,
                Kind = f.Kind,
                Shared = f.Shared,
            });
        }
        return new InnerInfo
        {
            PartitionType = inner.PartitionType,
            Uid = (byte[])inner.Uid.Clone(),
            Label = PartitionEntry.DecodeLabel(inner.Label),
            UsedBytes = (ulong)InnerLogicalLen(inner),
            DataHashAlgo = inner.DataHashAlgo,
            DataHash = InnerDataHash(inner),
            Extents = extents,
        };
    }

    /// <summary>A read-only view of one inner partition.</summary>
    public InnerInfo GetInner(byte[] uid) => View(_inners[IndexOf(uid)]);

    /// <summary>Read-only views of every inner partition, in stored order.</summary>
    public List<InnerInfo> Inners()
    {
        var outList = new List<InnerInfo>(_inners.Count);
        foreach (var i in _inners)
        {
            outList.Add(View(i));
        }
        return outList;
    }

    /// <summary>Reconstruct an inner partition's logical content (spec Section 8.3).</summary>
    public byte[] Content(byte[] uid)
    {
        var inner = _inners[IndexOf(uid)];
        var bytes = InnerContent(inner);
        int declared = InnerLogicalLen(inner);
        if (bytes.Length != declared)
        {
            throw PcfDcpException.LengthMismatch(declared, bytes.Length);
        }
        return bytes;
    }

    // ---- builder -----------------------------------------------------------

    /// <summary>
    /// Add an inner partition whose <paramref name="content"/> is split by
    /// <paramref name="chunker"/> into extents, deduplicating against extents
    /// already present (spec Section 10.2).
    /// </summary>
    public void AddInner(
        uint partitionType, byte[] uid, string label, byte[] content,
        HashAlgo dataHashAlgo, Chunker chunker)
    {
        if (partitionType == 0)
        {
            throw PcfDcpException.ReservedType();
        }
        if (partitionType == Constants.DcpContainerType)
        {
            throw PcfDcpException.NestedContainer();
        }
        if (BytesEqual(uid, Pcf.Constants.NilUid))
        {
            throw PcfDcpException.NilUid();
        }
        foreach (var i in _inners)
        {
            if (BytesEqual(i.Uid, uid))
            {
                throw PcfDcpException.DuplicateUid();
            }
        }
        var labelBytes = PartitionEntry.EncodeLabel(label);

        var frags = new List<Frag>();
        foreach (var chunk in SplitChunks(chunker, content))
        {
            var hit = FindExtent(chunk);
            if (hit == null)
            {
                hit = FindLocal(frags, chunk);
            }
            if (hit != null)
            {
                int offset = hit.Value.Item1;
                int length = hit.Value.Item2;
                MarkShared(offset, length);
                foreach (var f in frags)
                {
                    if (f.Offset == offset && f.Length == length)
                    {
                        f.Shared = true;
                    }
                }
                frags.Add(new Frag { Offset = offset, Length = length, Kind = Constants.KindData, Shared = true });
            }
            else
            {
                int offset = AppendBlob(chunk);
                frags.Add(new Frag { Offset = offset, Length = chunk.Length, Kind = Constants.KindData, Shared = false });
            }
        }
        _inners.Add(new Inner
        {
            PartitionType = partitionType,
            Uid = (byte[])uid.Clone(),
            Label = labelBytes,
            DataHashAlgo = dataHashAlgo,
            Frags = frags,
        });
    }

    private static IEnumerable<byte[]> SplitChunks(Chunker chunker, byte[] content)
    {
        if (content.Length == 0)
        {
            yield break;
        }
        if (chunker.IsWhole)
        {
            yield return content;
            yield break;
        }
        for (int i = 0; i < content.Length; i += chunker.Size)
        {
            int len = Math.Min(chunker.Size, content.Length - i);
            var chunk = new byte[len];
            Buffer.BlockCopy(content, i, chunk, 0, len);
            yield return chunk;
        }
    }

    private (int, int)? FindExtent(byte[] chunk)
    {
        if (chunk.Length == 0)
        {
            return null;
        }
        foreach (var inner in _inners)
        {
            foreach (var f in inner.Frags)
            {
                if (f.Kind == Constants.KindData && f.Length == chunk.Length && BlobEquals(f.Offset, f.Length, chunk))
                {
                    return (f.Offset, f.Length);
                }
            }
        }
        return null;
    }

    private (int, int)? FindLocal(List<Frag> frags, byte[] chunk)
    {
        if (chunk.Length == 0)
        {
            return null;
        }
        foreach (var f in frags)
        {
            if (f.Kind == Constants.KindData && f.Length == chunk.Length && BlobEquals(f.Offset, f.Length, chunk))
            {
                return (f.Offset, f.Length);
            }
        }
        return null;
    }

    private void MarkShared(int offset, int length)
    {
        foreach (var inner in _inners)
        {
            foreach (var f in inner.Frags)
            {
                if (f.Offset == offset && f.Length == length)
                {
                    f.Shared = true;
                }
            }
        }
    }

    // ---- logical edits (copy-on-write) -------------------------------------

    /// <summary>Append <paramref name="bytes"/> to an inner partition's content.</summary>
    public void Append(byte[] uid, byte[] bytes)
    {
        int idx = IndexOf(uid);
        if (bytes.Length == 0)
        {
            return;
        }
        int offset = AppendBlob(bytes);
        _inners[idx].Frags.Add(new Frag { Offset = offset, Length = bytes.Length, Kind = Constants.KindData, Shared = false });
    }

    /// <summary>Overwrite the logical range <c>[pos, pos+len)</c> with <paramref name="bytes"/>.</summary>
    public void Overwrite(byte[] uid, int pos, int len, byte[] bytes)
    {
        Delete(uid, pos, len);
        Insert(uid, pos, bytes);
    }

    /// <summary>Insert <paramref name="bytes"/> at logical position <paramref name="pos"/>.</summary>
    public void Insert(byte[] uid, int pos, byte[] bytes)
    {
        int idx = IndexOf(uid);
        int total = InnerLogicalLen(_inners[idx]);
        if (pos > total)
        {
            throw PcfDcpException.PositionOutOfRange();
        }
        if (bytes.Length == 0)
        {
            return;
        }
        int split = SplitAt(idx, pos);
        int offset = AppendBlob(bytes);
        _inners[idx].Frags.Insert(split, new Frag { Offset = offset, Length = bytes.Length, Kind = Constants.KindData, Shared = false });
    }

    /// <summary>Delete the logical range <c>[pos, pos+len)</c>.</summary>
    public void Delete(byte[] uid, int pos, int len)
    {
        int idx = IndexOf(uid);
        int total = InnerLogicalLen(_inners[idx]);
        int end = pos + len;
        if (end > total)
        {
            throw PcfDcpException.PositionOutOfRange();
        }
        if (len == 0)
        {
            return;
        }
        int lo = SplitAt(idx, pos);
        int hi = SplitAt(idx, end);
        _inners[idx].Frags.RemoveRange(lo, hi - lo);
    }

    /// <summary>Truncate the partition's logical content to <paramref name="newLen"/> bytes.</summary>
    public void Truncate(byte[] uid, int newLen)
    {
        int idx = IndexOf(uid);
        int total = InnerLogicalLen(_inners[idx]);
        if (newLen > total)
        {
            throw PcfDcpException.PositionOutOfRange();
        }
        int cut = SplitAt(idx, newLen);
        var frags = _inners[idx].Frags;
        if (cut < frags.Count)
        {
            frags.RemoveRange(cut, frags.Count - cut);
        }
    }

    private int SplitAt(int idx, int pos)
    {
        var frags = _inners[idx].Frags;
        int logical = 0;
        int i = 0;
        while (i < frags.Count)
        {
            var f = frags[i];
            int flen = f.Length;
            if (logical == pos)
            {
                return i;
            }
            if (pos < logical + flen)
            {
                int head = pos - logical;
                var left = new Frag { Offset = f.Offset, Length = head, Kind = f.Kind, Shared = f.Shared };
                var right = new Frag { Offset = f.Offset + head, Length = flen - head, Kind = f.Kind, Shared = f.Shared };
                frags[i] = left;
                frags.Insert(i + 1, right);
                return i + 1;
            }
            logical += flen;
            i += 1;
        }
        return frags.Count;
    }

    // ---- promotion support -------------------------------------------------

    /// <summary>
    /// Remove an inner partition, returning the pieces a promotion needs: its
    /// type, label, hash algorithm, and reconstructed logical content.
    /// </summary>
    public (uint PartitionType, string Label, HashAlgo DataHashAlgo, byte[] Content) RemoveInner(byte[] uid)
    {
        int idx = IndexOf(uid);
        var content = Content(uid);
        var inner = _inners[idx];
        _inners.RemoveAt(idx);
        return (inner.PartitionType, PartitionEntry.DecodeLabel(inner.Label), inner.DataHashAlgo, content);
    }

    // ---- deduplication and compaction --------------------------------------

    /// <summary>
    /// Re-chunk every inner partition with <paramref name="chunker"/> and
    /// deduplicate identical extents across the whole arena. Returns the
    /// estimated number of bytes the pool shrank by once re-serialised.
    /// </summary>
    public long Dedup(Chunker chunker)
    {
        long before = CanonicalExtentBytes();
        var rebuilt = new Arena
        {
            ProfileVersionMajor = ProfileVersionMajor,
            ProfileVersionMinor = ProfileVersionMinor,
            Flags = Flags,
            _innerTableAlgo = _innerTableAlgo,
        };
        foreach (var inner in _inners)
        {
            rebuilt.AddInner(
                inner.PartitionType, inner.Uid, PartitionEntry.DecodeLabel(inner.Label),
                InnerContent(inner), inner.DataHashAlgo, chunker);
        }
        _blob = rebuilt._blob;
        _blobLen = rebuilt._blobLen;
        _inners.Clear();
        _inners.AddRange(rebuilt._inners);
        long after = CanonicalExtentBytes();
        return Math.Max(0, before - after);
    }

    /// <summary>
    /// Compact the arena (spec Section 10.3): drop unreferenced pool bytes and
    /// normalise the SHARED flag, clearing it on any extent now referenced
    /// exactly once (rule F2). Returns the number of dead pool bytes reclaimed.
    /// </summary>
    public long Compact()
    {
        var refcount = new Dictionary<(int, int), int>();
        foreach (var inner in _inners)
        {
            foreach (var f in inner.Frags)
            {
                var k = (f.Offset, f.Length);
                refcount[k] = refcount.TryGetValue(k, out int c) ? c + 1 : 1;
            }
        }
        foreach (var inner in _inners)
        {
            foreach (var f in inner.Frags)
            {
                if (refcount[(f.Offset, f.Length)] <= 1)
                {
                    f.Shared = false;
                }
            }
        }
        long liveBytes = 0;
        foreach (var k in refcount.Keys)
        {
            liveBytes += k.Item2;
        }
        long deadBefore = Math.Max(0, _blobLen - liveBytes);

        var newPool = new Arena();
        var remap = new Dictionary<(int, int), int>();
        foreach (var inner in _inners)
        {
            foreach (var f in inner.Frags)
            {
                var k = (f.Offset, f.Length);
                if (!remap.ContainsKey(k))
                {
                    var region = new byte[f.Length];
                    Buffer.BlockCopy(_blob, f.Offset, region, 0, f.Length);
                    remap[k] = newPool.AppendBlob(region);
                }
            }
        }
        foreach (var inner in _inners)
        {
            foreach (var f in inner.Frags)
            {
                f.Offset = remap[(f.Offset, f.Length)];
            }
        }
        _blob = newPool._blob;
        _blobLen = newPool._blobLen;
        return deadBefore;
    }

    private long CanonicalExtentBytes()
    {
        var seen = new HashSet<(int, int)>();
        long total = 0;
        foreach (var inner in _inners)
        {
            foreach (var f in inner.Frags)
            {
                if (seen.Add((f.Offset, f.Length)))
                {
                    total += f.Length;
                }
            }
        }
        return total;
    }

    // ---- canonical serialisation -------------------------------------------

    /// <summary>Serialise the arena into its canonical on-disk layout (spec Section 17).</summary>
    public byte[] ToBytes()
    {
        var extOrder = new List<(int, int)>();
        var extIndex = new Dictionary<(int, int), int>();
        foreach (var inner in _inners)
        {
            foreach (var f in inner.Frags)
            {
                var k = (f.Offset, f.Length);
                if (!extIndex.ContainsKey(k))
                {
                    extIndex[k] = extOrder.Count;
                    extOrder.Add(k);
                }
            }
        }

        int cur = Constants.DcpHeaderSize;
        var extArenaOff = new int[extOrder.Count];
        for (int i = 0; i < extOrder.Count; i++)
        {
            extArenaOff[i] = cur;
            cur += extOrder[i].Item2;
        }

        var fragOff = new int[_inners.Count];
        for (int ii = 0; ii < _inners.Count; ii++)
        {
            fragOff[ii] = cur;
            cur += FragtableSpan(_inners[ii].Frags.Count);
        }

        int innerTableOffset = cur;
        var counts = BlockCounts(_inners.Count);
        var blockOff = new int[counts.Count];
        for (int b = 0; b < counts.Count; b++)
        {
            blockOff[b] = cur;
            cur += (int)Pcf.Constants.TableHeaderSize + counts[b] * (int)Pcf.Constants.EntrySize;
        }
        int arenaUsed = cur;

        var buf = new byte[arenaUsed];

        var header = new DcpHeader
        {
            ProfileVersionMajor = ProfileVersionMajor,
            ProfileVersionMinor = ProfileVersionMinor,
            Flags = Flags,
            InnerTableOffset = (ulong)innerTableOffset,
            ArenaUsed = (ulong)arenaUsed,
        };
        Buffer.BlockCopy(header.ToBytes(), 0, buf, 0, Constants.DcpHeaderSize);

        for (int i = 0; i < extOrder.Count; i++)
        {
            Buffer.BlockCopy(_blob, extOrder[i].Item1, buf, extArenaOff[i], extOrder[i].Item2);
        }

        for (int ii = 0; ii < _inners.Count; ii++)
        {
            WriteFragmentTable(buf, fragOff[ii], _inners[ii].Frags, extIndex, extArenaOff);
        }

        var entries = new List<PartitionEntry>(_inners.Count);
        for (int ii = 0; ii < _inners.Count; ii++)
        {
            var inner = _inners[ii];
            ulong used = (ulong)InnerLogicalLen(inner);
            entries.Add(new PartitionEntry
            {
                PartitionType = inner.PartitionType,
                Uid = (byte[])inner.Uid.Clone(),
                Label = (byte[])inner.Label.Clone(),
                StartOffset = (ulong)fragOff[ii],
                MaxLength = used,
                UsedBytes = used,
                DataHashAlgo = inner.DataHashAlgo,
                DataHash = InnerDataHash(inner),
            });
        }

        int idx = 0;
        for (int b = 0; b < counts.Count; b++)
        {
            int c = counts[b];
            ulong next = b + 1 < counts.Count ? (ulong)blockOff[b + 1] : 0;
            var slice = entries.GetRange(idx, c);
            var th = TableBlockHeader.ComputeTableHash(_innerTableAlgo, next, slice);
            var bh = new TableBlockHeader
            {
                PartitionCount = (byte)c,
                NextTableOffset = next,
                TableHashAlgo = _innerTableAlgo,
                TableHash = th,
            };
            int p = blockOff[b];
            Buffer.BlockCopy(bh.ToBytes(), 0, buf, p, (int)Pcf.Constants.TableHeaderSize);
            p += (int)Pcf.Constants.TableHeaderSize;
            foreach (var e in slice)
            {
                Buffer.BlockCopy(e.ToBytes(), 0, buf, p, (int)Pcf.Constants.EntrySize);
                p += (int)Pcf.Constants.EntrySize;
            }
            idx += c;
        }

        return buf;
    }

    private static int FragtableSpan(int n)
    {
        int span = 0;
        foreach (int c in BlockCounts(n))
        {
            span += Constants.FragTableHeaderSize + c * Constants.FragmentEntrySize;
        }
        return span;
    }

    private static List<int> BlockCounts(int n)
    {
        if (n == 0)
        {
            return new List<int> { 0 };
        }
        var outList = new List<int>();
        int rem = n;
        while (rem > 0)
        {
            int c = Math.Min(rem, Constants.MaxEntriesPerBlock);
            outList.Add(c);
            rem -= c;
        }
        return outList;
    }

    private static void WriteFragmentTable(
        byte[] buf, int start, List<Frag> frags,
        Dictionary<(int, int), int> extIndex, int[] extArenaOff)
    {
        var counts = BlockCounts(frags.Count);
        int blockStart = start;
        int idx = 0;
        for (int b = 0; b < counts.Count; b++)
        {
            int c = counts[b];
            int span = Constants.FragTableHeaderSize + c * Constants.FragmentEntrySize;
            ulong next = b + 1 < counts.Count ? (ulong)(blockStart + span) : 0;
            var fh = new FragTableHeader { NextFragtableOffset = next, FragmentCount = (byte)c };
            Buffer.BlockCopy(fh.ToBytes(), 0, buf, blockStart, Constants.FragTableHeaderSize);
            for (int j = 0; j < c; j++)
            {
                var f = frags[idx + j];
                int arenaOff = extArenaOff[extIndex[(f.Offset, f.Length)]];
                var fe = new FragmentEntry
                {
                    ExtentOffset = (ulong)arenaOff,
                    ExtentLength = (ulong)f.Length,
                    Kind = f.Kind,
                    Flags = f.Shared ? Constants.FlagShared : (byte)0,
                };
                Buffer.BlockCopy(fe.ToBytes(), 0, buf, blockStart + Constants.FragTableHeaderSize + j * Constants.FragmentEntrySize, Constants.FragmentEntrySize);
            }
            blockStart += span;
            idx += c;
        }
    }

    internal static bool BytesEqual(byte[] a, byte[] b)
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
