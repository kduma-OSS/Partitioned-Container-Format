using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Pcf;

namespace Pcf.Dcp;

/// <summary>An inner partition together with the container that holds it.</summary>
public sealed class InnerLocation
{
    /// <summary>uid of the enclosing DCP container partition.</summary>
    public byte[] ContainerUid { get; set; }

    /// <summary>The inner partition's metadata and extents.</summary>
    public InnerInfo Info { get; set; }
}

/// <summary>The result of resolving a uid against top-level ∪ inner (spec 2.1).</summary>
public sealed class Resolved
{
    /// <summary>Whether the uid resolved to a top-level PCF partition.</summary>
    public bool IsTopLevel { get; set; }

    /// <summary>The top-level entry (when <see cref="IsTopLevel"/> is true).</summary>
    public PartitionEntry Entry { get; set; }

    /// <summary>The inner partition location (when <see cref="IsTopLevel"/> is false).</summary>
    public InnerLocation Inner { get; set; }
}

/// <summary>
/// A reader for DCP containers layered over a PCF file. It works entirely
/// through the high-level <see cref="Container"/> API, so a DCP file written in
/// trailer mode reads back transparently.
/// </summary>
public sealed class DcpReader
{
    private readonly Container _c;

    private DcpReader(Container c)
    {
        _c = c;
    }

    /// <summary>Open a PCF file for DCP-aware reading.</summary>
    public static DcpReader Open(Stream storage) => new DcpReader(Container.Open(storage));

    /// <summary>Borrow the underlying PCF container.</summary>
    public Container Container => _c;

    /// <summary>All top-level entries, in chain order.</summary>
    public List<PartitionEntry> Entries() => _c.Entries();

    /// <summary>The top-level DCP container entries.</summary>
    public List<PartitionEntry> Containers()
    {
        var outList = new List<PartitionEntry>();
        foreach (var e in _c.Entries())
        {
            if (e.PartitionType == Constants.DcpContainerType)
            {
                outList.Add(e);
            }
        }
        return outList;
    }

    /// <summary>Parse the arena of a DCP container entry.</summary>
    public Arena OpenArena(PartitionEntry entry)
    {
        if (entry.PartitionType != Constants.DcpContainerType)
        {
            throw PcfDcpException.NotADcpContainer();
        }
        return Arena.Parse(_c.ReadPartitionData(entry));
    }

    /// <summary>Every inner partition across every DCP container, in file order.</summary>
    public List<InnerLocation> InnerPartitions()
    {
        var outList = new List<InnerLocation>();
        foreach (var cont in Containers())
        {
            var arena = OpenArena(cont);
            foreach (var info in arena.Inners())
            {
                outList.Add(new InnerLocation { ContainerUid = (byte[])cont.Uid.Clone(), Info = info });
            }
        }
        return outList;
    }

    /// <summary>Resolve a uid against the flattened set top-level ∪ inner (spec 2.1).</summary>
    public Resolved ResolveUid(byte[] uid)
    {
        foreach (var e in _c.Entries())
        {
            if (Arena.BytesEqual(e.Uid, uid))
            {
                return new Resolved { IsTopLevel = true, Entry = e };
            }
        }
        foreach (var loc in InnerPartitions())
        {
            if (Arena.BytesEqual(loc.Info.Uid, uid))
            {
                return new Resolved { IsTopLevel = false, Inner = loc };
            }
        }
        throw PcfDcpException.NotFound();
    }

    /// <summary>Reconstruct an inner partition's logical content by uid.</summary>
    public byte[] ReadInner(byte[] uid)
    {
        foreach (var cont in Containers())
        {
            var arena = OpenArena(cont);
            foreach (var u in arena.Uids())
            {
                if (Arena.BytesEqual(u, uid))
                {
                    return arena.Content(uid);
                }
            }
        }
        throw PcfDcpException.NotFound();
    }

    /// <summary>
    /// Full DCP-aware verification: PCF integrity, each inner Table Block's
    /// table_hash, reconstruction length and (when algorithmic) data_hash, no
    /// nested container, and file-wide uid uniqueness.
    /// </summary>
    public void Verify()
    {
        _c.Verify();

        var seen = new HashSet<string>();
        foreach (var e in _c.Entries())
        {
            if (!seen.Add(Hex(e.Uid)))
            {
                throw PcfDcpException.DuplicateUid();
            }
        }

        foreach (var cont in Containers())
        {
            var data = _c.ReadPartitionData(cont);
            VerifyInnerTableHashes(data);

            var arena = Arena.Parse(data);
            foreach (var info in arena.Inners())
            {
                if (info.PartitionType == Constants.DcpContainerType)
                {
                    throw PcfDcpException.NestedContainer();
                }
                if (!seen.Add(Hex(info.Uid)))
                {
                    throw PcfDcpException.DuplicateUid();
                }
                var content = arena.Content(info.Uid);
                if ((ulong)content.Length != info.UsedBytes)
                {
                    throw PcfDcpException.LengthMismatch((long)info.UsedBytes, content.Length);
                }
                if (!info.DataHashAlgo.Verify(content, info.DataHash))
                {
                    throw PcfDcpException.HashMismatch();
                }
            }
        }
    }

    private static void VerifyInnerTableHashes(byte[] arena)
    {
        DcpHeader header = DcpHeader.Read(arena);
        ulong off = header.InnerTableOffset;
        int budget = arena.Length / (int)Pcf.Constants.TableHeaderSize + 1;
        while (off != 0)
        {
            if (budget == 0)
            {
                throw PcfDcpException.OffsetOutOfRange();
            }
            budget -= 1;
            int baseOff = checked((int)off);
            if (baseOff + (int)Pcf.Constants.TableHeaderSize > arena.Length)
            {
                throw PcfDcpException.OffsetOutOfRange();
            }
            var hb = new byte[(int)Pcf.Constants.TableHeaderSize];
            Buffer.BlockCopy(arena, baseOff, hb, 0, hb.Length);
            var h = TableBlockHeader.FromBytes(hb);
            var entries = new List<PartitionEntry>(h.PartitionCount);
            for (int i = 0; i < h.PartitionCount; i++)
            {
                int eo = baseOff + (int)Pcf.Constants.TableHeaderSize + i * (int)Pcf.Constants.EntrySize;
                if (eo + (int)Pcf.Constants.EntrySize > arena.Length)
                {
                    throw PcfDcpException.OffsetOutOfRange();
                }
                var eb = new byte[(int)Pcf.Constants.EntrySize];
                Buffer.BlockCopy(arena, eo, eb, 0, eb.Length);
                entries.Add(PartitionEntry.FromBytes(eb));
            }
            if (h.TableHashAlgo.Verifies())
            {
                var computed = TableBlockHeader.ComputeTableHash(h.TableHashAlgo, h.NextTableOffset, entries);
                int n = h.TableHashAlgo.DigestLen();
                for (int i = 0; i < n; i++)
                {
                    if (computed[i] != h.TableHash[i])
                    {
                        throw PcfDcpException.HashMismatch();
                    }
                }
            }
            off = h.NextTableOffset;
        }
    }

    private static string Hex(byte[] b)
    {
        var sb = new StringBuilder(b.Length * 2);
        foreach (var x in b)
        {
            sb.Append(x.ToString("x2"));
        }
        return sb.ToString();
    }
}
