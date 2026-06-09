using System;
using System.Collections.Generic;
using System.IO;
using Pcf;

namespace Pcf.Dcp;

/// <summary>
/// Building and rewriting PCF files that carry DCP containers. The writer keeps
/// the whole file as an in-memory list of top-level partitions and emits a
/// fresh, canonical PCF image on demand. Every mutating operation is a logical
/// edit of that list followed by a rebuild — simple and always correct for a
/// reference implementation; the result is a fully conforming PCF v1.0 file.
/// </summary>
public sealed class DcpWriter
{
    private sealed class TopPart
    {
        public uint PartitionType;
        public byte[] Uid;
        public string Label;
        public HashAlgo DataHashAlgo;
        public byte[] PlainData; // non-null for a plain partition
        public Arena Arena;      // non-null for a DCP container
    }

    private readonly List<TopPart> _parts = new List<TopPart>();
    private readonly HashAlgo _tableHashAlgo = HashAlgo.Sha256;
    private bool _trailer;

    /// <summary>Load an existing PCF file into the writer's model.</summary>
    public static DcpWriter Open(Stream storage)
    {
        var c = Container.Open(storage);
        var w = new DcpWriter();
        foreach (var e in c.Entries())
        {
            var data = c.ReadPartitionData(e);
            var label = PartitionEntry.DecodeLabel(e.Label);
            var part = new TopPart
            {
                PartitionType = e.PartitionType,
                Uid = (byte[])e.Uid.Clone(),
                Label = label,
                DataHashAlgo = e.DataHashAlgo,
            };
            if (e.PartitionType == Constants.DcpContainerType)
            {
                part.Arena = Arena.Parse(data);
            }
            else
            {
                part.PlainData = data;
            }
            w._parts.Add(part);
        }
        return w;
    }

    /// <summary>Finalise emitted images in trailer mode (append-only host).</summary>
    public void SetTrailer(bool on) => _trailer = on;

    private void EnsureUnique(byte[] uid)
    {
        foreach (var p in _parts)
        {
            if (Arena.BytesEqual(p.Uid, uid))
            {
                throw PcfDcpException.DuplicateUid();
            }
        }
    }

    /// <summary>Add a DCP container partition holding <paramref name="arena"/>.</summary>
    public void AddContainer(byte[] uid, string label, Arena arena)
    {
        EnsureUnique(uid);
        _parts.Add(new TopPart
        {
            PartitionType = Constants.DcpContainerType,
            Uid = (byte[])uid.Clone(),
            Label = label,
            DataHashAlgo = HashAlgo.None,
            Arena = arena,
        });
    }

    /// <summary>Add an ordinary top-level partition.</summary>
    public void AddPlain(uint partitionType, byte[] uid, string label, byte[] data, HashAlgo dataHashAlgo)
    {
        EnsureUnique(uid);
        _parts.Add(new TopPart
        {
            PartitionType = partitionType,
            Uid = (byte[])uid.Clone(),
            Label = label,
            DataHashAlgo = dataHashAlgo,
            PlainData = data,
        });
    }

    private Arena ContainerArena(byte[] uid)
    {
        foreach (var p in _parts)
        {
            if (Arena.BytesEqual(p.Uid, uid))
            {
                if (p.Arena == null)
                {
                    throw PcfDcpException.NotADcpContainer();
                }
                return p.Arena;
            }
        }
        throw PcfDcpException.NotFound();
    }

    /// <summary>Borrow a container's arena for inspection or in-place editing.</summary>
    public Arena GetArena(byte[] containerUid) => ContainerArena(containerUid);

    // ---- migration: promotion / demotion -----------------------------------

    /// <summary>
    /// Promote an inner partition out of its DCP container to a top-level PCF
    /// partition (dynamic → fixed), preserving uid, type, label, hash algorithm
    /// and data_hash (the promotion invariant, spec Section 10.4).
    /// </summary>
    public void Promote(byte[] containerUid, byte[] innerUid)
    {
        var arena = ContainerArena(containerUid);
        var piece = arena.RemoveInner(innerUid);
        _parts.Add(new TopPart
        {
            PartitionType = piece.PartitionType,
            Uid = (byte[])innerUid.Clone(),
            Label = piece.Label,
            DataHashAlgo = piece.DataHashAlgo,
            PlainData = piece.Content,
        });
    }

    /// <summary>
    /// Demote a top-level partition into a DCP container as an inner partition
    /// (fixed → dynamic), preserving uid, type, label, hash algorithm and
    /// data_hash. The content becomes a single DATA extent.
    /// </summary>
    public void Demote(byte[] partUid, byte[] containerUid)
    {
        int pos = -1;
        for (int i = 0; i < _parts.Count; i++)
        {
            if (Arena.BytesEqual(_parts[i].Uid, partUid))
            {
                pos = i;
                break;
            }
        }
        if (pos < 0)
        {
            throw PcfDcpException.NotFound();
        }
        var p = _parts[pos];
        if (p.PartitionType == Constants.DcpContainerType || p.PlainData == null)
        {
            throw PcfDcpException.NestedContainer();
        }
        var arena = ContainerArena(containerUid);
        arena.AddInner(p.PartitionType, partUid, p.Label, p.PlainData, p.DataHashAlgo, Chunker.Whole());
        _parts.RemoveAt(pos);
    }

    // ---- container-level maintenance ---------------------------------------

    /// <summary>Re-chunk and deduplicate a container's inner partitions.</summary>
    public long Dedup(byte[] containerUid, Chunker chunker) => ContainerArena(containerUid).Dedup(chunker);

    /// <summary>Compact / defragment a container's arena. Returns bytes reclaimed.</summary>
    public long Defrag(byte[] containerUid) => ContainerArena(containerUid).Compact();

    // ---- serialisation -----------------------------------------------------

    /// <summary>Build a fresh, canonical PCF image of the whole file.</summary>
    public byte[] ToImage()
    {
        uint cap = (uint)Math.Max(1, _parts.Count);
        var stream = new MemoryStream();
        var c = Container.CreateWith(stream, cap, _tableHashAlgo);
        foreach (var p in _parts)
        {
            byte[] data = p.Arena != null ? p.Arena.ToBytes() : p.PlainData;
            c.AddPartition(p.PartitionType, p.Uid, p.Label, data, 0, p.DataHashAlgo);
        }
        if (_trailer)
        {
            c.FinalizeWithTrailer();
        }
        return ((MemoryStream)c.Storage).ToArray();
    }
}
