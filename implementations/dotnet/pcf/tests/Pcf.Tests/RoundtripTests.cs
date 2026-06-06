using System;
using System.IO;
using System.Text;

namespace Pcf.Tests;

/// <summary>End-to-end black-box tests covering whole-file operations.</summary>
public class RoundtripTests
{
    [Fact]
    public void Create_add_read_verify()
    {
        var c = Container.Create(new MemoryStream());
        c.AddPartition(0x10, TestSupport.Uid(1), "notes",
            Encoding.ASCII.GetBytes("hello"), 64, HashAlgo.Sha256);
        c.Verify();

        var e = c.Entries()[0];
        Assert.Equal("notes", e.LabelString());
        Assert.Equal(Encoding.ASCII.GetBytes("hello"), c.ReadPartitionData(e));
        Assert.Equal(64ul, e.FreeBytes()); // max = 5 + 64, used = 5
    }

    [Fact]
    public void Reopen_from_bytes()
    {
        var c = Container.Create(new MemoryStream());
        c.AddPartition(0x10, TestSupport.Uid(1), "a", new byte[] { 1, 2, 3 }, 0, HashAlgo.Crc64);
        byte[] img = c.CompactedImage();

        var reopened = Container.Open(new MemoryStream(img));
        reopened.Verify();
        Assert.Single(reopened.Entries());
        Assert.Equal(new byte[] { 1, 2, 3 }, reopened.ReadPartitionData(reopened.Entries()[0]));
    }

    [Fact]
    public void Update_in_place_with_cascade()
    {
        var stream = new MemoryStream();
        var c = Container.CreateWith(stream, 8, HashAlgo.Sha256);
        c.AddPartition(0x10, TestSupport.Uid(1), "a", new byte[] { 1, 2, 3 }, 16, HashAlgo.Sha256);

        c.UpdatePartitionData(TestSupport.Uid(1), Encoding.ASCII.GetBytes("updated payload"));
        c.Verify();
        Assert.Equal(Encoding.ASCII.GetBytes("updated payload"),
            c.ReadPartitionData(c.Entries()[0]));
    }

    [Fact]
    public void Update_rejects_data_larger_than_reservation()
    {
        var c = Container.Create(new MemoryStream());
        c.AddPartition(0x10, TestSupport.Uid(1), "a", new byte[] { 1, 2, 3 }, 2, HashAlgo.Sha256);
        var ex = Assert.Throws<PcfException>(() =>
            c.UpdatePartitionData(TestSupport.Uid(1), new byte[] { 1, 2, 3, 4, 5, 6 }));
        Assert.Equal(PcfError.DataTooLarge, ex.Kind);
    }

    [Fact]
    public void Remove_partition()
    {
        var c = Container.Create(new MemoryStream());
        c.AddPartition(0x10, TestSupport.Uid(1), "a", new byte[] { 1 }, 0, HashAlgo.Sha256);
        c.AddPartition(0x11, TestSupport.Uid(2), "b", new byte[] { 2 }, 0, HashAlgo.Sha256);

        c.RemovePartition(TestSupport.Uid(1));
        var entries = c.Entries();
        Assert.Single(entries);
        Assert.Equal("b", entries[0].LabelString());
        c.Verify();
    }

    [Fact]
    public void Duplicate_uid_is_rejected()
    {
        var c = Container.Create(new MemoryStream());
        c.AddPartition(0x10, TestSupport.Uid(7), "a", new byte[] { 1 }, 0, HashAlgo.Sha256);
        var ex = Assert.Throws<PcfException>(() =>
            c.AddPartition(0x11, TestSupport.Uid(7), "b", new byte[] { 2 }, 0, HashAlgo.Sha256));
        Assert.Equal(PcfError.DuplicateUid, ex.Kind);
    }

    [Fact]
    public void Corruption_is_detected_by_data_hash()
    {
        var c = Container.Create(new MemoryStream());
        c.AddPartition(0x10, TestSupport.Uid(1), "a",
            Encoding.ASCII.GetBytes("payload"), 0, HashAlgo.Sha256);
        byte[] img = c.CompactedImage();

        // Flip one byte of the partition's data region (the final bytes).
        img[^1] ^= 0xFF;
        var reopened = Container.Open(new MemoryStream(img));
        var ex = Assert.Throws<PcfException>(() => reopened.Verify());
        Assert.Equal(PcfError.DataHashMismatch, ex.Kind);
    }

    [Fact]
    public void Compaction_reclaims_space()
    {
        var c = Container.CreateWith(new MemoryStream(), 8, HashAlgo.Sha256);
        c.AddPartition(0x10, TestSupport.Uid(1), "a", new byte[] { 1 }, 1000, HashAlgo.Sha256);
        c.AddPartition(0x11, TestSupport.Uid(2), "b", new byte[] { 2 }, 1000, HashAlgo.Sha256);
        c.RemovePartition(TestSupport.Uid(1));

        byte[] img = c.CompactedImage();
        var reopened = Container.Open(new MemoryStream(img));
        reopened.Verify();

        var entries = reopened.Entries();
        Assert.Single(entries);
        // Reservation trimmed to the used size.
        Assert.Equal(1ul, entries[0].MaxLength);
        Assert.Equal(1ul, entries[0].UsedBytes);
    }

    [Fact]
    public void Overflow_chain_roundtrips()
    {
        // First block capacity 2 forces overflow blocks for further additions.
        var c = Container.CreateWith(new MemoryStream(), 2, HashAlgo.Sha256);
        for (int i = 1; i <= 5; i++)
        {
            c.AddPartition(0x10, TestSupport.Uid((byte)i), "p",
                new byte[] { (byte)i }, 0, HashAlgo.Sha256);
        }
        c.Verify();
        Assert.Equal(5, c.Entries().Count);

        var reopened = Container.Open(new MemoryStream(c.CompactedImage()));
        reopened.Verify();
        Assert.Equal(5, reopened.Entries().Count);
    }

    [Fact]
    public void ReadBlockAt_exposes_block_view()
    {
        // A first-block capacity of 2 forces a second (overflow) block for 3
        // partitions, so we can walk the chain block-by-block via ReadBlockAt.
        var c = Container.CreateWith(new MemoryStream(), 2, HashAlgo.Sha256);
        for (byte i = 1; i <= 3; i++)
        {
            c.AddPartition(i, TestSupport.Uid(i), $"p{i}",
                new byte[] { i, i, i, i }, 0, HashAlgo.Sha256);
        }

        ulong off = c.Header.PartitionTableOffset;
        int total = 0, blocks = 0;
        while (off != 0)
        {
            BlockView view = c.ReadBlockAt(off);
            Assert.Equal(off, view.Offset);
            Assert.Equal((int)view.Header.PartitionCount, view.Entries.Count);
            // The exposed table_hash must match a recomputation over the block.
            byte[] recomputed = TableBlockHeader.ComputeTableHash(
                view.Header.TableHashAlgo, view.Header.NextTableOffset, view.Entries);
            Assert.Equal(recomputed, view.Header.TableHash);
            total += view.Entries.Count;
            blocks++;
            off = view.Header.NextTableOffset;
        }
        Assert.Equal(3, total);
        Assert.Equal(2, blocks);
    }
}
