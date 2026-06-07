using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;

namespace Pcf.Tests;

/// <summary>Tests for the optional end-of-file trailer (spec section 4, "File Trailer").</summary>
public class TrailerTests
{
    private static byte[] Build()
    {
        var s = new MemoryStream();
        var c = Container.CreateWith(s, 4, HashAlgo.Sha256);
        c.AddPartition(0x10, TestSupport.Uid(1), "alpha",
            Encoding.ASCII.GetBytes("Hello, PCF!"), 0, HashAlgo.Sha256);
        c.AddPartition(0xFFFF_FFFF, TestSupport.Uid(2), "raw",
            new byte[] { 0, 1, 2 }, 0, HashAlgo.Crc32c);
        c.FinalizeWithTrailer();
        return s.ToArray();
    }

    private static ulong HeaderOffset(byte[] b) =>
        BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(12, 8));

    private static byte[] WithSentinel(byte[] b)
    {
        var copy = (byte[])b.Clone();
        BinaryPrimitives.WriteUInt64LittleEndian(copy.AsSpan(12, 8), Constants.PtOffsetTrailer);
        return copy;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        using var ms = new MemoryStream();
        foreach (byte[] p in parts)
        {
            ms.Write(p, 0, p.Length);
        }
        return ms.ToArray();
    }

    [Fact]
    public void Finalize_with_trailer_roundtrips()
    {
        byte[] bytes = Build();
        Assert.Equal(Constants.PtOffsetTrailer, HeaderOffset(bytes));

        var tb = new byte[20];
        Array.Copy(bytes, bytes.Length - 20, tb, 0, 20);
        Trailer t = Trailer.FromBytes(tb);
        Assert.Equal((ulong)Constants.HeaderSize, t.PartitionTableOffset);
        Assert.Equal(Constants.ChainForward, t.ChainFlags);

        var c = Container.Open(new MemoryStream(bytes));
        Assert.Equal(Constants.PtOffsetTrailer, c.Header.PartitionTableOffset);
        Assert.Equal((ulong)Constants.HeaderSize, c.TableHead);
        Assert.False(c.ChainIsBackward);
        c.Verify();
        var e = c.Entries();
        Assert.Equal(2, e.Count);
        Assert.Equal(Encoding.ASCII.GetBytes("Hello, PCF!"), c.ReadPartitionData(e[0]));
    }

    [Fact]
    public void Reports_backward_flag()
    {
        var s = new MemoryStream();
        var c = Container.Create(s);
        c.AddPartition(1, TestSupport.Uid(1), "only", Encoding.ASCII.GetBytes("data"), 0, HashAlgo.Sha256);
        byte[] baseBytes = s.ToArray();
        ulong head = HeaderOffset(baseBytes);

        var trailer = new Trailer { PartitionTableOffset = head, ChainFlags = Constants.ChainBackward };
        byte[] bytes = WithSentinel(Concat(baseBytes, trailer.ToBytes()));

        var r = Container.Open(new MemoryStream(bytes));
        Assert.Equal(head, r.TableHead);
        Assert.True(r.ChainIsBackward);
        r.Verify();
        Assert.Single(r.Entries());
    }

    [Fact]
    public void Rejects_missing_trailer()
    {
        var s = new MemoryStream();
        var c = Container.Create(s);
        c.AddPartition(1, TestSupport.Uid(1), "p", Encoding.ASCII.GetBytes("x"), 0, HashAlgo.Sha256);
        byte[] bytes = WithSentinel(s.ToArray());

        var ex = Assert.Throws<PcfException>(() => Container.Open(new MemoryStream(bytes)));
        Assert.Equal(PcfError.BadTrailer, ex.Kind);
    }

    [Fact]
    public void Recovers_from_aborted_append()
    {
        var garbage = new byte[500];
        Array.Fill(garbage, (byte)0xAB);
        byte[] bytes = Concat(Build(), garbage);

        var c = Container.Open(new MemoryStream(bytes));
        Assert.Equal((ulong)Constants.HeaderSize, c.TableHead);
        c.Verify();
        Assert.Equal(2, c.Entries().Count);
    }

    [Fact]
    public void Skips_spurious_trailer_magic_in_tail()
    {
        var fakeA = new Trailer { PartitionTableOffset = 5, ChainFlags = Constants.ChainForward };
        var fakeB = new Trailer { PartitionTableOffset = ulong.MaxValue - 1, ChainFlags = Constants.ChainForward };
        byte[] bytes = Concat(Build(), fakeA.ToBytes(), fakeB.ToBytes());

        var c = Container.Open(new MemoryStream(bytes));
        Assert.Equal((ulong)Constants.HeaderSize, c.TableHead);
        c.Verify();
        Assert.Equal(2, c.Entries().Count);
    }

    [Fact]
    public void Trailer_from_bytes_validates_length_and_magic()
    {
        Assert.Equal(PcfError.BadTrailer,
            Assert.Throws<PcfException>(() => Trailer.FromBytes(new byte[10])).Kind);
        byte[] good = new Trailer { PartitionTableOffset = 20, ChainFlags = Constants.ChainForward }.ToBytes();
        good[19] = 0; // corrupt the magic
        Assert.Equal(PcfError.BadTrailer,
            Assert.Throws<PcfException>(() => Trailer.FromBytes(good)).Kind);
    }

    [Fact]
    public void Rejects_header_only_sentinel_file()
    {
        var s = new MemoryStream();
        var c = Container.Create(s);
        c.AddPartition(1, TestSupport.Uid(1), "p", Encoding.ASCII.GetBytes("x"), 0, HashAlgo.Sha256);
        byte[] full = s.ToArray();
        var header = new byte[20];
        Array.Copy(full, 0, header, 0, 20);
        header = WithSentinel(header);

        var ex = Assert.Throws<PcfException>(() => Container.Open(new MemoryStream(header)));
        Assert.Equal(PcfError.BadTrailer, ex.Kind);
    }
}
