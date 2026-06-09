using System.IO;
using Pcf;
using Pcf.Dcp;
using Xunit;

namespace Pcf.Dcp.Tests;

public class CoverageTests
{
    private static PcfDcpErrorKind KindOf(System.Action fn)
    {
        var ex = Assert.Throws<PcfDcpException>(fn);
        return ex.Kind;
    }

    [Fact]
    public void RejectsBadArenaMagic()
    {
        var a = new Arena();
        a.AddInner(0x10, TestSupport.Fill(1), "x", TestSupport.Bytes("hi"), HashAlgo.Sha256, Chunker.Whole());
        var bytes = a.ToBytes();
        bytes[0] = 0x58;
        Assert.Equal(PcfDcpErrorKind.BadDcpMagic, KindOf(() => Arena.Parse(bytes)));
    }

    [Fact]
    public void RejectsUnsupportedProfileMajor()
    {
        var a = new Arena();
        a.AddInner(0x10, TestSupport.Fill(1), "x", TestSupport.Bytes("hi"), HashAlgo.Sha256, Chunker.Whole());
        var bytes = a.ToBytes();
        bytes[4] = 2;
        Assert.Equal(PcfDcpErrorKind.UnsupportedProfileMajor, KindOf(() => Arena.Parse(bytes)));
    }

    [Fact]
    public void RejectsReservedNestedAndNilUid()
    {
        var a = new Arena();
        Assert.Equal(PcfDcpErrorKind.ReservedType,
            KindOf(() => a.AddInner(0, TestSupport.Fill(1), "x", TestSupport.Bytes(""), HashAlgo.None, Chunker.Whole())));
        Assert.Equal(PcfDcpErrorKind.NestedContainer,
            KindOf(() => a.AddInner(0xAAAC0001, TestSupport.Fill(1), "x", TestSupport.Bytes(""), HashAlgo.None, Chunker.Whole())));
        Assert.Equal(PcfDcpErrorKind.NilUid,
            KindOf(() => a.AddInner(0x10, new byte[16], "x", TestSupport.Bytes(""), HashAlgo.None, Chunker.Whole())));
    }

    [Fact]
    public void RejectsDuplicateUidWithinArena()
    {
        var a = new Arena();
        a.AddInner(0x10, TestSupport.Fill(1), "x", TestSupport.Bytes("a"), HashAlgo.None, Chunker.Whole());
        Assert.Equal(PcfDcpErrorKind.DuplicateUid,
            KindOf(() => a.AddInner(0x10, TestSupport.Fill(1), "y", TestSupport.Bytes("b"), HashAlgo.None, Chunker.Whole())));
    }

    [Fact]
    public void RejectsBadKindAndOutOfRangeExtent()
    {
        Assert.Equal(PcfDcpErrorKind.BadFragmentKind,
            KindOf(() => FragmentTable.Reconstruct(new byte[64],
                new[] { new FragmentEntry { ExtentOffset = 24, ExtentLength = 1, Kind = 2, Flags = 0 } }, 64)));
        Assert.Equal(PcfDcpErrorKind.OffsetOutOfRange,
            KindOf(() => FragmentTable.Reconstruct(new byte[64],
                new[] { new FragmentEntry { ExtentOffset = 60, ExtentLength = 100, Kind = 1, Flags = 0 } }, 64)));
    }

    [Fact]
    public void AllowsEmptyInner()
    {
        var a = new Arena();
        a.AddInner(0x10, TestSupport.Fill(1), "empty", TestSupport.Bytes(""), HashAlgo.Sha256, Chunker.Whole());
        var info = a.GetInner(TestSupport.Fill(1));
        Assert.Equal(0ul, info.UsedBytes);
        Assert.Empty(info.Extents);
        var parsed = Arena.Parse(a.ToBytes());
        Assert.Empty(parsed.Content(TestSupport.Fill(1)));
    }

    [Fact]
    public void ChainsInnerTableBeyond255()
    {
        var a = new Arena();
        for (int i = 0; i < 300; i++)
        {
            var uid = new byte[16];
            uid[0] = (byte)(i & 0xFF);
            uid[1] = (byte)((i >> 8) & 0xFF);
            uid[15] = 1;
            a.AddInner(0x10, uid, "n", new byte[] { (byte)(i & 0xFF), (byte)((i >> 8) & 0xFF) }, HashAlgo.Sha256, Chunker.Whole());
        }
        Assert.Equal(300, a.Count);
        Assert.Equal(300, Arena.Parse(a.ToBytes()).Count);

        var w = new DcpWriter();
        w.AddContainer(TestSupport.Fill(0xDC), "big", a);
        DcpReader.Open(new MemoryStream(w.ToImage())).Verify();
    }

    [Fact]
    public void ChainsFragmentTableBeyond255()
    {
        var a = new Arena();
        var distinct = new byte[300];
        for (int i = 0; i < 300; i++) distinct[i] = (byte)(i & 0xFF);
        a.AddInner(0x10, TestSupport.Fill(2), "frag", distinct, HashAlgo.Sha256, Chunker.Fixed(1));
        var parsed = Arena.Parse(a.ToBytes());
        Assert.Equal(TestSupport.Hex(distinct), TestSupport.Hex(parsed.Content(TestSupport.Fill(2))));
    }

    [Fact]
    public void VerifyDetectsFileWideUidCollision()
    {
        var a = new Arena();
        a.AddInner(0x10, TestSupport.Fill(0xB2), "B", TestSupport.Bytes("World!"), HashAlgo.Sha256, Chunker.Whole());
        var w = new DcpWriter();
        w.AddContainer(TestSupport.Fill(0xDC), "dcp", a);
        w.AddPlain(0x10, TestSupport.Fill(0xB2), "dup", TestSupport.Bytes("x"), HashAlgo.Sha256);
        var r = DcpReader.Open(new MemoryStream(w.ToImage()));
        Assert.Equal(PcfDcpErrorKind.DuplicateUid, KindOf(() => r.Verify()));
    }

    [Fact]
    public void OpenArenaRejectsNonDcpPartition()
    {
        var c = Container.CreateWith(new MemoryStream(), 4, HashAlgo.Sha256);
        c.AddPartition(0x10, TestSupport.Fill(7), "plain", TestSupport.Bytes("hi"), 0, HashAlgo.Sha256);
        var r = DcpReader.Open(c.Storage);
        var entry = r.Entries()[0];
        Assert.Equal(PcfDcpErrorKind.NotADcpContainer, KindOf(() => r.OpenArena(entry)));
    }
}
