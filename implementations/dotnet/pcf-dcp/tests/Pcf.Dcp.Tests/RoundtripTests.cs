using System.IO;
using Pcf;
using Pcf.Dcp;
using Xunit;

namespace Pcf.Dcp.Tests;

public class RoundtripTests
{
    private static byte[] BuildTwoInnerFile()
    {
        var arena = new Arena();
        arena.AddInner(0x10, TestSupport.Fill(0xA1), "A", TestSupport.Bytes("Hello, World!"), HashAlgo.Sha256, Chunker.Fixed(7));
        arena.AddInner(0x10, TestSupport.Fill(0xB2), "B", TestSupport.Bytes("World!"), HashAlgo.Sha256, Chunker.Whole());
        var w = new DcpWriter();
        w.AddContainer(TestSupport.Fill(0xDC), "dcp", arena);
        return w.ToImage();
    }

    [Fact]
    public void EditsReconstructCorrectly()
    {
        var a = new Arena();
        a.AddInner(0x10, TestSupport.Fill(1), "f", TestSupport.Bytes("Hello, World!"), HashAlgo.Sha256, Chunker.Fixed(7));

        a.Append(TestSupport.Fill(1), TestSupport.Bytes("!!"));
        Assert.Equal("Hello, World!!!", TestSupport.Str(a.Content(TestSupport.Fill(1))));

        a.Insert(TestSupport.Fill(1), 5, TestSupport.Bytes("XYZ"));
        Assert.Equal("HelloXYZ, World!!!", TestSupport.Str(a.Content(TestSupport.Fill(1))));

        a.Delete(TestSupport.Fill(1), 5, 3);
        Assert.Equal("Hello, World!!!", TestSupport.Str(a.Content(TestSupport.Fill(1))));

        a.Overwrite(TestSupport.Fill(1), 0, 5, TestSupport.Bytes("HOWDY"));
        Assert.Equal("HOWDY, World!!!", TestSupport.Str(a.Content(TestSupport.Fill(1))));

        a.Truncate(TestSupport.Fill(1), 5);
        Assert.Equal("HOWDY", TestSupport.Str(a.Content(TestSupport.Fill(1))));
    }

    [Fact]
    public void CopyOnWriteDoesNotDisturbSharedBytes()
    {
        var a = new Arena();
        a.AddInner(0x10, TestSupport.Fill(0xA1), "A", TestSupport.Bytes("Hello, World!"), HashAlgo.Sha256, Chunker.Fixed(7));
        a.AddInner(0x10, TestSupport.Fill(0xB2), "B", TestSupport.Bytes("World!"), HashAlgo.Sha256, Chunker.Whole());
        a.Overwrite(TestSupport.Fill(0xA1), 7, 6, TestSupport.Bytes("PLANET"));
        Assert.Equal("Hello, PLANET", TestSupport.Str(a.Content(TestSupport.Fill(0xA1))));
        Assert.Equal("World!", TestSupport.Str(a.Content(TestSupport.Fill(0xB2))));
    }

    [Fact]
    public void DedupThenDefragPreserveContent()
    {
        var a = new Arena();
        a.AddInner(0x10, TestSupport.Fill(1), "A", TestSupport.Bytes("abcabc"), HashAlgo.Sha256, Chunker.Whole());
        a.AddInner(0x10, TestSupport.Fill(2), "B", TestSupport.Bytes("abcabc"), HashAlgo.Sha256, Chunker.Whole());
        var h1 = a.GetInner(TestSupport.Fill(1)).DataHash;

        long saved = a.Dedup(Chunker.Fixed(3));
        Assert.True(saved > 0);
        Assert.Equal("abcabc", TestSupport.Str(a.Content(TestSupport.Fill(1))));
        Assert.Equal("abcabc", TestSupport.Str(a.Content(TestSupport.Fill(2))));
        Assert.Equal(TestSupport.Hex(h1), TestSupport.Hex(a.GetInner(TestSupport.Fill(1)).DataHash));

        a.Compact();
        Assert.Equal("abcabc", TestSupport.Str(a.Content(TestSupport.Fill(2))));
    }

    [Fact]
    public void DefragClearsSharedWhenNoLongerAliased()
    {
        var a = new Arena();
        a.AddInner(0x10, TestSupport.Fill(0xA1), "A", TestSupport.Bytes("Hello, World!"), HashAlgo.Sha256, Chunker.Fixed(7));
        a.AddInner(0x10, TestSupport.Fill(0xB2), "B", TestSupport.Bytes("World!"), HashAlgo.Sha256, Chunker.Whole());
        a.RemoveInner(TestSupport.Fill(0xB2));
        a.Compact();
        var ia = a.GetInner(TestSupport.Fill(0xA1));
        Assert.All(ia.Extents, e => Assert.False(e.Shared));
        Assert.Equal("Hello, World!", TestSupport.Str(a.Content(TestSupport.Fill(0xA1))));
    }

    [Fact]
    public void PromotePreservesUidAndDataHash()
    {
        var w = DcpWriter.Open(new MemoryStream(BuildTwoInnerFile()));
        byte[] before;
        {
            var r0 = DcpReader.Open(new MemoryStream(w.ToImage()));
            before = r0.InnerPartitions().Find(l => l.Info.Uid[0] == 0xB2)!.Info.DataHash;
        }

        w.Promote(TestSupport.Fill(0xDC), TestSupport.Fill(0xB2));
        var r = DcpReader.Open(new MemoryStream(w.ToImage()));
        r.Verify();
        var resolved = r.ResolveUid(TestSupport.Fill(0xB2));
        Assert.True(resolved.IsTopLevel);
        Assert.Equal(TestSupport.Hex(before), TestSupport.Hex(resolved.Entry!.DataHash));
        Assert.Equal(6ul, resolved.Entry.UsedBytes);
        Assert.Equal("Hello, World!", TestSupport.Str(r.ReadInner(TestSupport.Fill(0xA1))));
    }

    [Fact]
    public void DemoteThenPromoteIsIdentityForContent()
    {
        var w = DcpWriter.Open(new MemoryStream(BuildTwoInnerFile()));
        w.Promote(TestSupport.Fill(0xDC), TestSupport.Fill(0xB2));
        w.Demote(TestSupport.Fill(0xB2), TestSupport.Fill(0xDC));
        var r = DcpReader.Open(new MemoryStream(w.ToImage()));
        r.Verify();
        Assert.Equal("World!", TestSupport.Str(r.ReadInner(TestSupport.Fill(0xB2))));
        Assert.False(r.ResolveUid(TestSupport.Fill(0xB2)).IsTopLevel);
    }

    [Fact]
    public void TrailerModeReadsBackIdentically()
    {
        var arena = new Arena();
        arena.AddInner(0x10, TestSupport.Fill(0xA1), "A", TestSupport.Bytes("Hello, World!"), HashAlgo.Sha256, Chunker.Fixed(7));
        arena.AddInner(0x10, TestSupport.Fill(0xB2), "B", TestSupport.Bytes("World!"), HashAlgo.Sha256, Chunker.Whole());
        var w = new DcpWriter();
        w.AddContainer(TestSupport.Fill(0xDC), "dcp", arena);
        w.SetTrailer(true);
        var r = DcpReader.Open(new MemoryStream(w.ToImage()));
        r.Verify();
        Assert.Equal("Hello, World!", TestSupport.Str(r.ReadInner(TestSupport.Fill(0xA1))));
        Assert.Equal(2, r.InnerPartitions().Count);
    }
}
