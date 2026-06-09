using Pcf;
using Pcf.Dcp;
using Xunit;

namespace Pcf.Dcp.Tests;

public class SpecComplianceTests
{
    [Fact]
    public void StructureSizesMatchAppendixA()
    {
        Assert.Equal(24, Pcf.Dcp.Constants.DcpHeaderSize);
        Assert.Equal(9, Pcf.Dcp.Constants.FragTableHeaderSize);
        Assert.Equal(18, Pcf.Dcp.Constants.FragmentEntrySize);
        Assert.Equal(0xAAAC0001u, Pcf.Dcp.Constants.DcpContainerType);
    }

    [Fact]
    public void HeaderRoundTripsAndCarriesMagic()
    {
        var h = new DcpHeader
        {
            ProfileVersionMajor = 1,
            ProfileVersionMinor = 0,
            Flags = 0,
            InnerTableOffset = 109,
            ArenaUsed = 465,
        };
        var b = h.ToBytes();
        Assert.Equal(new byte[] { 0x50, 0x44, 0x43, 0x50 }, new[] { b[0], b[1], b[2], b[3] });
        var parsed = DcpHeader.FromBytes(b);
        Assert.Equal(109ul, parsed.InnerTableOffset);
        Assert.Equal(465ul, parsed.ArenaUsed);
        Assert.Equal(1, parsed.ProfileVersionMajor);
        Assert.Equal(0, parsed.ProfileVersionMinor);
    }

    [Fact]
    public void FragmentRecordsRoundTrip()
    {
        var e = new FragmentEntry { ExtentOffset = 31, ExtentLength = 6, Kind = 1, Flags = 1 };
        var pe = FragmentEntry.FromBytes(e.ToBytes());
        Assert.Equal(31ul, pe.ExtentOffset);
        Assert.Equal(6ul, pe.ExtentLength);
        Assert.Equal(1, pe.Kind);
        Assert.True(pe.IsShared());

        var fh = new FragTableHeader { NextFragtableOffset = 0, FragmentCount = 2 };
        var pfh = FragTableHeader.FromBytes(fh.ToBytes());
        Assert.Equal(0ul, pfh.NextFragtableOffset);
        Assert.Equal(2, pfh.FragmentCount);
    }

    [Fact]
    public void ReconstructionEqualsLogicalContent()
    {
        var a = new Arena();
        a.AddInner(0x10, TestSupport.Fill(1), "x", TestSupport.Bytes("Hello, World!"), HashAlgo.Sha256, Chunker.Fixed(7));
        Assert.Equal("Hello, World!", TestSupport.Str(a.Content(TestSupport.Fill(1))));
        var info = a.GetInner(TestSupport.Fill(1));
        Assert.Equal(13ul, info.UsedBytes);
        Assert.Equal(2, info.Extents.Count);
    }

    [Fact]
    public void DataHashIsInvariantUnderFragmentation()
    {
        string Mk(Chunker c)
        {
            var a = new Arena();
            a.AddInner(0x10, TestSupport.Fill(7), "x", TestSupport.Bytes("abcdefghij"), HashAlgo.Sha256, c);
            return TestSupport.Hex(a.GetInner(TestSupport.Fill(7)).DataHash);
        }
        Assert.Equal(Mk(Chunker.Whole()), Mk(Chunker.Fixed(3)));
        Assert.Equal(Mk(Chunker.Whole()), TestSupport.Hex(HashAlgo.Sha256.Compute(TestSupport.Bytes("abcdefghij"))));
    }

    [Fact]
    public void DedupSetsSharedOnAllAliasesRuleF1()
    {
        var a = new Arena();
        a.AddInner(0x10, TestSupport.Fill(0xA1), "A", TestSupport.Bytes("Hello, World!"), HashAlgo.Sha256, Chunker.Fixed(7));
        a.AddInner(0x10, TestSupport.Fill(0xB2), "B", TestSupport.Bytes("World!"), HashAlgo.Sha256, Chunker.Whole());

        var ia = a.GetInner(TestSupport.Fill(0xA1));
        var ib = a.GetInner(TestSupport.Fill(0xB2));
        Assert.False(ia.Extents[0].Shared);
        Assert.True(ia.Extents[1].Shared);
        Assert.Single(ib.Extents);
        Assert.True(ib.Extents[0].Shared);
        Assert.Equal(TestSupport.Hex(HashAlgo.Sha256.Compute(TestSupport.Bytes("World!"))), TestSupport.Hex(ib.DataHash));
    }

    [Fact]
    public void ParseRoundTripsCanonicalArenaByteExact()
    {
        var a = new Arena();
        a.AddInner(0x10, TestSupport.Fill(0xA1), "A", TestSupport.Bytes("Hello, World!"), HashAlgo.Sha256, Chunker.Fixed(7));
        a.AddInner(0x10, TestSupport.Fill(0xB2), "B", TestSupport.Bytes("World!"), HashAlgo.Sha256, Chunker.Whole());
        var bytes = a.ToBytes();
        Assert.Equal(TestSupport.Hex(bytes), TestSupport.Hex(Arena.Parse(bytes).ToBytes()));
    }
}
