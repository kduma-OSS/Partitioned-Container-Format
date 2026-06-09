using System.IO;
using Pcf;
using Pcf.Dcp;
using Xunit;

namespace Pcf.Dcp.Tests;

public class CanonicalVectorTests
{
    private const string ExpectedSha256 =
        "b9bb59794abed008863063886d8d0daa810c44939c1c5d29449475ced8156b90";

    private static byte[] Canonical() =>
        File.ReadAllBytes(Path.Combine(
            Path.GetDirectoryName(typeof(CanonicalVectorTests).Assembly.Location)!,
            "testdata", "canonical.bin"));

    [Fact]
    public void ShipsExpectedSha256AndLength()
    {
        var c = Canonical();
        Assert.Equal(700, c.Length);
        Assert.Equal(ExpectedSha256, TestSupport.Sha256Hex(c));
    }

    [Fact]
    public void RegeneratesByteExact()
    {
        var image = ReferenceVector.Build();
        Assert.Equal(700, image.Length);
        Assert.Equal(ExpectedSha256, TestSupport.Sha256Hex(image));
        Assert.Equal(TestSupport.Hex(Canonical()), TestSupport.Hex(image));
    }

    [Fact]
    public void IsValidPcf()
    {
        var c = Container.Open(new MemoryStream(Canonical()));
        c.Verify();
        var entries = c.Entries();
        Assert.Single(entries);
        Assert.Equal(0xAAAC0001u, entries[0].PartitionType);
        Assert.Equal(465ul, entries[0].UsedBytes);
    }

    [Fact]
    public void IsValidDcp()
    {
        var r = DcpReader.Open(new MemoryStream(Canonical()));
        r.Verify();
        Assert.Equal("Hello, World!", TestSupport.Str(r.ReadInner(TestSupport.Fill(0xA1))));
        Assert.Equal("World!", TestSupport.Str(r.ReadInner(TestSupport.Fill(0xB2))));
    }
}
