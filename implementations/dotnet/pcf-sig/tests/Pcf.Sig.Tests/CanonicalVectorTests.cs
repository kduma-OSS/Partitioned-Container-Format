using System.IO;
using System.Security.Cryptography;
using Pcf;
using Pcf.Sig;
using Xunit;

namespace Pcf.Sig.Tests;

public class CanonicalVectorTests
{
    private const string ExpectedSha256 =
        "b158e2f5b160d72cea3226af2041f8d18aa75b3db6cb85faeca5df7879871307";

    private static byte[] Canonical() =>
        File.ReadAllBytes(Path.Combine(
            Path.GetDirectoryName(typeof(CanonicalVectorTests).Assembly.Location)!,
            "testdata", "canonical.bin"));

    private static string Hex(byte[] b)
    {
        using var sha = SHA256.Create();
        return TestSupport.Hex(sha.ComputeHash(b));
    }

    [Fact]
    public void ShipsExpectedSha256()
    {
        Assert.Equal(ExpectedSha256, Hex(Canonical()));
    }

    [Fact]
    public void OpensVerifiesPcfAndPcfSig()
    {
        var c = Container.Open(new MemoryStream(Canonical()));
        c.Verify();
        var reports = Verify.AllWithRecheck(c);
        Assert.Single(reports);
        Assert.Equal(ManifestVerdict.Valid, reports[0].Verdict);
        Assert.Single(reports[0].Entries);
        Assert.Equal(EntryVerdict.Valid, reports[0].Entries[0].Verdict);
    }

    [Fact]
    public void RegeneratesByteExactFromDeterministicSeed()
    {
        var seed = new byte[32];
        for (int i = 0; i < 32; i++) seed[i] = (byte)i;
        var signer = SigningMaterial.Ed25519FromSeed(seed);

        var c = Container.CreateWith(new MemoryStream(), 8, HashAlgo.Sha256);
        c.AddPartition(0x10, TestSupport.Repeat(0x11, 16), "alpha",
            System.Text.Encoding.UTF8.GetBytes("Hello, PCF-SIG!"),
            0, HashAlgo.Sha256);
        SignPartitions.Run(
            c, signer,
            new[] { TestSupport.Repeat(0x11, 16) },
            TestSupport.Repeat(0x33, 16),
            TestSupport.Repeat(0x22, 16),
            0, "pcfsig", "pcfkey");
        var image = c.CompactedImage();
        Assert.Equal(Canonical().Length, image.Length);
        Assert.Equal(ExpectedSha256, Hex(image));
    }
}
