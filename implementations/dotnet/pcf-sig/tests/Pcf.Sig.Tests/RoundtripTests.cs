using System.IO;
using System.Linq;
using System.Text;
using Pcf;
using Pcf.Sig;
using Xunit;

namespace Pcf.Sig.Tests;

public class RoundtripTests
{
    [Fact]
    public void SignsAndVerifiesSinglePartition()
    {
        var c = Container.Create(new MemoryStream());
        var alpha = TestSupport.Uid(1);
        c.AddPartition(0x10, alpha, "alpha", Encoding.UTF8.GetBytes("hello"), 0, HashAlgo.Sha256);

        var signer = SigningMaterial.Ed25519FromSeed(TestSupport.Repeat(0x42, 32));
        SignPartitions.Run(
            c, signer, new[] { alpha },
            TestSupport.Uid(0xA1), TestSupport.Uid(0xA0),
            1_700_000_000, "pcfsig", "pcfkey");

        c.Verify();
        var reports = Verify.All(c, DataRecheck.Skip);
        Assert.Single(reports);
        Assert.Equal(ManifestVerdict.Valid, reports[0].Verdict);
        Assert.Single(reports[0].Entries);
        Assert.Equal(EntryVerdict.Valid, reports[0].Entries[0].Verdict);
        Assert.Equal(1_700_000_000, reports[0].SignedAtUnixSeconds);
        Assert.Equal(signer.Fingerprint(), reports[0].SignerKeyFingerprint);
    }

    [Fact]
    public void ReopensAfterSerialiseAndVerifies()
    {
        var ms = new MemoryStream();
        var c = Container.Create(ms);
        c.AddPartition(0x10, TestSupport.Uid(1), "alpha", Encoding.UTF8.GetBytes("hello"), 0, HashAlgo.Sha256);
        c.AddPartition(0x11, TestSupport.Uid(2), "beta", Encoding.UTF8.GetBytes("world"), 0, HashAlgo.Blake3);
        var signer = SigningMaterial.Ed25519FromSeed(TestSupport.Repeat(0x01, 32));
        SignPartitions.Run(
            c, signer, new[] { TestSupport.Uid(1), TestSupport.Uid(2) },
            TestSupport.Uid(0xA1), TestSupport.Uid(0xA0),
            0, "sig", "key");
        var image = c.CompactedImage();

        var c2 = Container.Open(new MemoryStream(image));
        c2.Verify();
        var reports = Verify.AllWithRecheck(c2);
        Assert.Single(reports);
        Assert.Equal(ManifestVerdict.Valid, reports[0].Verdict);
        Assert.Equal(2, reports[0].Entries.Count);
        foreach (var er in reports[0].Entries)
        {
            Assert.Equal(EntryVerdict.Valid, er.Verdict);
        }
    }

    [Fact]
    public void DeduplicatesKeyPartitions()
    {
        var c = Container.Create(new MemoryStream());
        c.AddPartition(0x10, TestSupport.Uid(1), "a", new byte[] { 0x61 }, 0, HashAlgo.Sha256);
        c.AddPartition(0x10, TestSupport.Uid(2), "b", new byte[] { 0x62 }, 0, HashAlgo.Sha256);

        var signer = SigningMaterial.Ed25519FromSeed(TestSupport.Repeat(0x03, 32));
        SignPartitions.Run(c, signer, new[] { TestSupport.Uid(1) },
            TestSupport.Uid(0xA1), TestSupport.Uid(0xA0), 0, "sig1", "k");
        SignPartitions.Run(c, signer, new[] { TestSupport.Uid(2) },
            TestSupport.Uid(0xA2), TestSupport.Uid(0xA3), 0, "sig2", "k2");

        var keyPartitions = c.Entries()
            .Where(e => e.PartitionType == Constants.TypePcfsigKey)
            .ToList();
        Assert.Single(keyPartitions);
        Assert.Equal(TestSupport.Uid(0xA0), keyPartitions[0].Uid);

        var reports = Verify.All(c, DataRecheck.Skip);
        Assert.Equal(2, reports.Count);
        foreach (var r in reports)
        {
            Assert.Equal(ManifestVerdict.Valid, r.Verdict);
        }
    }

    [Fact]
    public void RefusesToSignWeaklyHashedPartition()
    {
        var c = Container.Create(new MemoryStream());
        var alpha = TestSupport.Uid(1);
        c.AddPartition(0x10, alpha, "alpha", new byte[] { 0x78 }, 0, HashAlgo.Crc32c);
        var signer = SigningMaterial.Ed25519FromSeed(TestSupport.Repeat(0x04, 32));
        var ex = Assert.Throws<PcfSigException>(() => SignPartitions.Run(
            c, signer, new[] { alpha },
            TestSupport.Uid(0xA1), TestSupport.Uid(0xA0),
            0, "sig", "key"));
        Assert.Equal(PcfSigErrorKind.NonCryptoTargetHash, ex.Kind);
    }

    [Fact]
    public void RefusesSelfReference()
    {
        var c = Container.Create(new MemoryStream());
        var alpha = TestSupport.Uid(1);
        c.AddPartition(0x10, alpha, "alpha", new byte[] { 0x78 }, 0, HashAlgo.Sha256);
        var signer = SigningMaterial.Ed25519FromSeed(TestSupport.Repeat(0x05, 32));
        var sigUid = TestSupport.Uid(0xA1);
        var ex = Assert.Throws<PcfSigException>(() => SignPartitions.Run(
            c, signer, new[] { alpha, sigUid }, sigUid, TestSupport.Uid(0xA0),
            0, "sig", "key"));
        Assert.Equal(PcfSigErrorKind.SelfSignedEntry, ex.Kind);
    }
}
