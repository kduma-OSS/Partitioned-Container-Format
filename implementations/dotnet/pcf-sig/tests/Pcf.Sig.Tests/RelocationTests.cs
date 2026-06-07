using System.IO;
using System.Linq;
using System.Text;
using Pcf;
using Pcf.Sig;
using Xunit;

namespace Pcf.Sig.Tests;

public class RelocationTests
{
    [Fact]
    public void SignatureSurvivesPcfCompaction()
    {
        var c = Container.Create(new MemoryStream());
        c.AddPartition(0x10, TestSupport.Uid(1), "alpha",
            Encoding.UTF8.GetBytes("alpha payload"), 1024, HashAlgo.Sha256);
        c.AddPartition(0x11, TestSupport.Uid(2), "beta",
            Encoding.UTF8.GetBytes("beta payload"), 1024, HashAlgo.Sha512);
        c.AddPartition(0x12, TestSupport.Uid(3), "gamma",
            Encoding.UTF8.GetBytes("gamma payload"), 1024, HashAlgo.Blake3);
        var signer = SigningMaterial.Ed25519FromSeed(TestSupport.Repeat(0x10, 32));
        SignPartitions.Run(c, signer,
            new[] { TestSupport.Uid(1), TestSupport.Uid(2), TestSupport.Uid(3) },
            TestSupport.Uid(0xA1), TestSupport.Uid(0xA0),
            0, "sig", "key");

        var compacted = c.CompactedImage();
        var c2 = Container.Open(new MemoryStream(compacted));
        c2.Verify();

        var alpha = c2.Entries().First(e => e.Uid[0] == 1);
        Assert.Equal(13UL, alpha.UsedBytes);
        Assert.Equal(13UL, alpha.MaxLength);

        var reports = Verify.AllWithRecheck(c2);
        Assert.Equal(ManifestVerdict.Valid, reports[0].Verdict);
        Assert.Equal(3, reports[0].Entries.Count);
        foreach (var er in reports[0].Entries)
        {
            Assert.Equal(EntryVerdict.Valid, er.Verdict);
        }
    }

    [Fact]
    public void SignatureSurvivesChainGrowth()
    {
        var c = Container.CreateWith(new MemoryStream(), 2, HashAlgo.Sha256);
        c.AddPartition(0x10, TestSupport.Uid(1), "alpha",
            Encoding.UTF8.GetBytes("alpha"), 0, HashAlgo.Sha256);
        var signer = SigningMaterial.Ed25519FromSeed(TestSupport.Repeat(0x20, 32));
        SignPartitions.Run(c, signer, new[] { TestSupport.Uid(1) },
            TestSupport.Uid(0xA1), TestSupport.Uid(0xA0),
            0, "sig", "key");
        for (int i = 0; i < 6; i++)
        {
            c.AddPartition(0x20, TestSupport.Uid(0x40 + i), "extra",
                new byte[] { (byte)i, (byte)i, (byte)i, (byte)i }, 0, HashAlgo.Sha256);
        }
        c.Verify();
        var reports = Verify.AllWithRecheck(c);
        Assert.Equal(ManifestVerdict.Valid, reports[0].Verdict);
        Assert.Equal(EntryVerdict.Valid, reports[0].Entries[0].Verdict);
    }

    [Fact]
    public void SignatureSurvivesUnrelatedUpdate()
    {
        var c = Container.Create(new MemoryStream());
        c.AddPartition(0x10, TestSupport.Uid(1), "signed",
            Encoding.UTF8.GetBytes("locked"), 0, HashAlgo.Sha256);
        c.AddPartition(0x11, TestSupport.Uid(2), "free",
            Encoding.UTF8.GetBytes("original"), 64, HashAlgo.Sha256);
        var signer = SigningMaterial.Ed25519FromSeed(TestSupport.Repeat(0x30, 32));
        SignPartitions.Run(c, signer, new[] { TestSupport.Uid(1) },
            TestSupport.Uid(0xA1), TestSupport.Uid(0xA0),
            0, "sig", "key");
        c.UpdatePartitionData(TestSupport.Uid(2),
            Encoding.UTF8.GetBytes("replaced payload data"));
        c.Verify();
        var reports = Verify.AllWithRecheck(c);
        Assert.Equal(ManifestVerdict.Valid, reports[0].Verdict);
        Assert.Equal(EntryVerdict.Valid, reports[0].Entries[0].Verdict);
    }
}
