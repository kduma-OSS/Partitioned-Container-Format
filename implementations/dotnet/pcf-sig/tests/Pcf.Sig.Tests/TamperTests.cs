using System.IO;
using System.Linq;
using System.Text;
using Pcf;
using Pcf.Sig;
using Xunit;

namespace Pcf.Sig.Tests;

public class TamperTests
{
    private static (Container, byte[]) Build()
    {
        var c = Container.Create(new MemoryStream());
        var alpha = TestSupport.Uid(1);
        c.AddPartition(0x10, alpha, "alpha",
            Encoding.UTF8.GetBytes("original payload"), 64, HashAlgo.Sha256);
        var signer = SigningMaterial.Ed25519FromSeed(TestSupport.Repeat(0x33, 32));
        SignPartitions.Run(c, signer, new[] { alpha },
            TestSupport.Uid(0xA1), TestSupport.Uid(0xA0),
            0, "sig", "key");
        return (c, alpha);
    }

    [Fact]
    public void BaselineVerifies()
    {
        var (c, _) = Build();
        var reports = Verify.AllWithRecheck(c);
        Assert.Equal(ManifestVerdict.Valid, reports[0].Verdict);
        Assert.Equal(EntryVerdict.Valid, reports[0].Entries[0].Verdict);
    }

    [Fact]
    public void DataUpdateInvalidatesEntry()
    {
        var (c, alpha) = Build();
        c.UpdatePartitionData(alpha, Encoding.UTF8.GetBytes("forged payload"));
        var reports = Verify.AllWithRecheck(c);
        Assert.Equal(ManifestVerdict.Valid, reports[0].Verdict);
        Assert.Equal(EntryVerdict.ProtectedFieldMismatch, reports[0].Entries[0].Verdict);
    }

    [Fact]
    public void RemovedCoveredPartitionIsReportedMissing()
    {
        var (c, alpha) = Build();
        c.RemovePartition(alpha);
        var reports = Verify.AllWithRecheck(c);
        Assert.Equal(ManifestVerdict.Valid, reports[0].Verdict);
        Assert.Equal(EntryVerdict.MissingPartition, reports[0].Entries[0].Verdict);
    }

    [Fact]
    public void FlippingSignatureByteInvalidatesManifest()
    {
        var (c, _) = Build();
        var bytes = c.CompactedImage();
        var c2 = Container.Open(new MemoryStream(bytes));
        var sig = c2.Entries().First(e => e.PartitionType == Constants.TypePcfsigSig);
        int last = (int)(sig.StartOffset + sig.UsedBytes - 8);
        bytes[last] ^= 0x01;
        var c3 = Container.Open(new MemoryStream(bytes));
        var reports = Verify.AllWithRecheck(c3);
        Assert.Equal(ManifestVerdict.Invalid, reports[0].Verdict);
    }
}
