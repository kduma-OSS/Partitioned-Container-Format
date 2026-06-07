using System;
using Pcf;
using Pcf.Sig;
using Xunit;

namespace Pcf.Sig.Tests;

public class SpecComplianceTests
{
    [Fact]
    public void Section5ReservedTypeValues()
    {
        Assert.Equal(0xAAAB_0001u, Constants.TypePcfsigKey);
        Assert.Equal(0xAAAB_0002u, Constants.TypePcfsigSig);
    }

    [Fact]
    public void Section61KeyMagic()
    {
        Assert.Equal(
            new byte[] { 0x50, 0x43, 0x46, 0x4B, 0x45, 0x59, 0x00, 0x00 },
            Constants.KeyMagic);
    }

    [Fact]
    public void Section61ProfileVersionConstants()
    {
        Assert.Equal((ushort)1, Constants.ProfileVersionMajor);
        Assert.Equal((ushort)0, Constants.ProfileVersionMinor);
    }

    [Fact]
    public void Section61ReaderRejectsBadKeyMagic()
    {
        var bytes = KeyRecord.Make(KeyFormat.Ed25519Raw, TestSupport.Repeat(0x10, 32)).ToBytes();
        bytes[0] = (byte)'X';
        var ex = Assert.Throws<PcfSigException>(() => KeyRecord.FromBytes(bytes));
        Assert.Equal(PcfSigErrorKind.BadKeyMagic, ex.Kind);
    }

    [Fact]
    public void Section61ReaderRejectsUnknownMajor()
    {
        var bytes = KeyRecord.Make(KeyFormat.Ed25519Raw, TestSupport.Repeat(0x10, 32)).ToBytes();
        bytes[8] = 2;
        var ex = Assert.Throws<PcfSigException>(() => KeyRecord.FromBytes(bytes));
        Assert.Equal(PcfSigErrorKind.UnsupportedMajor, ex.Kind);
    }

    [Fact]
    public void Section61ReaderRejectsNonZeroReserved()
    {
        var bytes = KeyRecord.Make(KeyFormat.Ed25519Raw, TestSupport.Repeat(0x10, 32)).ToBytes();
        bytes[13] = 0xFF;
        var ex = Assert.Throws<PcfSigException>(() => KeyRecord.FromBytes(bytes));
        Assert.Equal(PcfSigErrorKind.NonZeroKeyReserved, ex.Kind);
    }

    [Fact]
    public void Section63FingerprintIsSha256()
    {
        var key = TestSupport.Repeat(0xAA, 32);
        var rec = KeyRecord.Make(KeyFormat.Ed25519Raw, key);
        Assert.Equal(KeyRecord.ComputeFingerprint(key), rec.Fingerprint);
        Assert.Equal(32, Constants.FingerprintSize);
    }

    [Fact]
    public void Section63ReaderRejectsFingerprintMismatch()
    {
        var bytes = KeyRecord.Make(KeyFormat.Ed25519Raw, TestSupport.Repeat(0x10, 32)).ToBytes();
        bytes[16] ^= 0x01;
        var ex = Assert.Throws<PcfSigException>(() => KeyRecord.FromBytes(bytes));
        Assert.Equal(PcfSigErrorKind.FingerprintMismatch, ex.Kind);
    }

    [Fact]
    public void Section71SigMagic()
    {
        Assert.Equal(
            new byte[] { 0x50, 0x43, 0x46, 0x53, 0x49, 0x47, 0x00, 0x00 },
            Constants.SigMagic);
    }

    [Fact]
    public void Section71ByteLayoutSizes()
    {
        Assert.Equal(60, Constants.ManifestPrefixSize);
        Assert.Equal(218, Constants.SignedEntrySize);
    }

    [Fact]
    public void Section8Ed25519BindsSha512()
    {
        Assert.Equal(HashAlgo.Sha512, SigAlgo.Ed25519.RequiredManifestHash());
    }

    [Fact]
    public void Section8Ed25519IsImplemented()
    {
        Assert.True(SigAlgo.Ed25519.IsImplemented());
    }

    [Fact]
    public void Section9CryptoHashCheck()
    {
        Assert.True(Manifest.IsCryptoHash(HashAlgo.Sha256));
        Assert.True(Manifest.IsCryptoHash(HashAlgo.Sha512));
        Assert.True(Manifest.IsCryptoHash(HashAlgo.Blake3));
        Assert.False(Manifest.IsCryptoHash(HashAlgo.Crc32c));
        Assert.False(Manifest.IsCryptoHash(HashAlgo.Md5));
        Assert.False(Manifest.IsCryptoHash(HashAlgo.Sha1));
    }

    [Fact]
    public void Section72NilUidEntryRejected()
    {
        var bytes = new byte[Constants.SignedEntrySize];
        LittleEndianWriteU32(bytes, 16, 0x10);
        bytes[60] = HashAlgoExtensions.Id(HashAlgo.Sha256);
        var ex = Assert.Throws<PcfSigException>(() => SignedEntry.FromBytes(bytes));
        Assert.Equal(PcfSigErrorKind.EntryNilUid, ex.Kind);
    }

    [Fact]
    public void Section72WeakDataHashRejected()
    {
        var bytes = new byte[Constants.SignedEntrySize];
        bytes[0] = 1;
        LittleEndianWriteU32(bytes, 16, 0x10);
        bytes[60] = HashAlgoExtensions.Id(HashAlgo.Crc32c);
        var ex = Assert.Throws<PcfSigException>(() => SignedEntry.FromBytes(bytes));
        Assert.Equal(PcfSigErrorKind.NonCryptoEntryHash, ex.Kind);
    }

    [Fact]
    public void Section73NonZeroTrailerRejected()
    {
        var entry = new SignedEntry
        {
            Uid = TestSupport.Uid(1),
            PartitionType = 0x10,
            Label = new byte[Pcf.Constants.LabelSize],
            UsedBytes = 0,
            DataHashAlgo = HashAlgo.Sha256,
            DataHash = new byte[Pcf.Constants.HashFieldSize],
        };
        var manifest = Manifest.Make(SigAlgo.Ed25519, HashAlgo.Sha512,
            new byte[Constants.FingerprintSize], 0,
            new System.Collections.Generic.List<SignedEntry> { entry });
        var mb = manifest.ToBytes();
        var tail = new byte[mb.Length + 4 + 64 + 4 + 1];
        Buffer.BlockCopy(mb, 0, tail, 0, mb.Length);
        LittleEndianWriteU32(tail, mb.Length, 64);
        LittleEndianWriteU32(tail, mb.Length + 4 + 64, 1);
        var ex = Assert.Throws<PcfSigException>(() => SignaturePartition.FromBytes(tail));
        Assert.Equal(PcfSigErrorKind.NonZeroTrailer, ex.Kind);
    }

    [Fact]
    public void Section72SignedEntryRoundtrip()
    {
        var label = new byte[Pcf.Constants.LabelSize];
        System.Text.Encoding.UTF8.GetBytes("alpha", 0, 5, label, 0);
        var hash = new byte[Pcf.Constants.HashFieldSize];
        for (int i = 0; i < 32; i++) hash[i] = 0x7F;
        var entry = new SignedEntry
        {
            Uid = TestSupport.Uid(1),
            PartitionType = 0x10,
            Label = label,
            UsedBytes = 15,
            DataHashAlgo = HashAlgo.Sha256,
            DataHash = hash,
        };
        var bytes = entry.ToBytes();
        Assert.Equal(Constants.SignedEntrySize, bytes.Length);
        var parsed = SignedEntry.FromBytes(bytes);
        Assert.Equal(entry.PartitionType, parsed.PartitionType);
        Assert.Equal(entry.UsedBytes, parsed.UsedBytes);
        Assert.Equal(entry.DataHashAlgo, parsed.DataHashAlgo);
    }

    private static void LittleEndianWriteU32(byte[] b, int o, uint v)
    {
        b[o] = (byte)(v & 0xFF);
        b[o + 1] = (byte)((v >> 8) & 0xFF);
        b[o + 2] = (byte)((v >> 16) & 0xFF);
        b[o + 3] = (byte)((v >> 24) & 0xFF);
    }
}
