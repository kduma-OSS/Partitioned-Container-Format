using System;
using System.IO;
using System.Text;

namespace Pcf.Tests;

/// <summary>Targeted error-path, algorithm-variant and edge-case tests.</summary>
public class CoverageTests
{
    // ---- header / entry / table roundtrips --------------------------------

    [Fact]
    public void Header_roundtrips()
    {
        var h = new FileHeader { VersionMajor = 1, VersionMinor = 0, PartitionTableOffset = 20 };
        var back = FileHeader.FromBytes(h.ToBytes());
        Assert.Equal(h.VersionMajor, back.VersionMajor);
        Assert.Equal(h.VersionMinor, back.VersionMinor);
        Assert.Equal(h.PartitionTableOffset, back.PartitionTableOffset);
    }

    [Fact]
    public void Entry_roundtrips()
    {
        var e = new PartitionEntry
        {
            PartitionType = 7,
            Uid = TestSupport.Uid(0x33),
            Label = PartitionEntry.EncodeLabel("hello"),
            StartOffset = 1024,
            MaxLength = 4096,
            UsedBytes = 100,
            DataHashAlgo = HashAlgo.Sha256,
            DataHash = HashAlgo.Sha256.Compute(new byte[] { 9 }),
        };
        var back = PartitionEntry.FromBytes(e.ToBytes());
        Assert.Equal(e.PartitionType, back.PartitionType);
        Assert.Equal(e.Uid, back.Uid);
        Assert.Equal(e.StartOffset, back.StartOffset);
        Assert.Equal(e.MaxLength, back.MaxLength);
        Assert.Equal(e.UsedBytes, back.UsedBytes);
        Assert.Equal(e.DataHashAlgo, back.DataHashAlgo);
        Assert.Equal(e.DataHash, back.DataHash);
    }

    [Fact]
    public void Table_header_roundtrips()
    {
        var h = new TableBlockHeader
        {
            PartitionCount = 3,
            NextTableOffset = 4096,
            TableHashAlgo = HashAlgo.Sha512,
            TableHash = HashAlgo.Sha512.Compute(Encoding.ASCII.GetBytes("abc")),
        };
        var back = TableBlockHeader.FromBytes(h.ToBytes());
        Assert.Equal(h.PartitionCount, back.PartitionCount);
        Assert.Equal(h.NextTableOffset, back.NextTableOffset);
        Assert.Equal(h.TableHashAlgo, back.TableHashAlgo);
        Assert.Equal(h.TableHash, back.TableHash);
    }

    // ---- label encoding ---------------------------------------------------

    [Fact]
    public void Label_too_long_is_rejected()
    {
        var ex = Assert.Throws<PcfException>(() => PartitionEntry.EncodeLabel(new string('a', 33)));
        Assert.Equal(PcfError.InvalidLabel, ex.Kind);
    }

    [Fact]
    public void Label_with_embedded_nul_is_rejected()
    {
        var ex = Assert.Throws<PcfException>(() => PartitionEntry.EncodeLabel("a\0b"));
        Assert.Equal(PcfError.InvalidLabel, ex.Kind);
    }

    [Fact]
    public void Label_with_non_ascii_is_rejected()
    {
        var ex = Assert.Throws<PcfException>(() => PartitionEntry.EncodeLabel("café"));
        Assert.Equal(PcfError.InvalidLabel, ex.Kind);
    }

    // ---- hash algorithm check values --------------------------------------

    [Fact]
    public void Md5_and_sha1_empty_digests()
    {
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        byte[] md5 = HashAlgo.Md5.Compute(Array.Empty<byte>());
        Assert.Equal("d41d8cd98f00b204e9800998ecf8427e", Hex(md5, 16));
        // SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        byte[] sha1 = HashAlgo.Sha1.Compute(Array.Empty<byte>());
        Assert.Equal("da39a3ee5e6b4b0d3255bfef95601890afd80709", Hex(sha1, 20));
    }

    [Fact]
    public void Sha512_empty_digest_length()
    {
        byte[] field = HashAlgo.Sha512.Compute(Array.Empty<byte>());
        Assert.Equal(64, HashAlgo.Sha512.DigestLen());
        // SHA-512("") starts with cf83e1357eefb8bd...
        Assert.Equal("cf83e1357eefb8bd", Hex(field, 8));
    }

    [Fact]
    public void Blake3_empty_digest()
    {
        // BLAKE3("") = af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
        byte[] field = HashAlgo.Blake3.Compute(Array.Empty<byte>());
        Assert.Equal("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", Hex(field, 32));
        // Padding beyond 32 bytes is zero.
        for (int i = 32; i < 64; i++)
        {
            Assert.Equal(0, field[i]);
        }
    }

    [Fact]
    public void Blake3_known_vector()
    {
        // BLAKE3 of the three bytes 0x00 0x01 0x02.
        byte[] field = HashAlgo.Blake3.Compute(new byte[] { 0, 1, 2 });
        Assert.True(HashAlgo.Blake3.Verify(new byte[] { 0, 1, 2 }, field));
        Assert.False(HashAlgo.Blake3.Verify(new byte[] { 0, 1, 3 }, field));
    }

    // ---- container error paths --------------------------------------------

    [Fact]
    public void Open_rejects_unsupported_major()
    {
        byte[] img = TestSupport.CanonicalVector.ToArray();
        img[8] = 0x02;
        var ex = Assert.Throws<PcfException>(() => Container.Open(new MemoryStream(img)));
        Assert.Equal(PcfError.UnsupportedMajor, ex.Kind);
    }

    [Fact]
    public void Update_not_found_throws()
    {
        var c = Container.Create(new MemoryStream());
        c.AddPartition(1, TestSupport.Uid(1), "a", new byte[] { 1 }, 0, HashAlgo.Sha256);
        var ex = Assert.Throws<PcfException>(() =>
            c.UpdatePartitionData(TestSupport.Uid(9), new byte[] { 2 }));
        Assert.Equal(PcfError.NotFound, ex.Kind);
    }

    [Fact]
    public void Remove_not_found_throws()
    {
        var c = Container.Create(new MemoryStream());
        var ex = Assert.Throws<PcfException>(() => c.RemovePartition(TestSupport.Uid(9)));
        Assert.Equal(PcfError.NotFound, ex.Kind);
    }

    [Fact]
    public void Table_hash_corruption_is_detected()
    {
        byte[] img = TestSupport.CanonicalVector.ToArray();
        // The first table_hash field begins at offset 20 + 10 = 30.
        img[30] ^= 0xFF;
        var reopened = Container.Open(new MemoryStream(img));
        var ex = Assert.Throws<PcfException>(() => reopened.Verify());
        Assert.Equal(PcfError.TableHashMismatch, ex.Kind);
    }

    [Fact]
    public void Unknown_algo_id_in_entry_is_rejected_on_read()
    {
        byte[] img = TestSupport.CanonicalVector.ToArray();
        // Entry 0 data_hash_algo_id sits at 0x00AA (= 170).
        img[0x00AA] = 0x07; // reserved / unknown id
        var ex = Assert.Throws<PcfException>(() => Container.Open(new MemoryStream(img)).Entries());
        Assert.Equal(PcfError.UnknownHashAlgo, ex.Kind);
    }

    [Fact]
    public void Empty_partition_has_empty_data_and_verifies()
    {
        var c = Container.Create(new MemoryStream());
        c.AddPartition(1, TestSupport.Uid(1), "empty", Array.Empty<byte>(), 0, HashAlgo.Sha256);
        c.Verify();
        Assert.Empty(c.ReadPartitionData(c.Entries()[0]));
    }

    [Fact]
    public void Compaction_across_multiple_blocks()
    {
        var c = Container.CreateWith(new MemoryStream(), 2, HashAlgo.Sha256);
        for (int i = 1; i <= 6; i++)
        {
            c.AddPartition(0x10, TestSupport.Uid((byte)i), "p", new byte[] { (byte)i }, 5, HashAlgo.Sha256);
        }
        var reopened = Container.Open(new MemoryStream(c.CompactedImage()));
        reopened.Verify();
        Assert.Equal(6, reopened.Entries().Count);
    }

    [Fact]
    public void CompactInto_writes_same_bytes_as_compacted_image()
    {
        var c = Container.CreateWith(new MemoryStream(), 8, HashAlgo.Sha256);
        c.AddPartition(0x10, TestSupport.Uid(1), "a", new byte[] { 1, 2, 3 }, 10, HashAlgo.Sha256);

        byte[] image = c.CompactedImage();
        using var ms = new MemoryStream();
        c.CompactInto(ms);
        Assert.Equal(image, ms.ToArray());
    }

    [Fact]
    public void Storage_property_exposes_backing_stream()
    {
        var stream = new MemoryStream();
        var c = Container.Create(stream);
        Assert.Same(stream, c.Storage);
    }

    private static string Hex(byte[] data, int n)
    {
        var sb = new StringBuilder(n * 2);
        for (int i = 0; i < n; i++)
        {
            sb.Append(data[i].ToString("x2"));
        }
        return sb.ToString();
    }
}
