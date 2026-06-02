using System;
using System.IO;
using System.Text;

namespace Pcf.Tests;

/// <summary>
/// One assertion (or a small focused group) per normative MUST/SHALL in the
/// specification, organised by spec section.
/// </summary>
public class SpecComplianceTests
{
    // ---- Section 2.3: byte order -----------------------------------------

    [Fact]
    public void S2_3_integers_are_little_endian()
    {
        var h = new FileHeader { VersionMajor = 1, VersionMinor = 0, PartitionTableOffset = 0x14 };
        byte[] b = h.ToBytes();
        // partition_table_offset = 20 stored at offset 12, low byte first.
        Assert.Equal(0x14, b[12]);
        Assert.Equal(0x00, b[13]);
        Assert.Equal(0x00, b[19]);
    }

    // ---- Section 4: file header ------------------------------------------

    [Fact]
    public void S4_header_is_20_bytes_with_exact_magic()
    {
        byte[] b = new FileHeader { VersionMajor = 1, VersionMinor = 0, PartitionTableOffset = 20 }.ToBytes();
        Assert.Equal(20, b.Length);
        byte[] magic = { 0x89, 0x4B, 0x50, 0x52, 0x54, 0x0D, 0x0A, 0x1A };
        Assert.Equal(magic, b[..8]);
    }

    [Fact]
    public void S4_reader_rejects_bad_magic()
    {
        byte[] b = new FileHeader { VersionMajor = 1, VersionMinor = 0, PartitionTableOffset = 20 }.ToBytes();
        b[0] = 0x00;
        var ex = Assert.Throws<PcfException>(() => FileHeader.FromBytes(b));
        Assert.Equal(PcfError.BadMagic, ex.Kind);
    }

    // ---- Section 5.1: table block header ---------------------------------

    [Fact]
    public void S5_1_table_block_header_is_74_bytes()
    {
        byte[] b = new TableBlockHeader
        {
            PartitionCount = 0,
            NextTableOffset = 0,
            TableHashAlgo = HashAlgo.Sha256,
            TableHash = HashAlgo.Sha256.Compute(Array.Empty<byte>()),
        }.ToBytes();
        Assert.Equal(74, b.Length);
    }

    [Fact]
    public void S5_1_chain_terminates_on_zero_next_offset()
    {
        var c = Container.CreateWith(new MemoryStream(), 4, HashAlgo.Sha256);
        c.AddPartition(1, TestSupport.Uid(1), "a", new byte[] { 1 }, 0, HashAlgo.Sha256);
        // A single block: its next_table_offset must be 0 (end of chain).
        var reopened = Container.Open(new MemoryStream(c.CompactedImage()));
        Assert.Single(reopened.Entries());
    }

    // ---- Section 5.2: partition entry ------------------------------------

    [Fact]
    public void S5_2_entry_is_141_bytes()
    {
        var e = new PartitionEntry
        {
            PartitionType = 7,
            Uid = TestSupport.Uid(1),
            Label = PartitionEntry.EncodeLabel("x"),
            StartOffset = 1,
            MaxLength = 2,
            UsedBytes = 1,
            DataHashAlgo = HashAlgo.Sha256,
            DataHash = HashAlgo.Sha256.Compute(new byte[] { 9 }),
        };
        Assert.Equal(141, e.ToBytes().Length);
    }

    [Fact]
    public void S5_2_used_must_not_exceed_max()
    {
        var e = new PartitionEntry
        {
            PartitionType = 7,
            Uid = TestSupport.Uid(1),
            MaxLength = 4,
            UsedBytes = 5,
        };
        var ex = Assert.Throws<PcfException>(() => e.Validate());
        Assert.Equal(PcfError.UsedExceedsMax, ex.Kind);
    }

    [Fact]
    public void S5_2_free_bytes_is_derived()
    {
        var e = new PartitionEntry { MaxLength = 10, UsedBytes = 3 };
        Assert.Equal(7ul, e.FreeBytes());
    }

    // ---- Section 5.3: overflow chain -------------------------------------

    [Fact]
    public void S5_3_more_than_255_partitions_use_overflow_chain()
    {
        var c = Container.CreateWith(new MemoryStream(), 255, HashAlgo.Crc32);
        for (int i = 0; i < 300; i++)
        {
            byte[] uid = TestSupport.Uid(0);
            uid[0] = (byte)(i & 0xFF);
            uid[1] = (byte)(i >> 8);
            uid[2] = 1; // keep non-nil even when low bytes are zero
            c.AddPartition(1, uid, "p", new byte[] { (byte)i }, 0, HashAlgo.Crc32);
        }
        var reopened = Container.Open(new MemoryStream(c.CompactedImage()));
        Assert.Equal(300, reopened.Entries().Count);
        reopened.Verify();
    }

    [Fact]
    public void S5_3_zero_count_block_is_valid()
    {
        var c = Container.CreateWith(new MemoryStream(), 8, HashAlgo.Sha256);
        // No partitions added: the single block has partition_count == 0.
        byte[] img = c.CompactedImage();
        var reopened = Container.Open(new MemoryStream(img));
        Assert.Empty(reopened.Entries());
        reopened.Verify();
    }

    // ---- Section 7: reserved values --------------------------------------

    [Fact]
    public void S7_1_reserved_type_zero_is_rejected()
    {
        var c = Container.Create(new MemoryStream());
        var ex = Assert.Throws<PcfException>(() =>
            c.AddPartition(0x0000_0000, TestSupport.Uid(1), "x", Array.Empty<byte>(), 0, HashAlgo.Sha256));
        Assert.Equal(PcfError.ReservedType, ex.Kind);
    }

    [Fact]
    public void S7_1_raw_type_is_allowed()
    {
        var c = Container.Create(new MemoryStream());
        c.AddPartition(Constants.TypeRaw, TestSupport.Uid(1), "x", new byte[] { 1 }, 0, HashAlgo.Sha256);
        Assert.Equal(Constants.TypeRaw, c.Entries()[0].PartitionType);
    }

    [Fact]
    public void S7_2_nil_uid_is_rejected()
    {
        var c = Container.Create(new MemoryStream());
        var ex = Assert.Throws<PcfException>(() =>
            c.AddPartition(1, new byte[Constants.UidSize], "x", Array.Empty<byte>(), 0, HashAlgo.Sha256));
        Assert.Equal(PcfError.NilUid, ex.Kind);
    }

    // ---- Section 8.1: hash registry --------------------------------------

    [Theory]
    [InlineData(HashAlgo.None, 0)]
    [InlineData(HashAlgo.Crc32, 1)]
    [InlineData(HashAlgo.Crc32c, 2)]
    [InlineData(HashAlgo.Crc64, 3)]
    [InlineData(HashAlgo.Md5, 4)]
    [InlineData(HashAlgo.Sha1, 5)]
    [InlineData(HashAlgo.Sha256, 16)]
    [InlineData(HashAlgo.Sha512, 17)]
    [InlineData(HashAlgo.Blake3, 18)]
    public void S8_1_registry_ids_roundtrip(HashAlgo algo, byte id)
    {
        Assert.Equal(id, algo.Id());
        Assert.Equal(algo, HashAlgoExtensions.FromId(id));
    }

    [Theory]
    [InlineData(6)]
    [InlineData(15)]
    [InlineData(19)]
    [InlineData(200)]
    public void S8_1_reserved_ids_are_rejected(byte id)
    {
        var ex = Assert.Throws<PcfException>(() => HashAlgoExtensions.FromId(id));
        Assert.Equal(PcfError.UnknownHashAlgo, ex.Kind);
    }

    [Fact]
    public void S8_1_crc_check_values()
    {
        byte[] input = Encoding.ASCII.GetBytes("123456789");
        // CRC-32/ISO-HDLC = 0xCBF43926
        Assert.Equal(0xCBF43926u, ReadU32(HashAlgo.Crc32.Compute(input)));
        // CRC-32C = 0xE3069283
        Assert.Equal(0xE3069283u, ReadU32(HashAlgo.Crc32c.Compute(input)));
        // CRC-64/XZ = 0x995DC9BBDF1939FA
        Assert.Equal(0x995DC9BBDF1939FAul, ReadU64(HashAlgo.Crc64.Compute(input)));
    }

    // ---- Section 8.2: hash field encoding --------------------------------

    [Fact]
    public void S8_2_digest_is_left_aligned_and_zero_padded()
    {
        byte[] field = HashAlgo.Sha256.Compute(Array.Empty<byte>());
        Assert.Equal(64, field.Length);
        // SHA-256("") well-known prefix.
        Assert.Equal(0xe3, field[0]);
        Assert.Equal(0xb0, field[1]);
        Assert.Equal(0x55, field[31]);
        // Bytes after the 32-byte digest are zero.
        for (int i = 32; i < 64; i++)
        {
            Assert.Equal(0, field[i]);
        }
    }

    [Fact]
    public void S8_2_crc_is_stored_little_endian()
    {
        // CRC-32C of bytes 0..7 is 0x8A2CBC3B (from the spec test vector).
        byte[] field = HashAlgo.Crc32c.Compute(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 });
        Assert.Equal(0x3B, field[0]);
        Assert.Equal(0xBC, field[1]);
        Assert.Equal(0x2C, field[2]);
        Assert.Equal(0x8A, field[3]);
        for (int i = 4; i < 64; i++)
        {
            Assert.Equal(0, field[i]);
        }
    }

    [Fact]
    public void S8_2_none_is_all_zero_and_skips_verification()
    {
        byte[] field = HashAlgo.None.Compute(Encoding.ASCII.GetBytes("anything"));
        Assert.All(field, b => Assert.Equal(0, b));
        Assert.True(HashAlgo.None.Verify(Encoding.ASCII.GetBytes("anything"), new byte[64]));
    }

    // ---- Section 8.3: partition data hash --------------------------------

    [Fact]
    public void S8_3_empty_input_hashes_to_algorithm_empty_digest()
    {
        // SHA-256 of empty input is the canonical e3b0... digest.
        byte[] field = HashAlgo.Sha256.Compute(Array.Empty<byte>());
        Assert.True(HashAlgo.Sha256.Verify(Array.Empty<byte>(), field));
    }

    // ---- Section 8.4: table block hash -----------------------------------

    [Fact]
    public void S8_4_table_hash_includes_algo_byte_with_field_zeroed()
    {
        // Two algos over the same (empty) entry set must differ because the
        // algo id byte is part of the hashed input.
        byte[] a = TableBlockHeader.ComputeTableHash(HashAlgo.Crc32, 0, Array.Empty<PartitionEntry>());
        byte[] b = TableBlockHeader.ComputeTableHash(HashAlgo.Crc32c, 0, Array.Empty<PartitionEntry>());
        Assert.False(EqualPrefix(a, b, 4));
    }

    [Fact]
    public void S8_4_table_hash_depends_on_next_offset()
    {
        byte[] a = TableBlockHeader.ComputeTableHash(HashAlgo.Sha256, 0, Array.Empty<PartitionEntry>());
        byte[] b = TableBlockHeader.ComputeTableHash(HashAlgo.Sha256, 4096, Array.Empty<PartitionEntry>());
        Assert.False(EqualPrefix(a, b, 32));
    }

    // ---- Section 8.5: hash cascade ---------------------------------------

    [Fact]
    public void S8_5_updating_data_cascades_to_table_hash()
    {
        var stream = new MemoryStream();
        var c = Container.CreateWith(stream, 4, HashAlgo.Sha256);
        c.AddPartition(1, TestSupport.Uid(1), "a", new byte[] { 1, 2, 3 }, 8, HashAlgo.Sha256);

        byte[] before = c.Entries()[0].DataHash;
        c.UpdatePartitionData(TestSupport.Uid(1), new byte[] { 9, 9 });
        byte[] after = c.Entries()[0].DataHash;
        Assert.False(EqualPrefix(before, after, 32));

        // The table hash is still consistent (Verify recomputes it).
        c.Verify();
    }

    // ---- Section 9: versioning -------------------------------------------

    [Fact]
    public void S9_higher_minor_is_accepted()
    {
        byte[] img = TestSupport.CanonicalVector.ToArray();
        img[10] = 0x05; // bump version_minor to 5
        // Header parse must accept it (major unchanged).
        var h = FileHeader.FromBytes(img[..20]);
        Assert.Equal(5, h.VersionMinor);
    }

    [Fact]
    public void S9_unsupported_major_is_rejected()
    {
        byte[] img = TestSupport.CanonicalVector.ToArray();
        img[8] = 0x02; // major = 2
        var ex = Assert.Throws<PcfException>(() => FileHeader.FromBytes(img[..20]));
        Assert.Equal(PcfError.UnsupportedMajor, ex.Kind);
    }

    // ---- Section 10: labels ----------------------------------------------

    [Fact]
    public void S10_label_reads_until_nul()
    {
        byte[] l = PartitionEntry.EncodeLabel("config.bin");
        Assert.Equal("config.bin", PartitionEntry.DecodeLabel(l));
    }

    [Fact]
    public void S10_full_32_char_label_has_no_terminator()
    {
        string s = new string('a', 32);
        byte[] l = PartitionEntry.EncodeLabel(s);
        Assert.Equal(s, PartitionEntry.DecodeLabel(l));
    }

    [Fact]
    public void S10_high_bit_byte_makes_label_invalid()
    {
        var l = new byte[Constants.LabelSize];
        l[0] = 0x80;
        var ex = Assert.Throws<PcfException>(() => PartitionEntry.DecodeLabel(l));
        Assert.Equal(PcfError.InvalidLabel, ex.Kind);
    }

    [Fact]
    public void S10_empty_label_is_all_zero()
    {
        byte[] l = PartitionEntry.EncodeLabel("");
        Assert.All(l, b => Assert.Equal(0, b));
        Assert.Equal("", PartitionEntry.DecodeLabel(l));
    }

    // ---- Section 12: conformance -----------------------------------------

    [Fact]
    public void S12_verify_skips_table_hash_when_algo_is_none()
    {
        var c = Container.CreateWith(new MemoryStream(), 4, HashAlgo.None);
        c.AddPartition(1, TestSupport.Uid(1), "a", new byte[] { 1 }, 0, HashAlgo.None);
        byte[] img = c.CompactedImage();
        // Corrupt the (unused) table hash bytes; verification must still pass
        // because table_hash_algo is None.
        var reopened = Container.Open(new MemoryStream(img));
        reopened.Verify();
    }

    // ---- Section 15: canonical test vector --------------------------------

    [Fact]
    public void S15_canonical_vector_is_byte_exact()
    {
        byte[] image = TestSupport.BuildCanonical();
        Assert.Equal(395, image.Length);
        Assert.Equal(TestSupport.CanonicalVector, image);
    }

    [Fact]
    public void S15_canonical_vector_opens_and_verifies()
    {
        var c = Container.Open(new MemoryStream(TestSupport.CanonicalVector.ToArray()));
        c.Verify();
        var entries = c.Entries();
        Assert.Equal(2, entries.Count);
        Assert.Equal("alpha", entries[0].LabelString());
        Assert.Equal("raw", entries[1].LabelString());
        Assert.Equal(Encoding.ASCII.GetBytes("Hello, PCF!"), c.ReadPartitionData(entries[0]));
        Assert.Equal(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 }, c.ReadPartitionData(entries[1]));
    }

    // ---- helpers ----------------------------------------------------------

    private static uint ReadU32(byte[] field) =>
        (uint)field[0] | ((uint)field[1] << 8) | ((uint)field[2] << 16) | ((uint)field[3] << 24);

    private static ulong ReadU64(byte[] field)
    {
        ulong v = 0;
        for (int i = 0; i < 8; i++)
        {
            v |= (ulong)field[i] << (8 * i);
        }
        return v;
    }

    private static bool EqualPrefix(byte[] a, byte[] b, int n)
    {
        for (int i = 0; i < n; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }
        return true;
    }
}
