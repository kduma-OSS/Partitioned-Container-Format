using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Pcf;

namespace Pcf.Sig;

/// <summary>One metadata TLV entry (spec Section 6.4).</summary>
public sealed class KeyMetadata
{
    /// <summary>16-bit tag from the metadata registry (spec Appendix B).</summary>
    public ushort Tag { get; }

    /// <summary>Value bytes; interpretation depends on <see cref="Tag"/>.</summary>
    public byte[] Value { get; }

    /// <summary>Construct a metadata entry from a tag and a value.</summary>
    public KeyMetadata(ushort tag, byte[] value)
    {
        Tag = tag;
        Value = value ?? throw new ArgumentNullException(nameof(value));
    }
}

/// <summary>A parsed Key Record (spec Section 6).</summary>
public sealed class KeyRecord
{
    /// <summary><c>record_version_major</c>. v1.0 implementations require 1.</summary>
    public ushort VersionMajor { get; set; }

    /// <summary><c>record_version_minor</c>.</summary>
    public ushort VersionMinor { get; set; }

    /// <summary><c>key_format_id</c> (spec Section 6.2).</summary>
    public KeyFormat KeyFormat { get; set; }

    /// <summary>32-byte SHA-256 fingerprint of <see cref="KeyData"/> (spec Section 6.3).</summary>
    public byte[] Fingerprint { get; set; } = new byte[Constants.FingerprintSize];

    /// <summary>Raw key material in the encoding named by <see cref="KeyFormat"/>.</summary>
    public byte[] KeyData { get; set; } = new byte[0];

    /// <summary>Optional metadata entries (spec Section 6.4).</summary>
    public List<KeyMetadata> Metadata { get; set; } = new();

    /// <summary>Build a Key Record from raw key bytes; fills version + fingerprint.</summary>
    public static KeyRecord Make(KeyFormat keyFormat, byte[] keyData, List<KeyMetadata> metadata = null)
    {
        if (keyData == null || keyData.Length == 0)
        {
            throw PcfSigException.EmptyKeyData();
        }
        return new KeyRecord
        {
            VersionMajor = Constants.ProfileVersionMajor,
            VersionMinor = Constants.ProfileVersionMinor,
            KeyFormat = keyFormat,
            Fingerprint = ComputeFingerprint(keyData),
            KeyData = (byte[])keyData.Clone(),
            Metadata = metadata ?? new List<KeyMetadata>(),
        };
    }

    /// <summary>Serialise to the on-disk byte layout (spec Section 6.1).</summary>
    public byte[] ToBytes()
    {
        int metaLen = 0;
        foreach (var m in Metadata) metaLen += 6 + m.Value.Length;
        var out_ = new byte[Constants.KeyPrefixSize + KeyData.Length + metaLen];

        Buffer.BlockCopy(Constants.KeyMagic, 0, out_, 0, 8);
        LittleEndian.WriteU16(out_, 8, VersionMajor);
        LittleEndian.WriteU16(out_, 10, VersionMinor);
        out_[12] = KeyFormat.Id();
        // bytes 13..16 reserved = 0
        Buffer.BlockCopy(Fingerprint, 0, out_, 16, Constants.FingerprintSize);
        LittleEndian.WriteU32(out_, 48, (uint)KeyData.Length);
        Buffer.BlockCopy(KeyData, 0, out_, Constants.KeyPrefixSize, KeyData.Length);

        int cur = Constants.KeyPrefixSize + KeyData.Length;
        foreach (var m in Metadata)
        {
            LittleEndian.WriteU16(out_, cur, m.Tag);
            LittleEndian.WriteU32(out_, cur + 2, (uint)m.Value.Length);
            Buffer.BlockCopy(m.Value, 0, out_, cur + 6, m.Value.Length);
            cur += 6 + m.Value.Length;
        }
        return out_;
    }

    /// <summary>Parse from the on-disk byte layout (spec Section 6.1).</summary>
    public static KeyRecord FromBytes(byte[] b)
    {
        if (b.Length < Constants.KeyPrefixSize)
        {
            throw PcfSigException.MalformedSignaturePartition();
        }
        for (int i = 0; i < 8; i++)
        {
            if (b[i] != Constants.KeyMagic[i])
            {
                throw PcfSigException.BadKeyMagic();
            }
        }
        ushort versionMajor = LittleEndian.ReadU16(b, 8);
        ushort versionMinor = LittleEndian.ReadU16(b, 10);
        if (versionMajor != Constants.ProfileVersionMajor)
        {
            throw PcfSigException.UnsupportedMajor(versionMajor);
        }
        var keyFormat = KeyFormatExtensions.FromId(b[12]);
        if (b[13] != 0 || b[14] != 0 || b[15] != 0)
        {
            throw PcfSigException.NonZeroKeyReserved();
        }
        var fingerprintStored = new byte[Constants.FingerprintSize];
        Buffer.BlockCopy(b, 16, fingerprintStored, 0, Constants.FingerprintSize);
        uint keyDataLength = LittleEndian.ReadU32(b, 48);
        if (keyDataLength == 0)
        {
            throw PcfSigException.EmptyKeyData();
        }
        int keyEnd = Constants.KeyPrefixSize + (int)keyDataLength;
        if (b.Length < keyEnd)
        {
            throw PcfSigException.MalformedSignaturePartition();
        }
        var keyData = new byte[keyDataLength];
        Buffer.BlockCopy(b, Constants.KeyPrefixSize, keyData, 0, (int)keyDataLength);

        var recomputed = ComputeFingerprint(keyData);
        for (int i = 0; i < Constants.FingerprintSize; i++)
        {
            if (recomputed[i] != fingerprintStored[i])
            {
                throw PcfSigException.FingerprintMismatch();
            }
        }

        var metadata = new List<KeyMetadata>();
        int cur = keyEnd;
        while (cur < b.Length)
        {
            if (b.Length - cur < 6)
            {
                throw PcfSigException.MalformedSignaturePartition();
            }
            ushort tag = LittleEndian.ReadU16(b, cur);
            uint len = LittleEndian.ReadU32(b, cur + 2);
            int valueStart = cur + 6;
            int valueEnd = valueStart + (int)len;
            if (valueEnd > b.Length)
            {
                throw PcfSigException.MalformedSignaturePartition();
            }
            var value = new byte[len];
            Buffer.BlockCopy(b, valueStart, value, 0, (int)len);
            metadata.Add(new KeyMetadata(tag, value));
            cur = valueEnd;
        }

        return new KeyRecord
        {
            VersionMajor = versionMajor,
            VersionMinor = versionMinor,
            KeyFormat = keyFormat,
            Fingerprint = fingerprintStored,
            KeyData = keyData,
            Metadata = metadata,
        };
    }

    /// <summary>Compute the SHA-256 fingerprint of a key's key_data (spec Section 6.3).</summary>
    public static byte[] ComputeFingerprint(byte[] keyData)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(keyData);
    }
}
