using System;
using System.Collections.Generic;
using Pcf;

namespace Pcf.Sig;

/// <summary>One Signed Entry inside a Manifest (spec Section 7.2).</summary>
public sealed class SignedEntry
{
    public byte[] Uid { get; set; } = new byte[Pcf.Constants.UidSize];
    public uint PartitionType { get; set; }
    public byte[] Label { get; set; } = new byte[Pcf.Constants.LabelSize];
    public ulong UsedBytes { get; set; }
    public HashAlgo DataHashAlgo { get; set; }
    public byte[] DataHash { get; set; } = new byte[Pcf.Constants.HashFieldSize];

    /// <summary>Serialise to the on-disk 218-byte layout.</summary>
    public byte[] ToBytes()
    {
        var b = new byte[Constants.SignedEntrySize];
        Buffer.BlockCopy(Uid, 0, b, 0, Pcf.Constants.UidSize);
        LittleEndian.WriteU32(b, 16, PartitionType);
        Buffer.BlockCopy(Label, 0, b, 20, Pcf.Constants.LabelSize);
        LittleEndian.WriteU64(b, 52, UsedBytes);
        b[60] = DataHashAlgo.Id();
        // b[61] reserved = 0
        Buffer.BlockCopy(DataHash, 0, b, 62, Pcf.Constants.HashFieldSize);
        // b[126..218] reserved = 0
        return b;
    }

    /// <summary>
    /// Parse from the on-disk 218-byte layout. Validates reserved spans, the
    /// cryptographic-hash constraint (Section 9), and the PCF reserved-value
    /// guards (Section 11, V7).
    /// </summary>
    public static SignedEntry FromBytes(byte[] b)
    {
        if (b == null || b.Length != Constants.SignedEntrySize)
        {
            throw PcfSigException.MalformedSignaturePartition();
        }
        if (b[61] != 0)
        {
            throw PcfSigException.NonZeroEntryReserved();
        }
        for (int i = 126; i < 218; i++)
        {
            if (b[i] != 0)
            {
                throw PcfSigException.NonZeroEntryReserved();
            }
        }
        var uid = new byte[Pcf.Constants.UidSize];
        Buffer.BlockCopy(b, 0, uid, 0, Pcf.Constants.UidSize);
        if (IsAllZero(uid))
        {
            throw PcfSigException.EntryNilUid();
        }
        uint partitionType = LittleEndian.ReadU32(b, 16);
        if (partitionType == Pcf.Constants.TypeReserved)
        {
            throw PcfSigException.EntryReservedType();
        }
        var label = new byte[Pcf.Constants.LabelSize];
        Buffer.BlockCopy(b, 20, label, 0, Pcf.Constants.LabelSize);
        ulong usedBytes = LittleEndian.ReadU64(b, 52);
        var dataHashAlgo = HashAlgoExtensions.FromId(b[60]);
        if (!Manifest.IsCryptoHash(dataHashAlgo))
        {
            throw PcfSigException.NonCryptoEntryHash(b[60]);
        }
        var dataHash = new byte[Pcf.Constants.HashFieldSize];
        Buffer.BlockCopy(b, 62, dataHash, 0, Pcf.Constants.HashFieldSize);
        return new SignedEntry
        {
            Uid = uid,
            PartitionType = partitionType,
            Label = label,
            UsedBytes = usedBytes,
            DataHashAlgo = dataHashAlgo,
            DataHash = dataHash,
        };
    }

    private static bool IsAllZero(byte[] b)
    {
        for (int i = 0; i < b.Length; i++) if (b[i] != 0) return false;
        return true;
    }
}

/// <summary>A parsed Manifest (spec Section 7.1).</summary>
public sealed class Manifest
{
    public ushort VersionMajor { get; set; }
    public ushort VersionMinor { get; set; }
    public SigAlgo SigAlgo { get; set; }
    public HashAlgo ManifestHashAlgo { get; set; }
    public ushort Flags { get; set; }
    public byte[] SignerKeyFingerprint { get; set; } = new byte[Constants.FingerprintSize];
    public long SignedAtUnixSeconds { get; set; }
    public List<SignedEntry> SignedEntries { get; set; } = new();

    /// <summary>Construct a Manifest from its component parts.</summary>
    public static Manifest Make(
        SigAlgo sigAlgo,
        HashAlgo manifestHashAlgo,
        byte[] signerKeyFingerprint,
        long signedAtUnixSeconds,
        List<SignedEntry> signedEntries)
    {
        return new Manifest
        {
            VersionMajor = Constants.ProfileVersionMajor,
            VersionMinor = Constants.ProfileVersionMinor,
            SigAlgo = sigAlgo,
            ManifestHashAlgo = manifestHashAlgo,
            Flags = 0,
            SignerKeyFingerprint = (byte[])signerKeyFingerprint.Clone(),
            SignedAtUnixSeconds = signedAtUnixSeconds,
            SignedEntries = signedEntries,
        };
    }

    /// <summary>Serialised length in bytes.</summary>
    public int ByteLen() =>
        Constants.ManifestPrefixSize + Constants.SignedEntrySize * SignedEntries.Count;

    /// <summary>Serialise to the on-disk byte layout (spec Section 7.1).</summary>
    public byte[] ToBytes()
    {
        var out_ = new byte[ByteLen()];
        Buffer.BlockCopy(Constants.SigMagic, 0, out_, 0, 8);
        LittleEndian.WriteU16(out_, 8, VersionMajor);
        LittleEndian.WriteU16(out_, 10, VersionMinor);
        out_[12] = SigAlgo.Id();
        out_[13] = ManifestHashAlgo.Id();
        LittleEndian.WriteU16(out_, 14, Flags);
        Buffer.BlockCopy(SignerKeyFingerprint, 0, out_, 16, Constants.FingerprintSize);
        LittleEndian.WriteI64(out_, 48, SignedAtUnixSeconds);
        LittleEndian.WriteU32(out_, 56, (uint)SignedEntries.Count);
        for (int i = 0; i < SignedEntries.Count; i++)
        {
            Buffer.BlockCopy(
                SignedEntries[i].ToBytes(), 0,
                out_, Constants.ManifestPrefixSize + i * Constants.SignedEntrySize,
                Constants.SignedEntrySize);
        }
        return out_;
    }

    /// <summary>
    /// Parse from the on-disk byte layout. Validates magic, major version,
    /// algorithm registry membership, hash-algo binding, cryptographic hash
    /// requirement, reserved flags, non-empty signed_count, and per-entry
    /// reserved spans.
    /// </summary>
    public static Manifest FromBytes(byte[] b)
    {
        if (b == null || b.Length < Constants.ManifestPrefixSize)
        {
            throw PcfSigException.MalformedSignaturePartition();
        }
        for (int i = 0; i < 8; i++)
        {
            if (b[i] != Constants.SigMagic[i])
            {
                throw PcfSigException.BadManifestMagic();
            }
        }
        ushort versionMajor = LittleEndian.ReadU16(b, 8);
        ushort versionMinor = LittleEndian.ReadU16(b, 10);
        if (versionMajor != Constants.ProfileVersionMajor)
        {
            throw PcfSigException.UnsupportedMajor(versionMajor);
        }
        var sigAlgo = SigAlgoExtensions.FromId(b[12]);
        byte manifestHashId = b[13];
        var manifestHashAlgo = HashAlgoExtensions.FromId(manifestHashId);
        if (!IsCryptoHash(manifestHashAlgo))
        {
            throw PcfSigException.NonCryptoManifestHash(manifestHashId);
        }
        var required = sigAlgo.RequiredManifestHash();
        if (required.HasValue && required.Value != manifestHashAlgo)
        {
            throw PcfSigException.HashAlgoBindingMismatch();
        }
        ushort flags = LittleEndian.ReadU16(b, 14);
        if (flags != 0)
        {
            throw PcfSigException.NonZeroFlags();
        }
        var signerKeyFingerprint = new byte[Constants.FingerprintSize];
        Buffer.BlockCopy(b, 16, signerKeyFingerprint, 0, Constants.FingerprintSize);
        long signedAtUnixSeconds = LittleEndian.ReadI64(b, 48);
        uint signedCount = LittleEndian.ReadU32(b, 56);
        if (signedCount == 0)
        {
            throw PcfSigException.EmptyManifest();
        }
        int expected = Constants.ManifestPrefixSize + Constants.SignedEntrySize * (int)signedCount;
        if (b.Length < expected)
        {
            throw PcfSigException.MalformedSignaturePartition();
        }
        var entries = new List<SignedEntry>((int)signedCount);
        var seen = new HashSet<string>();
        for (uint i = 0; i < signedCount; i++)
        {
            int off = Constants.ManifestPrefixSize + (int)i * Constants.SignedEntrySize;
            var slice = new byte[Constants.SignedEntrySize];
            Buffer.BlockCopy(b, off, slice, 0, Constants.SignedEntrySize);
            var e = SignedEntry.FromBytes(slice);
            string key = BitConverter.ToString(e.Uid);
            if (!seen.Add(key))
            {
                throw PcfSigException.DuplicateSignedUid();
            }
            entries.Add(e);
        }
        return new Manifest
        {
            VersionMajor = versionMajor,
            VersionMinor = versionMinor,
            SigAlgo = sigAlgo,
            ManifestHashAlgo = manifestHashAlgo,
            Flags = flags,
            SignerKeyFingerprint = signerKeyFingerprint,
            SignedAtUnixSeconds = signedAtUnixSeconds,
            SignedEntries = entries,
        };
    }

    /// <summary>Whether a PCF hash algorithm id is cryptographic (spec Section 9).</summary>
    public static bool IsCryptoHash(HashAlgo a) =>
        a == HashAlgo.Sha256 || a == HashAlgo.Sha512 || a == HashAlgo.Blake3;
}

