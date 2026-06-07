using System.Collections.Generic;
using Pcf;

namespace Pcf.Sig;

/// <summary>High-level signing API (spec Section 10).</summary>
public static class SignPartitions
{
    /// <summary>
    /// Look up an existing PCFSIG_KEY partition by fingerprint, or add a fresh
    /// one carrying <paramref name="signer"/>'s public material. Returns the
    /// PCF uid of the chosen partition.
    /// </summary>
    public static byte[] EnsureKeyPartition(
        Container container,
        SigningMaterial signer,
        byte[] keyUidSeed,
        string label)
    {
        var fp = signer.Fingerprint();
        foreach (var e in container.Entries())
        {
            if (e.PartitionType == Constants.TypePcfsigKey)
            {
                try
                {
                    var rec = KeyRecord.FromBytes(container.ReadPartitionData(e));
                    if (BytesEqual(rec.Fingerprint, fp))
                    {
                        return e.Uid;
                    }
                }
                catch (PcfSigException)
                {
                    // skip malformed key records
                }
            }
        }
        container.AddPartition(
            Constants.TypePcfsigKey,
            keyUidSeed,
            label,
            signer.ToKeyRecordBytes(),
            0,
            HashAlgo.Sha256);
        return keyUidSeed;
    }

    /// <summary>Build a SignedEntry mirroring a PCF PartitionEntry.</summary>
    public static SignedEntry SignedEntryFromPartition(PartitionEntry e)
    {
        if (!Manifest.IsCryptoHash(e.DataHashAlgo))
        {
            throw PcfSigException.NonCryptoTargetHash();
        }
        var entry = new SignedEntry
        {
            Uid = (byte[])e.Uid.Clone(),
            PartitionType = e.PartitionType,
            Label = (byte[])e.Label.Clone(),
            UsedBytes = e.UsedBytes,
            DataHashAlgo = e.DataHashAlgo,
            DataHash = (byte[])e.DataHash.Clone(),
        };
        return entry;
    }

    /// <summary>
    /// Sign a chosen set of partitions and write the resulting PCFSIG_SIG
    /// partition into <paramref name="container"/>. Returns the sig partition uid.
    /// </summary>
    public static byte[] Run(
        Container container,
        SigningMaterial signer,
        IReadOnlyList<byte[]> targetUids,
        byte[] sigPartitionUid,
        byte[] keyPartitionUid,
        long signedAtUnixSeconds,
        string sigLabel,
        string keyLabel)
    {
        if (targetUids == null || targetUids.Count == 0)
        {
            throw PcfSigException.EmptyManifest();
        }
        foreach (var u in targetUids)
        {
            if (BytesEqual(u, sigPartitionUid))
            {
                throw PcfSigException.SelfSignedEntry();
            }
        }
        var seen = new HashSet<string>();
        foreach (var u in targetUids)
        {
            var k = System.BitConverter.ToString(u);
            if (!seen.Add(k))
            {
                throw PcfSigException.DuplicateSignedUid();
            }
        }

        EnsureKeyPartition(container, signer, keyPartitionUid, keyLabel);

        var entries = container.Entries();
        var signedEntries = new List<SignedEntry>(targetUids.Count);
        foreach (var uid in targetUids)
        {
            PartitionEntry found = null;
            foreach (var e in entries)
            {
                if (BytesEqual(e.Uid, uid))
                {
                    found = e;
                    break;
                }
            }
            if (found == null)
            {
                throw PcfSigException.TargetPartitionMissing();
            }
            signedEntries.Add(SignedEntryFromPartition(found));
        }

        var manifestHash = signer.SigAlgo.RequiredManifestHash();
        if (!manifestHash.HasValue)
        {
            throw new System.InvalidOperationException(
                "signer algorithm has no fixed manifest hash binding");
        }
        var manifest = Manifest.Make(
            signer.SigAlgo,
            manifestHash.Value,
            signer.Fingerprint(),
            signedAtUnixSeconds,
            signedEntries);
        var manifestBytes = manifest.ToBytes();
        var signature = signer.Sign(manifestBytes);
        var partition = new SignaturePartition
        {
            Manifest = manifest,
            ManifestBytes = manifestBytes,
            Signature = signature,
            Trailer = new byte[0],
        };
        container.AddPartition(
            Constants.TypePcfsigSig,
            sigPartitionUid,
            sigLabel,
            partition.ToBytes(),
            0,
            HashAlgo.Sha256);
        return sigPartitionUid;
    }

    private static bool BytesEqual(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
        return true;
    }
}
