using System.Collections.Generic;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Pcf;

namespace Pcf.Sig;

/// <summary>Verdict on one SignedEntry inside a Manifest (spec Section 11, V7).</summary>
public enum EntryVerdict
{
    /// <summary>Covered partition exists, all protected fields match, hash is cryptographic.</summary>
    Valid,
    /// <summary>No partition in the container has the SignedEntry's uid.</summary>
    MissingPartition,
    /// <summary>A protected field of the live partition does not match the manifest.</summary>
    ProtectedFieldMismatch,
    /// <summary>Recomputed digest of live partition data does not match the SignedEntry's data_hash.</summary>
    DataHashRecomputationMismatch,
    /// <summary>The covered partition's data_hash_algo_id is not cryptographic.</summary>
    WeakHash,
}

/// <summary>Verdict on a whole PCFSIG_SIG partition (spec Section 11, V8).</summary>
public enum ManifestVerdict
{
    /// <summary>Manifest parsed; signature cryptographically verified against the referenced key.</summary>
    Valid,
    /// <summary>Manifest parsed; signature did NOT verify against the referenced key.</summary>
    Invalid,
    /// <summary>Manifest parsed but cannot be verified (no matching key, or unsupported alg/format).</summary>
    Unverifiable,
}

/// <summary>Why a manifest could not be verified.</summary>
public enum UnverifiableReason
{
    /// <summary>No PCFSIG_KEY partition with the manifest's signer_key_fingerprint.</summary>
    NoMatchingKey,
    /// <summary>The signature algorithm id is not implemented by this build.</summary>
    UnsupportedSigAlgo,
    /// <summary>The key format id is not implemented by this build.</summary>
    UnsupportedKeyFormat,
    /// <summary>The matching key partition is malformed.</summary>
    MalformedKey,
    /// <summary>The signature byte length does not match the algorithm's natural size.</summary>
    SignatureLengthMismatch,
}

/// <summary>Per-entry report.</summary>
public sealed class EntryReport
{
    /// <summary>The SignedEntry's uid.</summary>
    public byte[] Uid { get; }

    /// <summary>Verdict for this entry.</summary>
    public EntryVerdict Verdict { get; set; }

    /// <summary>Construct a per-entry report.</summary>
    public EntryReport(byte[] uid, EntryVerdict verdict)
    {
        Uid = uid;
        Verdict = verdict;
    }
}

/// <summary>Report for one PCFSIG_SIG partition.</summary>
public sealed class SignatureReport
{
    /// <summary>PCF uid of the PCFSIG_SIG partition itself.</summary>
    public byte[] SigPartitionUid { get; set; }

    /// <summary><c>signer_key_fingerprint</c> copied from the manifest.</summary>
    public byte[] SignerKeyFingerprint { get; set; }

    /// <summary><c>signed_at_unix_seconds</c> copied from the manifest.</summary>
    public long SignedAtUnixSeconds { get; set; }

    /// <summary>Verdict on the manifest as a whole.</summary>
    public ManifestVerdict Verdict { get; set; }

    /// <summary>Detailed reason when <see cref="Verdict"/> is <see cref="ManifestVerdict.Unverifiable"/>.</summary>
    public UnverifiableReason? UnverifiableReason { get; set; }

    /// <summary>Optional id detail (e.g., unsupported algorithm id).</summary>
    public int? UnverifiableId { get; set; }

    /// <summary>Per-entry verdicts.</summary>
    public List<EntryReport> Entries { get; set; } = new();
}

/// <summary>Whether to independently re-hash each covered partition during verification.</summary>
public enum DataRecheck
{
    /// <summary>Trust the PCF data_hash field as captured by the SignedEntry.</summary>
    Skip,
    /// <summary>Recompute hash(partition bytes) and compare to the SignedEntry's data_hash.</summary>
    Recompute,
}

/// <summary>High-level verification API (spec Section 11).</summary>
public static class Verify
{
    /// <summary>Verify every PCFSIG_SIG partition and return one report each.</summary>
    public static List<SignatureReport> All(
        Container container,
        DataRecheck recheck = DataRecheck.Skip)
    {
        var entries = container.Entries();

        var keys = new List<(KeyRecord Record, byte[] Uid)>();
        foreach (var e in entries)
        {
            if (e.PartitionType == Constants.TypePcfsigKey)
            {
                try
                {
                    var rec = KeyRecord.FromBytes(container.ReadPartitionData(e));
                    keys.Add((rec, e.Uid));
                }
                catch (PcfSigException)
                {
                    // skip malformed
                }
            }
        }

        var reports = new List<SignatureReport>();
        foreach (var e in entries)
        {
            if (e.PartitionType != Constants.TypePcfsigSig) continue;
            var data = container.ReadPartitionData(e);
            reports.Add(VerifyOne(entries, keys, e, data));
        }

        if (recheck == DataRecheck.Recompute)
        {
            foreach (var r in reports)
            {
                foreach (var er in r.Entries)
                {
                    if (er.Verdict != EntryVerdict.Valid) continue;
                    PartitionEntry p = null;
                    foreach (var x in entries)
                    {
                        if (BytesEqual(x.Uid, er.Uid)) { p = x; break; }
                    }
                    if (p != null)
                    {
                        var bytes = container.ReadPartitionData(p);
                        var computed = p.DataHashAlgo.Compute(bytes);
                        if (!BytesEqual(computed, p.DataHash))
                        {
                            er.Verdict = EntryVerdict.DataHashRecomputationMismatch;
                        }
                    }
                }
            }
        }

        return reports;
    }

    /// <summary>Same as <see cref="All"/> with <see cref="DataRecheck.Recompute"/>.</summary>
    public static List<SignatureReport> AllWithRecheck(Container container) =>
        All(container, DataRecheck.Recompute);

    private static SignatureReport VerifyOne(
        List<PartitionEntry> entries,
        List<(KeyRecord Record, byte[] Uid)> keys,
        PartitionEntry sigEntry,
        byte[] data)
    {
        SignaturePartition parsed;
        try
        {
            parsed = SignaturePartition.FromBytes(data);
        }
        catch (PcfSigException)
        {
            return new SignatureReport
            {
                SigPartitionUid = sigEntry.Uid,
                SignerKeyFingerprint = new byte[Constants.FingerprintSize],
                SignedAtUnixSeconds = 0,
                Verdict = ManifestVerdict.Unverifiable,
                UnverifiableReason = Pcf.Sig.UnverifiableReason.MalformedKey,
            };
        }

        var report = new SignatureReport
        {
            SigPartitionUid = sigEntry.Uid,
            SignerKeyFingerprint = parsed.Manifest.SignerKeyFingerprint,
            SignedAtUnixSeconds = parsed.Manifest.SignedAtUnixSeconds,
            Verdict = ManifestVerdict.Valid,
        };

        foreach (var e in parsed.Manifest.SignedEntries)
        {
            if (BytesEqual(e.Uid, sigEntry.Uid))
            {
                report.Verdict = ManifestVerdict.Invalid;
                return report;
            }
        }

        if (!parsed.Manifest.SigAlgo.IsImplemented())
        {
            report.Verdict = ManifestVerdict.Unverifiable;
            report.UnverifiableReason = Pcf.Sig.UnverifiableReason.UnsupportedSigAlgo;
            report.UnverifiableId = (byte)parsed.Manifest.SigAlgo;
            return report;
        }

        (KeyRecord Record, byte[] Uid)? key = null;
        foreach (var k in keys)
        {
            if (BytesEqual(k.Record.Fingerprint, parsed.Manifest.SignerKeyFingerprint))
            {
                key = k;
                break;
            }
        }
        if (key == null)
        {
            report.Verdict = ManifestVerdict.Unverifiable;
            report.UnverifiableReason = Pcf.Sig.UnverifiableReason.NoMatchingKey;
            return report;
        }

        if (!key.Value.Record.KeyFormat.IsImplemented())
        {
            report.Verdict = ManifestVerdict.Unverifiable;
            report.UnverifiableReason = Pcf.Sig.UnverifiableReason.UnsupportedKeyFormat;
            report.UnverifiableId = (byte)key.Value.Record.KeyFormat;
            return report;
        }

        if (parsed.Manifest.SigAlgo == SigAlgo.Ed25519
            && key.Value.Record.KeyFormat == KeyFormat.Ed25519Raw)
        {
            if (parsed.Signature.Length != Constants.Ed25519SignatureLen)
            {
                report.Verdict = ManifestVerdict.Unverifiable;
                report.UnverifiableReason = Pcf.Sig.UnverifiableReason.SignatureLengthMismatch;
                return report;
            }
            if (key.Value.Record.KeyData.Length != Constants.Ed25519PublicKeyLen)
            {
                report.Verdict = ManifestVerdict.Unverifiable;
                report.UnverifiableReason = Pcf.Sig.UnverifiableReason.MalformedKey;
                return report;
            }
            bool ok;
            try
            {
                ok = Ed25519.Verify(
                    parsed.Signature, 0,
                    key.Value.Record.KeyData, 0,
                    parsed.ManifestBytes, 0, parsed.ManifestBytes.Length);
            }
            catch
            {
                ok = false;
            }
            if (!ok)
            {
                report.Verdict = ManifestVerdict.Invalid;
                return report;
            }
        }
        else
        {
            report.Verdict = ManifestVerdict.Unverifiable;
            report.UnverifiableReason = Pcf.Sig.UnverifiableReason.UnsupportedSigAlgo;
            report.UnverifiableId = (byte)parsed.Manifest.SigAlgo;
            return report;
        }

        foreach (var se in parsed.Manifest.SignedEntries)
        {
            PartitionEntry p = null;
            foreach (var x in entries)
            {
                if (BytesEqual(x.Uid, se.Uid)) { p = x; break; }
            }
            EntryVerdict verdict;
            if (p == null)
            {
                verdict = EntryVerdict.MissingPartition;
            }
            else if (!Manifest.IsCryptoHash(se.DataHashAlgo))
            {
                verdict = EntryVerdict.WeakHash;
            }
            else if (p.PartitionType != se.PartitionType
                     || !BytesEqual(p.Label, se.Label)
                     || p.UsedBytes != se.UsedBytes
                     || p.DataHashAlgo != se.DataHashAlgo
                     || !BytesEqual(p.DataHash, se.DataHash))
            {
                verdict = EntryVerdict.ProtectedFieldMismatch;
            }
            else
            {
                verdict = EntryVerdict.Valid;
            }
            report.Entries.Add(new EntryReport(se.Uid, verdict));
        }

        return report;
    }

    private static bool BytesEqual(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
        return true;
    }
}
