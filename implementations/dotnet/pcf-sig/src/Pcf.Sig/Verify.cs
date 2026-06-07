using System.Collections.Generic;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Pcf;

namespace Pcf.Sig;

/// <summary>Verdict on one SignedEntry inside a Manifest (spec Section 11, V7).</summary>
public enum EntryVerdict
{
    Valid,
    MissingPartition,
    ProtectedFieldMismatch,
    DataHashRecomputationMismatch,
    WeakHash,
}

/// <summary>Verdict on a whole PCFSIG_SIG partition (spec Section 11, V8).</summary>
public enum ManifestVerdict
{
    Valid,
    Invalid,
    Unverifiable,
}

/// <summary>Why a manifest could not be verified.</summary>
public enum UnverifiableReason
{
    NoMatchingKey,
    UnsupportedSigAlgo,
    UnsupportedKeyFormat,
    MalformedKey,
    SignatureLengthMismatch,
}

/// <summary>Per-entry report.</summary>
public sealed class EntryReport
{
    public byte[] Uid { get; }
    public EntryVerdict Verdict { get; set; }

    public EntryReport(byte[] uid, EntryVerdict verdict)
    {
        Uid = uid;
        Verdict = verdict;
    }
}

/// <summary>Report for one PCFSIG_SIG partition.</summary>
public sealed class SignatureReport
{
    public byte[] SigPartitionUid { get; set; }
    public byte[] SignerKeyFingerprint { get; set; }
    public long SignedAtUnixSeconds { get; set; }
    public ManifestVerdict Verdict { get; set; }
    public UnverifiableReason? UnverifiableReason { get; set; }
    public int? UnverifiableId { get; set; }
    public List<EntryReport> Entries { get; set; } = new();
}

/// <summary>Whether to independently re-hash each covered partition during verification.</summary>
public enum DataRecheck
{
    Skip,
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
