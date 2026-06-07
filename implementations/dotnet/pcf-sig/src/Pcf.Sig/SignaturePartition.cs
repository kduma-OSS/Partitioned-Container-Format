using System;

namespace Pcf.Sig;

/// <summary>
/// The byte payload of a `PCFSIG_SIG` partition: Manifest, length-prefixed
/// signature bytes, length-prefixed trailer (spec Section 7.3).
/// </summary>
public sealed class SignaturePartition
{
    /// <summary>Parsed Manifest.</summary>
    public Manifest Manifest { get; set; }

    /// <summary>
    /// Raw bytes of the Manifest as serialised in the partition. This is the
    /// signing input and MUST be byte-exact, so the parser caches it.
    /// </summary>
    public byte[] ManifestBytes { get; set; }

    /// <summary>Raw signature bytes (the algorithm's natural output).</summary>
    public byte[] Signature { get; set; }

    /// <summary>Trailer bytes; MUST be empty in v1.0.</summary>
    public byte[] Trailer { get; set; } = new byte[0];

    /// <summary>Compose a partition payload from a manifest + signature.</summary>
    public static SignaturePartition Make(Manifest manifest, byte[] signature)
    {
        return new SignaturePartition
        {
            Manifest = manifest,
            ManifestBytes = manifest.ToBytes(),
            Signature = (byte[])signature.Clone(),
            Trailer = new byte[0],
        };
    }

    /// <summary>Serialise to the on-disk byte layout (spec Section 7).</summary>
    public byte[] ToBytes()
    {
        int total = ManifestBytes.Length + 4 + Signature.Length + 4 + Trailer.Length;
        var out_ = new byte[total];
        Buffer.BlockCopy(ManifestBytes, 0, out_, 0, ManifestBytes.Length);
        LittleEndian.WriteU32(out_, ManifestBytes.Length, (uint)Signature.Length);
        Buffer.BlockCopy(Signature, 0, out_, ManifestBytes.Length + 4, Signature.Length);
        LittleEndian.WriteU32(out_, ManifestBytes.Length + 4 + Signature.Length, (uint)Trailer.Length);
        Buffer.BlockCopy(Trailer, 0, out_, ManifestBytes.Length + 4 + Signature.Length + 4, Trailer.Length);
        return out_;
    }

    /// <summary>
    /// Parse the on-disk byte layout. Validates manifest, sig_length presence,
    /// sig_bytes availability, trailer_length presence and 0 in v1.0, total
    /// length consistency.
    /// </summary>
    public static SignaturePartition FromBytes(byte[] b)
    {
        if (b == null || b.Length < Constants.ManifestPrefixSize)
        {
            throw PcfSigException.MalformedSignaturePartition();
        }
        var manifest = Manifest.FromBytes(b);
        int manifestLen = manifest.ByteLen();
        if (b.Length < manifestLen + 4)
        {
            throw PcfSigException.MalformedSignaturePartition();
        }
        uint sigLength = LittleEndian.ReadU32(b, manifestLen);
        if (sigLength == 0)
        {
            throw PcfSigException.SignatureLengthMismatch();
        }
        int sigStart = manifestLen + 4;
        int sigEnd = sigStart + (int)sigLength;
        if (b.Length < sigEnd + 4)
        {
            throw PcfSigException.MalformedSignaturePartition();
        }
        var signature = new byte[sigLength];
        Buffer.BlockCopy(b, sigStart, signature, 0, (int)sigLength);
        uint trailerLength = LittleEndian.ReadU32(b, sigEnd);
        if (trailerLength != 0)
        {
            throw PcfSigException.NonZeroTrailer();
        }
        int totalEnd = sigEnd + 4 + (int)trailerLength;
        if (b.Length != totalEnd)
        {
            throw PcfSigException.MalformedSignaturePartition();
        }
        var manifestBytes = new byte[manifestLen];
        Buffer.BlockCopy(b, 0, manifestBytes, 0, manifestLen);
        return new SignaturePartition
        {
            Manifest = manifest,
            ManifestBytes = manifestBytes,
            Signature = signature,
            Trailer = new byte[0],
        };
    }
}
