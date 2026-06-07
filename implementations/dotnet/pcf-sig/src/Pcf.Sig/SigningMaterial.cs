using System;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Pcf.Sig;

/// <summary>
/// A signing key wired to one algorithm.
///
/// v1.0 covers Ed25519, the MUST-support baseline. The library uses
/// BouncyCastle's RFC 8032 implementation for signing and verification.
/// </summary>
public sealed class SigningMaterial
{
    public SigAlgo SigAlgo { get; }
    public KeyFormat KeyFormat { get; }
    public byte[] PublicKeyBytes { get; }
    private readonly byte[] _secretSeed;

    private SigningMaterial(SigAlgo sigAlgo, KeyFormat keyFormat, byte[] secretSeed, byte[] publicKeyBytes)
    {
        SigAlgo = sigAlgo;
        KeyFormat = keyFormat;
        _secretSeed = secretSeed;
        PublicKeyBytes = publicKeyBytes;
    }

    /// <summary>Construct an Ed25519 signer from a 32-byte secret seed.</summary>
    public static SigningMaterial Ed25519FromSeed(byte[] seed)
    {
        if (seed == null || seed.Length != 32)
        {
            throw new ArgumentException("Ed25519 seed must be exactly 32 bytes", nameof(seed));
        }
        var pub = new byte[Ed25519.PublicKeySize];
        Ed25519.GeneratePublicKey(seed, 0, pub, 0);
        return new SigningMaterial(
            Pcf.Sig.SigAlgo.Ed25519,
            Pcf.Sig.KeyFormat.Ed25519Raw,
            (byte[])seed.Clone(),
            pub);
    }

    /// <summary>SHA-256 fingerprint of the signer's public key bytes.</summary>
    public byte[] Fingerprint() => KeyRecord.ComputeFingerprint(PublicKeyBytes);

    /// <summary>Sign <paramref name="message"/> and return the raw signature bytes.</summary>
    public byte[] Sign(byte[] message)
    {
        switch (SigAlgo)
        {
            case SigAlgo.Ed25519:
                var sig = new byte[Ed25519.SignatureSize];
                Ed25519.Sign(_secretSeed, 0, message, 0, message.Length, sig, 0);
                return sig;
            default:
                throw new InvalidOperationException(
                    $"sig_algo_id {(byte)SigAlgo} is not implemented");
        }
    }

    /// <summary>Bytes of a Key Record representing this signer.</summary>
    public byte[] ToKeyRecordBytes() =>
        KeyRecord.Make(KeyFormat, PublicKeyBytes).ToBytes();
}
