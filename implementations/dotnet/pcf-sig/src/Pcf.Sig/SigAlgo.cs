using Pcf;

namespace Pcf.Sig;

/// <summary>A signature algorithm id (spec Section 8, Appendix B).</summary>
public enum SigAlgo : byte
{
    /// <summary>1 — Ed25519 (RFC 8032). Manifest hash is intrinsically SHA-512.</summary>
    Ed25519 = 1,
    /// <summary>2 — RSA-PSS-SHA-256. Recognised but not implemented.</summary>
    RsaPssSha256 = 2,
    /// <summary>4 — RSA-PSS-SHA-512. Recognised but not implemented.</summary>
    RsaPssSha512 = 4,
    /// <summary>5 — RSA-PKCS1v15-SHA-256. Recognised but not implemented.</summary>
    RsaPkcs1v15Sha256 = 5,
    /// <summary>7 — RSA-PKCS1v15-SHA-512. Recognised but not implemented.</summary>
    RsaPkcs1v15Sha512 = 7,
    /// <summary>16 — ECDSA-P256-SHA-256. Recognised but not implemented.</summary>
    EcdsaP256Sha256 = 16,
    /// <summary>18 — ECDSA-P521-SHA-512. Recognised but not implemented.</summary>
    EcdsaP521Sha512 = 18,
    /// <summary>32 — X.509 chain. Recognised but not implemented.</summary>
    X509Chain = 32,
}

/// <summary>Registry behaviour for <see cref="SigAlgo"/>.</summary>
public static class SigAlgoExtensions
{
    /// <summary>Map a registry id byte to a signature algorithm.</summary>
    public static SigAlgo FromId(byte id)
    {
        switch (id)
        {
            case 1: return SigAlgo.Ed25519;
            case 2: return SigAlgo.RsaPssSha256;
            case 4: return SigAlgo.RsaPssSha512;
            case 5: return SigAlgo.RsaPkcs1v15Sha256;
            case 7: return SigAlgo.RsaPkcs1v15Sha512;
            case 16: return SigAlgo.EcdsaP256Sha256;
            case 18: return SigAlgo.EcdsaP521Sha512;
            case 32: return SigAlgo.X509Chain;
            default: throw PcfSigException.UnknownSigAlgo(id);
        }
    }

    /// <summary>The registry id byte for this algorithm.</summary>
    public static byte Id(this SigAlgo a) => (byte)a;

    /// <summary>
    /// The manifest_hash_algo_id an implementation MUST require for this
    /// algorithm (spec Section 8). <c>null</c> for X.509 chain.
    /// </summary>
    public static HashAlgo? RequiredManifestHash(this SigAlgo a)
    {
        switch (a)
        {
            case SigAlgo.Ed25519:
            case SigAlgo.RsaPssSha512:
            case SigAlgo.RsaPkcs1v15Sha512:
            case SigAlgo.EcdsaP521Sha512:
                return HashAlgo.Sha512;
            case SigAlgo.RsaPssSha256:
            case SigAlgo.RsaPkcs1v15Sha256:
            case SigAlgo.EcdsaP256Sha256:
                return HashAlgo.Sha256;
            case SigAlgo.X509Chain:
                return null;
            default:
                return null;
        }
    }

    /// <summary>Whether this library implements signing and verification for the algorithm.</summary>
    public static bool IsImplemented(this SigAlgo a) => a == SigAlgo.Ed25519;
}

/// <summary>A key-format id (spec Section 6.2).</summary>
public enum KeyFormat : byte
{
    /// <summary>1 — Ed25519 raw public key (32 bytes, RFC 8032).</summary>
    Ed25519Raw = 1,
    /// <summary>2 — RSA SPKI DER. Recognised but not implemented.</summary>
    RsaSpkiDer = 2,
    /// <summary>3 — ECDSA SPKI DER. Recognised but not implemented.</summary>
    EcdsaSpkiDer = 3,
    /// <summary>16 — X.509 single certificate (DER). Recognised but not implemented.</summary>
    X509Cert = 16,
    /// <summary>17 — X.509 length-prefixed chain. Recognised but not implemented.</summary>
    X509Chain = 17,
}

/// <summary>Registry behaviour for <see cref="KeyFormat"/>.</summary>
public static class KeyFormatExtensions
{
    /// <summary>Map a registry id byte to a key format.</summary>
    public static KeyFormat FromId(byte id)
    {
        switch (id)
        {
            case 1: return KeyFormat.Ed25519Raw;
            case 2: return KeyFormat.RsaSpkiDer;
            case 3: return KeyFormat.EcdsaSpkiDer;
            case 16: return KeyFormat.X509Cert;
            case 17: return KeyFormat.X509Chain;
            default: throw PcfSigException.UnknownKeyFormat(id);
        }
    }

    /// <summary>The registry id byte for this format.</summary>
    public static byte Id(this KeyFormat f) => (byte)f;

    /// <summary>Whether this library can extract a verification key from records of this format.</summary>
    public static bool IsImplemented(this KeyFormat f) => f == KeyFormat.Ed25519Raw;
}
