using System;
using System.Security.Cryptography;

namespace Pcf;

/// <summary>A hash algorithm from the PCF registry (spec section 8.1).</summary>
public enum HashAlgo : byte
{
    /// <summary><c>0</c> — no verification.</summary>
    None = 0,

    /// <summary><c>1</c> — CRC-32/ISO-HDLC.</summary>
    Crc32 = 1,

    /// <summary><c>2</c> — CRC-32C (Castagnoli).</summary>
    Crc32c = 2,

    /// <summary><c>3</c> — CRC-64/XZ.</summary>
    Crc64 = 3,

    /// <summary><c>4</c> — MD5 (checksum use only).</summary>
    Md5 = 4,

    /// <summary><c>5</c> — SHA-1 (checksum use only).</summary>
    Sha1 = 5,

    /// <summary><c>16</c> — SHA-256 (default).</summary>
    Sha256 = 16,

    /// <summary><c>17</c> — SHA-512.</summary>
    Sha512 = 17,

    /// <summary><c>18</c> — BLAKE3.</summary>
    Blake3 = 18,
}

/// <summary>
/// Registry behaviour for <see cref="HashAlgo"/>: id mapping, digest sizes and
/// the fixed 64-byte hash-field encoding of spec section 8.2 (digests
/// left-aligned and zero-padded; CRC values as little-endian integers).
/// </summary>
public static class HashAlgoExtensions
{
    /// <summary>Map a registry id byte to an algorithm, rejecting unknown ids.</summary>
    public static HashAlgo FromId(byte id)
    {
        switch (id)
        {
            case 0: return HashAlgo.None;
            case 1: return HashAlgo.Crc32;
            case 2: return HashAlgo.Crc32c;
            case 3: return HashAlgo.Crc64;
            case 4: return HashAlgo.Md5;
            case 5: return HashAlgo.Sha1;
            case 16: return HashAlgo.Sha256;
            case 17: return HashAlgo.Sha512;
            case 18: return HashAlgo.Blake3;
            default: throw PcfException.UnknownHashAlgo(id);
        }
    }

    /// <summary>The registry id byte for this algorithm.</summary>
    public static byte Id(this HashAlgo a) => (byte)a;

    /// <summary>Number of significant bytes this algorithm writes into a hash field.</summary>
    public static int DigestLen(this HashAlgo a)
    {
        switch (a)
        {
            case HashAlgo.None: return 0;
            case HashAlgo.Crc32: return 4;
            case HashAlgo.Crc32c: return 4;
            case HashAlgo.Crc64: return 8;
            case HashAlgo.Md5: return 16;
            case HashAlgo.Sha1: return 20;
            case HashAlgo.Sha256: return 32;
            case HashAlgo.Sha512: return 64;
            case HashAlgo.Blake3: return 32;
            default: throw PcfException.UnknownHashAlgo((byte)a);
        }
    }

    /// <summary>Whether this algorithm performs any verification (everything but <c>None</c>).</summary>
    public static bool Verifies(this HashAlgo a) => a != HashAlgo.None;

    /// <summary>Compute the full 64-byte hash field for <paramref name="data"/> per spec 8.2.</summary>
    public static byte[] Compute(this HashAlgo a, byte[] data)
    {
        var field = new byte[Constants.HashFieldSize];
        switch (a)
        {
            case HashAlgo.None:
                break;
            case HashAlgo.Crc32:
                LittleEndian.WriteU32(field, 0, Crc.Crc32IsoHdlc(data));
                break;
            case HashAlgo.Crc32c:
                LittleEndian.WriteU32(field, 0, Crc.Crc32c(data));
                break;
            case HashAlgo.Crc64:
                LittleEndian.WriteU64(field, 0, Crc.Crc64Xz(data));
                break;
            case HashAlgo.Md5:
                using (var h = MD5.Create()) { CopyDigest(h.ComputeHash(data), field); }
                break;
            case HashAlgo.Sha1:
                using (var h = SHA1.Create()) { CopyDigest(h.ComputeHash(data), field); }
                break;
            case HashAlgo.Sha256:
                using (var h = SHA256.Create()) { CopyDigest(h.ComputeHash(data), field); }
                break;
            case HashAlgo.Sha512:
                using (var h = SHA512.Create()) { CopyDigest(h.ComputeHash(data), field); }
                break;
            case HashAlgo.Blake3:
                // Writes the 32-byte digest into the left of the 64-byte field.
                global::Blake3.Hasher.Hash(data, field.AsSpan(0, HashAlgo.Blake3.DigestLen()));
                break;
            default:
                throw PcfException.UnknownHashAlgo((byte)a);
        }
        return field;
    }

    /// <summary>
    /// Verify <paramref name="data"/> against a stored 64-byte hash field.
    /// <c>None</c> always succeeds; only the significant prefix is compared.
    /// </summary>
    public static bool Verify(this HashAlgo a, byte[] data, byte[] stored)
    {
        if (!a.Verifies())
        {
            return true;
        }
        var computed = a.Compute(data);
        int n = a.DigestLen();
        for (int i = 0; i < n; i++)
        {
            if (computed[i] != stored[i])
            {
                return false;
            }
        }
        return true;
    }

    private static void CopyDigest(byte[] digest, byte[] field)
    {
        Buffer.BlockCopy(digest, 0, field, 0, digest.Length);
    }
}
